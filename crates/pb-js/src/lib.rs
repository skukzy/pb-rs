//! Minimal PocketBase-compatible JSVM runtime (M6a).
//!
//! Scope is deliberately smaller than goja: a single persistent QuickJS
//! context on a dedicated worker thread evaluates `pb_hooks/*.pb.js` files and
//! dispatches record request hooks. See `docs/COMPATIBILITY.md` (L8) for the
//! supported surface and the documented divergences.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};

use anyhow::{Context as _, Result};
use rquickjs::{Context, Ctx, Function, Runtime};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Hook names implemented by the runtime.
pub const SUPPORTED_HOOKS: &[&str] = &[
    "onRecordCreateRequest",
    "onRecordUpdateRequest",
    "onRecordDeleteRequest",
    "onRecordsListRequest",
    "onRecordViewRequest",
    "onRecordAfterCreateSuccess",
    "onRecordAfterUpdateSuccess",
    "onRecordAfterDeleteSuccess",
    "onRecordAfterCreateError",
    "onRecordAfterUpdateError",
    "onRecordAfterDeleteError",
];

/// An error thrown by a hook. `status`/`message`/`data` mirror
/// `router.ApiError`, which is what the JS error constructors build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookError {
    pub status: u16,
    pub message: String,
    pub data: Value,
    /// `true` when the hook threw an `ApiError` constructor; plain JS errors
    /// are wrapped by the router into a generic 400.
    pub api: bool,
}

/// The data made available to a hook as `e`.
#[derive(Debug, Clone, Default)]
pub struct HookEvent {
    pub collection: Option<Value>,
    pub record: Option<Value>,
    pub records: Option<Value>,
    pub request: Option<Value>,
    pub error: Option<Value>,
}

/// Result of a successful hook dispatch. `record` is the (possibly mutated)
/// record as exported by the hook; callers decide whether to apply it.
#[derive(Debug, Clone, Default)]
pub struct HookOutcome {
    pub record: Option<Value>,
}

enum Command {
    Call {
        hook: String,
        event: HookEvent,
        tags: Vec<String>,
        reply: Sender<Result<HookOutcome, HookError>>,
    },
    Shutdown,
}

/// Handle to the JS worker. Cheap to clone behind an `Arc`; calls are
/// serialized by the worker.
pub struct HookEngine {
    tx: Sender<Command>,
    hooks_dir: PathBuf,
}

impl HookEngine {
    /// Start the worker and evaluate every `*.pb.js` / `*.pb.ts` file in
    /// `hooks_dir` (sorted by filename). A missing directory is not an error:
    /// the engine simply has no hooks.
    ///
    /// `data_dir` backs `$app.dataDir()` and is kept exactly as the CLI received
    /// it (the oracle returns `config.DataDir` unchanged). `hooks_dir` is made
    /// absolute, matching `jsvm.go`'s `__hooks` global.
    pub fn load(hooks_dir: impl AsRef<Path>) -> Result<Self> {
        let hooks_dir = hooks_dir.as_ref().to_path_buf();
        Self::load_with_data_dir(hooks_dir.clone(), hooks_dir)
    }

    pub fn load_with_data_dir(
        hooks_dir: impl AsRef<Path>,
        data_dir: impl AsRef<Path>,
    ) -> Result<Self> {
        let hooks_dir = absolute_path(hooks_dir.as_ref());
        let data_dir = data_dir.as_ref().to_path_buf();
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();

        let dir_for_worker = hooks_dir.clone();
        std::thread::Builder::new()
            .name("pb-js".into())
            .spawn(move || worker(dir_for_worker, data_dir, rx, ready_tx))
            .context("spawn JS worker")?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self { tx, hooks_dir }),
            Ok(Err(err)) => Err(err),
            Err(_) => anyhow::bail!("JS worker stopped during initialization"),
        }
    }

    pub fn hooks_dir(&self) -> &Path {
        &self.hooks_dir
    }

    /// Dispatch a hook. Tag filtering follows `hook.TaggedHook`: a handler
    /// registered without tags matches every event, otherwise at least one of
    /// the event tags must be present. Hooks run in registration order.
    pub fn call(
        &self,
        hook: &str,
        tags: &[String],
        event: HookEvent,
    ) -> std::result::Result<HookOutcome, HookError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        let command = Command::Call {
            hook: hook.to_string(),
            event,
            tags: tags.to_vec(),
            reply: reply_tx,
        };
        if self.tx.send(command).is_err() {
            return Err(internal_error("JS hook worker is not running"));
        }
        reply_rx.recv().unwrap_or_else(|_| {
            Err(internal_error("JS hook worker stopped before replying"))
        })
    }
}

impl Drop for HookEngine {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Shutdown);
    }
}

fn internal_error(message: &str) -> HookError {
    HookError {
        status: 500,
        message: "Something went wrong while processing your request.".to_string(),
        data: Value::Null,
        api: false,
    }
    .with_detail(message)
}

impl HookError {
    fn with_detail(mut self, message: &str) -> Self {
        tracing::error!(error = message, "JS hook dispatch failed");
        self.data = Value::Null;
        self
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
    }
}

fn worker(
    hooks_dir: PathBuf,
    data_dir: PathBuf,
    rx: Receiver<Command>,
    ready_tx: Sender<Result<()>>,
) {
    let init = (|| -> Result<(Runtime, Context)> {
        let rt = Runtime::new().context("create QuickJS runtime")?;
        let ctx = Context::full(&rt).context("create QuickJS context")?;
        ctx.with(|ctx| {
            install_bindings(&ctx, &hooks_dir, &data_dir)?;
            ctx.eval::<(), _>(BOOTSTRAP)
                .map_err(|err| anyhow::anyhow!("evaluate JSVM bootstrap: {err}"))?;
            load_hook_files(&ctx, &hooks_dir)?;
            Ok::<(), anyhow::Error>(())
        })?;
        Ok((rt, ctx))
    })();

    match init {
        Ok((_rt, ctx)) => {
            if ready_tx.send(Ok(())).is_err() {
                return;
            }
            while let Ok(command) = rx.recv() {
                match command {
                    Command::Call {
                        hook,
                        event,
                        tags,
                        reply,
                    } => {
                        let result = dispatch(&ctx, &hook, &event, &tags);
                        let _ = reply.send(result);
                    }
                    Command::Shutdown => break,
                }
            }
        }
        Err(err) => {
            let _ = ready_tx.send(Err(err));
        }
    }
}

fn dispatch(
    ctx: &Context,
    hook: &str,
    event: &HookEvent,
    tags: &[String],
) -> std::result::Result<HookOutcome, HookError> {
    let event_json = serde_json::to_string(&event_json(event))
        .map_err(|_| internal_error("failed to encode hook event"))?;
    let tags_json = serde_json::to_string(tags)
        .map_err(|_| internal_error("failed to encode hook tags"))?;

    let raw = ctx
        .with(|ctx| -> rquickjs::Result<String> {
            let call: Function = ctx.globals().get("__pbCall")?;
            call.call((hook, event_json.as_str(), tags_json.as_str()))
        })
        .map_err(|err| {
            tracing::error!(error = %err, hook, "JS hook invocation failed");
            internal_error("failed to invoke JS hook")
        })?;

    let parsed: CallResult = serde_json::from_str(&raw).map_err(|err| {
        tracing::error!(error = %err, hook, "JS hook returned invalid JSON");
        internal_error("JS hook returned invalid data")
    })?;

    if let Some(err) = parsed.error {
        return Err(HookError {
            status: err.status,
            message: err.message,
            data: err.data,
            api: err.api,
        });
    }

    Ok(HookOutcome {
        record: parsed.record,
    })
}

fn event_json(event: &HookEvent) -> Value {
    let mut map = serde_json::Map::new();
    if let Some(collection) = &event.collection {
        map.insert("collection".into(), collection.clone());
    }
    if let Some(record) = &event.record {
        map.insert("record".into(), record.clone());
    }
    if let Some(records) = &event.records {
        map.insert("records".into(), records.clone());
    }
    if let Some(request) = &event.request {
        map.insert("request".into(), request.clone());
    }
    if let Some(error) = &event.error {
        map.insert("error".into(), error.clone());
    }
    Value::Object(map)
}

#[derive(Deserialize)]
struct CallResult {
    #[serde(default)]
    record: Option<Value>,
    #[serde(default)]
    error: Option<CallError>,
}

#[derive(Deserialize)]
struct CallError {
    status: u16,
    message: String,
    #[serde(default)]
    data: Value,
    #[serde(default)]
    api: bool,
}

pub fn has_hooks(dir: impl AsRef<Path>) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if !path.is_file() {
            return false;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        name.ends_with(".pb.js") || name.ends_with(".pb.ts")
    })
}

fn load_hook_files(ctx: &Ctx<'_>, dir: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("read hooks dir {}", dir.display()))
        }
    };

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read hooks dir {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".pb.js") || name.ends_with(".pb.ts") {
            files.push((name, path));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, path) in files {
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("read hook file {}", path.display()))?;
        ctx.eval::<(), _>(source)
            .map_err(|err| anyhow::anyhow!("load hook {name}: {err}"))?;
    }
    Ok(())
}

fn install_bindings(ctx: &Ctx<'_>, hooks_dir: &Path, data_dir: &Path) -> Result<()> {
    let globals = ctx.globals();

    let log = Function::new(ctx.clone(), |level: String, message: String| {
        match level.as_str() {
            "debug" => tracing::debug!(target: "pb_hooks", "{message}"),
            "warn" => tracing::warn!(target: "pb_hooks", "{message}"),
            "error" => tracing::error!(target: "pb_hooks", "{message}"),
            _ => tracing::info!(target: "pb_hooks", "{message}"),
        }
    })?;
    globals.set("__pbLog", log)?;

    let write_file = Function::new(
        ctx.clone(),
        |path: String, data: String, perm: Option<i64>| -> std::io::Result<()> {
            write_file_with_mode(&path, data.as_bytes(), perm.unwrap_or(0) as u32)
        },
    )?;
    globals.set("__pbWriteFile", write_file)?;

    let read_file = Function::new(ctx.clone(), |path: String| -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    })?;
    globals.set("__pbReadFile", read_file)?;

    let mkdir_all = Function::new(ctx.clone(), |path: String| std::fs::create_dir_all(path))?;
    globals.set("__pbMkdirAll", mkdir_all)?;

    let remove = Function::new(ctx.clone(), |path: String| std::fs::remove_file(path))?;
    globals.set("__pbRemove", remove)?;

    let remove_all = Function::new(ctx.clone(), |path: String| std::fs::remove_dir_all(path))?;
    globals.set("__pbRemoveAll", remove_all)?;

    let file_exists = Function::new(ctx.clone(), |path: String| Path::new(&path).exists())?;
    globals.set("__pbFileExists", file_exists)?;

    let getenv = Function::new(ctx.clone(), |key: String| {
        std::env::var(key).unwrap_or_default()
    })?;
    globals.set("__pbGetenv", getenv)?;

    let temp_dir = Function::new(ctx.clone(), || std::env::temp_dir().to_string_lossy().to_string())?;
    globals.set("__pbTempDir", temp_dir)?;

    let random_string = Function::new(ctx.clone(), |length: i64| random_string(length.max(0) as usize))?;
    globals.set("__pbRandomString", random_string)?;

    let hash = Function::new(ctx.clone(), |alg: String, data: String| hash_hex(&alg, data.as_bytes()))?;
    globals.set("__pbHash", hash)?;

    let sleep = Function::new(ctx.clone(), |milliseconds: i64| {
        if milliseconds > 0 {
            std::thread::sleep(std::time::Duration::from_millis(milliseconds as u64));
        }
    })?;
    globals.set("__pbSleep", sleep)?;

    let dir = hooks_dir.to_string_lossy().to_string();
    let hooks_path = Function::new(ctx.clone(), move || dir.clone())?;
    globals.set("__pbHooksDir", hooks_path)?;

    let data_dir = data_dir.to_string_lossy().to_string();
    let data_path = Function::new(ctx.clone(), move || data_dir.clone())?;
    globals.set("__pbDataDir", data_path)?;

    Ok(())
}

fn write_file_with_mode(path: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path)?;
    file.write_all(data)
}

fn random_string(length: usize) -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn hash_hex(algorithm: &str, data: &[u8]) -> String {
    use sha2::Digest as _;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    match algorithm {
        "md5" => {
            use md5::Md5;
            hex(&Md5::digest(data))
        }
        "sha512" => {
            use sha2::Sha512;
            hex(&Sha512::digest(data))
        }
        _ => {
            use sha2::Sha256;
            hex(&Sha256::digest(data))
        }
    }
}

/// JavaScript bootstrap. Kept as a string so the whole runtime fits in one
/// file; the supported globals are the documented M6a surface.
const BOOTSTRAP: &str = r#"
(function () {
  "use strict";

  const hooks = Object.create(null);

  function register(name, fn, tags) {
    if (typeof fn !== "function") {
      throw new TypeError(name + " expects a function");
    }
    (hooks[name] || (hooks[name] = [])).push({ fn: fn, tags: tags || [] });
  }

  const HOOK_NAMES = [
    "onRecordCreateRequest",
    "onRecordUpdateRequest",
    "onRecordDeleteRequest",
    "onRecordsListRequest",
    "onRecordViewRequest",
    "onRecordAfterCreateSuccess",
    "onRecordAfterUpdateSuccess",
    "onRecordAfterDeleteSuccess",
    "onRecordAfterCreateError",
    "onRecordAfterUpdateError",
    "onRecordAfterDeleteError"
  ];

  for (const name of HOOK_NAMES) {
    globalThis[name] = function (fn, ...tags) {
      register(name, fn, tags);
    };
  }

  globalThis.__pbRegistered = function (name) {
    return (hooks[name] || []).length;
  };

  function sentenize(value) {
    let text = String(value == null ? "" : value).trim();
    if (!text) return "";
    text = text.charAt(0).toUpperCase() + text.slice(1);
    if (!/[.!?]$/.test(text)) text += ".";
    return text;
  }

  class ApiError extends Error {
    constructor(status, message, data) {
      super(sentenize(message));
      this.name = "ApiError";
      this.status = Number(status) || 0;
      this.data = data === undefined ? null : data;
      this.__pbApiError = true;
    }
  }

  function errorClass(name, status, message) {
    const cls = class extends ApiError {
      constructor(customMessage, data) {
        if (customMessage === undefined || customMessage === null || customMessage === "") {
          customMessage = message;
        }
        super(status, customMessage, data);
        this.name = name;
      }
    };
    Object.defineProperty(cls, "name", { value: name });
    return cls;
  }

  globalThis.ApiError = ApiError;
  globalThis.NotFoundError = errorClass("NotFoundError", 404, "The requested resource wasn't found.");
  globalThis.BadRequestError = errorClass("BadRequestError", 400, "Something went wrong while processing your request.");
  globalThis.ForbiddenError = errorClass("ForbiddenError", 403, "You are not allowed to perform this request.");
  globalThis.UnauthorizedError = errorClass("UnauthorizedError", 401, "Missing or invalid authentication.");
  globalThis.TooManyRequestsError = errorClass("TooManyRequestsError", 429, "Too Many Requests.");
  globalThis.InternalServerError = errorClass("InternalServerError", 500, "Something went wrong while processing your request.");

  function stringify(value) {
    if (typeof value === "string") return value;
    if (value === undefined) return "undefined";
    if (value === null) return "null";
    try {
      return JSON.stringify(value);
    } catch (_) {
      return String(value);
    }
  }

  globalThis.console = {
    log: (...args) => __pbLog("info", args.map(stringify).join(" ")),
    info: (...args) => __pbLog("info", args.map(stringify).join(" ")),
    debug: (...args) => __pbLog("debug", args.map(stringify).join(" ")),
    warn: (...args) => __pbLog("warn", args.map(stringify).join(" ")),
    error: (...args) => __pbLog("error", args.map(stringify).join(" "))
  };

  globalThis.toString = function (value, maxBytes) {
    if (value === undefined || value === null) return "";
    if (typeof value === "string") return maxBytes ? value.slice(0, maxBytes) : value;
    if (Array.isArray(value) || value instanceof Uint8Array || value instanceof ArrayBuffer) {
      const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
      let out = "";
      for (let i = 0; i < bytes.length; i++) {
        if (maxBytes && out.length >= maxBytes) break;
        out += String.fromCharCode(bytes[i]);
      }
      try {
        return decodeURIComponent(escape(out));
      } catch (_) {
        return out;
      }
    }
    return String(value);
  };

  globalThis.sleep = function (milliseconds) {
    __pbSleep(Number(milliseconds) || 0);
  };

  function makeRecord(data, collection) {
    const record = {
      __data: Object.assign({}, data || {}),
      collection: collection || {}
    };

    Object.defineProperty(record, "id", {
      get: () => record.__data.id === undefined ? "" : record.__data.id,
      set: (value) => { record.__data.id = value; }
    });
    Object.defineProperty(record, "collectionName", {
      get: () => (collection && collection.name) || ""
    });
    Object.defineProperty(record, "collectionId", {
      get: () => (collection && collection.id) || ""
    });

    record.get = (key) => record.__data[key] === undefined ? "" : record.__data[key];
    record.getString = (key) => {
      const value = record.get(key);
      return value === null || value === undefined ? "" : String(value);
    };
    record.getInt = (key) => {
      const value = Number(record.get(key));
      return Number.isFinite(value) ? Math.trunc(value) : 0;
    };
    record.getFloat = (key) => {
      const value = Number(record.get(key));
      return Number.isFinite(value) ? value : 0;
    };
    record.getBool = (key) => Boolean(record.get(key));
    record.set = (key, value) => { record.__data[key] = value; };
    record.setIfNull = (key, value) => {
      if (record.__data[key] === undefined || record.__data[key] === null || record.__data[key] === "") {
        record.__data[key] = value;
      }
    };
    record.__export = () => JSON.parse(JSON.stringify(record.__data));

    return record;
  }

  function makeEvent(raw) {
    const event = {
      app: globalThis.$app,
      collection: raw.collection || {},
      next: () => true
    };
    if (raw.record) {
      event.record = makeRecord(raw.record, raw.collection);
    }
    if (raw.records) {
      event.records = raw.records.map((item) => makeRecord(item, raw.collection));
    }
    if (raw.request) {
      event.requestInfo = () => raw.request;
      event.httpContext = {
        request: {
          method: raw.request.method || "",
          url: raw.request.path || ""
        }
      };
    }
    if (raw.error !== undefined) {
      event.error = raw.error;
    }
    return event;
  }

  globalThis.__pbCall = function (name, eventJson, tagsJson) {
    const list = hooks[name] || [];
    if (list.length === 0) {
      return JSON.stringify({ record: null });
    }

    const raw = JSON.parse(eventJson || "{}");
    const tags = JSON.parse(tagsJson || "[]");
    const event = makeEvent(raw);

    for (const handler of list) {
      if (handler.tags.length > 0) {
        let matched = false;
        for (const tag of handler.tags) {
          if (tags.indexOf(tag) !== -1) {
            matched = true;
            break;
          }
        }
        if (!matched) continue;
      }

      try {
        handler.fn(event);
      } catch (err) {
        if (err && err.__pbApiError) {
          return JSON.stringify({
            error: {
              status: err.status,
              message: err.message,
              data: err.data,
              api: true
            }
          });
        }
        const detail = err && err.stack ? String(err.stack) : String(err);
        __pbLog("error", "[" + name + "] " + detail);
        return JSON.stringify({
          error: {
            status: 500,
            message: "Something went wrong while processing your request.",
            data: null,
            api: false
          }
        });
      }
    }

    return JSON.stringify({
      record: event.record ? event.record.__export() : null
    });
  };

  globalThis.$app = {
    logger: () => ({
      debug: (...args) => console.debug(...args),
      info: (...args) => console.info(...args),
      warn: (...args) => console.warn(...args),
      error: (...args) => console.error(...args)
    }),
    dataDir: () => __pbDataDir()
  };

  globalThis.$os = {
    writeFile: (path, data, perm) => __pbWriteFile(String(path), toString(data), perm),
    readFile: (path) => __pbReadFile(String(path)),
    mkdirAll: (path) => __pbMkdirAll(String(path)),
    remove: (path) => __pbRemove(String(path)),
    removeAll: (path) => __pbRemoveAll(String(path)),
    fileExists: (path) => __pbFileExists(String(path)),
    getenv: (key) => __pbGetenv(String(key)),
    tempDir: () => __pbTempDir()
  };

  globalThis.$security = {
    randomString: (length) => __pbRandomString(Number(length) || 0),
    equal: (a, b) => String(a) === String(b),
    md5: (value) => __pbHash("md5", toString(value)),
    sha256: (value) => __pbHash("sha256", toString(value)),
    sha512: (value) => __pbHash("sha512", toString(value))
  };

  globalThis.$filepath = {
    base: (path) => String(path).split("/").filter(Boolean).pop() || "",
    dir: (path) => {
      const parts = String(path).split("/");
      parts.pop();
      return parts.join("/") || ".";
    },
    ext: (path) => {
      const name = String(path).split("/").pop() || "";
      const index = name.lastIndexOf(".");
      return index <= 0 ? "" : name.slice(index);
    },
    join: (...parts) => parts.map(String).filter((p) => p.length > 0).join("/"),
    isAbs: (path) => String(path).startsWith("/")
  };

  globalThis.__hooks = __pbHooksDir();
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_hooks(files: &[(&str, &str)]) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "pb-js-test-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, source) in files {
            std::fs::write(dir.join(name), source).unwrap();
        }
        dir
    }

    fn event() -> HookEvent {
        HookEvent {
            collection: Some(json!({"id": "c1", "name": "posts", "type": "base"})),
            record: Some(json!({"id": "r1", "title": "hello"})),
            records: None,
            request: Some(json!({"method": "POST", "path": "/api/collections/posts/records"})),
            error: None,
        }
    }

    #[test]
    fn runs_hooks_and_returns_mutations() {
        let dir = temp_hooks(&[(
            "main.pb.js",
            r#"
            onRecordCreateRequest((e) => {
              e.record.set("title", e.record.getString("title") + "!");
              e.next();
            });
            "#,
        )]);
        let engine = HookEngine::load(&dir).unwrap();
        let outcome = engine
            .call("onRecordCreateRequest", &["posts".into()], event())
            .unwrap();
        assert_eq!(outcome.record.unwrap()["title"], "hello!");
    }

    #[test]
    fn tags_filter_handlers() {
        let dir = temp_hooks(&[(
            "main.pb.js",
            r#"
            onRecordCreateRequest((e) => {
              throw new BadRequestError("tagged only");
            }, "other");
            "#,
        )]);
        let engine = HookEngine::load(&dir).unwrap();
        engine
            .call("onRecordCreateRequest", &["posts".into()], event())
            .unwrap();
        let err = engine
            .call("onRecordCreateRequest", &["other".into()], event())
            .unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.message, "Tagged only.");
    }

    #[test]
    fn error_constructors_match_oracle_defaults() {
        let dir = temp_hooks(&[(
            "main.pb.js",
            r#"
            onRecordCreateRequest((e) => {
              throw new NotFoundError();
            });
            "#,
        )]);
        let engine = HookEngine::load(&dir).unwrap();
        let err = engine
            .call("onRecordCreateRequest", &["posts".into()], event())
            .unwrap_err();
        assert_eq!(err.status, 404);
        assert_eq!(err.message, "The requested resource wasn't found.");
    }

    #[test]
    fn console_and_os_bindings_work() {
        let dir = temp_hooks(&[(
            "main.pb.js",
            r#"
            onRecordCreateRequest((e) => {
              console.log("trace", e.record.id);
              $os.writeFile(__pbHooksDir() + "/trace.txt", "created:" + e.record.id, 0o644);
              e.next();
            });
            "#,
        )]);
        let engine = HookEngine::load(&dir).unwrap();
        engine
            .call("onRecordCreateRequest", &["posts".into()], event())
            .unwrap();
        let trace = std::fs::read_to_string(dir.join("trace.txt")).unwrap();
        assert_eq!(trace, "created:r1");
    }

    #[test]
    fn app_data_dir_and_missing_env_match_go() {
        let dir = temp_hooks(&[(
            "main.pb.js",
            r#"
            onRecordCreateRequest((e) => {
              $os.writeFile(__pbHooksDir() + "/app.txt",
                $app.dataDir() + "|" + $os.getenv("PB_RS_MISSING_ENV"), 0o644);
              e.next();
            });
            "#,
        )]);
        let data_dir = dir.join("custom-data");
        let engine = HookEngine::load_with_data_dir(&dir, &data_dir).unwrap();
        engine
            .call("onRecordCreateRequest", &["posts".into()], event())
            .unwrap();
        let trace = std::fs::read_to_string(dir.join("app.txt")).unwrap();
        assert_eq!(trace, format!("{}|", data_dir.display()));
    }

    #[test]
    fn hooks_run_in_filename_order() {
        let dir = temp_hooks(&[
            (
                "b.pb.js",
                r#"onRecordCreateRequest((e) => { e.record.set("title", e.record.getString("title") + "b"); });"#,
            ),
            (
                "a.pb.js",
                r#"onRecordCreateRequest((e) => { e.record.set("title", e.record.getString("title") + "a"); });"#,
            ),
        ]);
        let engine = HookEngine::load(&dir).unwrap();
        let outcome = engine
            .call("onRecordCreateRequest", &["posts".into()], event())
            .unwrap();
        assert_eq!(outcome.record.unwrap()["title"], "helloab");
    }
}

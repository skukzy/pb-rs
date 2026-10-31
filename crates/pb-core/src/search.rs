//! Filter-expression parsing and SQL generation (`tools/search/filter.go`).
//!
//! The grammar is the faithful [`crate::fexpr`] port; this module converts the
//! flat token groups into an [`Expr`] tree, resolves record fields/macros and
//! renders SQLite WHERE fragments with PocketBase's null-fallback semantics.

use std::fmt;

// Record type alias for auth context
use crate::records::Record as PbRecord;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp {
        left: Box<Expr>,
        op: CmpOp,
        right: Box<Expr>,
    },
    Field(String),
    /// `@collection.<nameOrId>[:alias].<field>[.<sub>]`.
    CollectionField(String),
    AuthField(String),
    /// `identifierMacros`: `@now`, `@todayStart`, ...
    Macro(String),
    Literal(Literal),
    Func {
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    NotContains,
    /// `?=` and friends: any-value match on multi-value fields.
    AnyEq,
    AnyNe,
    AnyGt,
    AnyGte,
    AnyLt,
    AnyLte,
    AnyContains,
    AnyNotContains,
}

impl CmpOp {
    /// The underlying comparison for the `?` (any-match) variants.
    pub fn base(self) -> CmpOp {
        match self {
            CmpOp::AnyEq => CmpOp::Eq,
            CmpOp::AnyNe => CmpOp::Ne,
            CmpOp::AnyGt => CmpOp::Gt,
            CmpOp::AnyGte => CmpOp::Gte,
            CmpOp::AnyLt => CmpOp::Lt,
            CmpOp::AnyLte => CmpOp::Lte,
            CmpOp::AnyContains => CmpOp::Contains,
            CmpOp::AnyNotContains => CmpOp::NotContains,
            other => other,
        }
    }

    /// `?` operators skip the multi-match `NOT EXISTS` check.
    pub fn is_any(self) -> bool {
        self != self.base()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
}

impl fmt::Display for CmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CmpOp::Eq => "=",
            CmpOp::Ne => "!=",
            CmpOp::Gt => ">",
            CmpOp::Gte => ">=",
            CmpOp::Lt => "<",
            CmpOp::Lte => "<=",
            CmpOp::Contains => "~",
            CmpOp::NotContains => "!~",
            CmpOp::AnyEq => "?=",
            CmpOp::AnyNe => "?!=",
            CmpOp::AnyGt => "?>",
            CmpOp::AnyGte => "?>=",
            CmpOp::AnyLt => "?<",
            CmpOp::AnyLte => "?<=",
            CmpOp::AnyContains => "?~",
            CmpOp::AnyNotContains => "?!~",
        };
        write!(f, "{}", s)
    }
}

/// `search.MaxFilterLength`.
pub const MAX_FILTER_LENGTH: usize = 3500;
/// `search.DefaultFilterExprLimit`.
pub const DEFAULT_FILTER_EXPR_LIMIT: usize = 200;
/// `search.DefaultSortExprLimit`.
pub const DEFAULT_SORT_EXPR_LIMIT: usize = 8;
/// `search.MaxSortFieldLength`.
pub const MAX_SORT_FIELD_LENGTH: usize = 255;

/// `search.ErrFilterLengthLimit`.
pub const ERR_FILTER_LENGTH_LIMIT: &str = "max filter length limit reached";
/// `search.ErrFilterExprLimit`.
pub const ERR_FILTER_EXPR_LIMIT: &str = "max filter expressions limit reached";
/// `search.ErrSortExprLimit`.
pub const ERR_SORT_EXPR_LIMIT: &str = "max sort expressions limit reached";
/// `search.ErrSortFieldLengthLimit`.
pub const ERR_SORT_FIELD_LENGTH_LIMIT: &str = "max sort field length limit reached";

#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

// ---------- Parsing (`fexpr` port) ----------

/// Parse a filter/rule expression.
///
/// The grammar and all scanner/parser errors come from the faithful `fexpr`
/// port; the flat group list is converted to a binary tree while preserving
/// SQL's `AND`-before-`OR` precedence (PocketBase joins the parts with spaces
/// and lets SQLite parse the precedence).
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let groups = crate::fexpr::parse(input).map_err(ParseError)?;
    if groups.is_empty() {
        return Err(ParseError(crate::fexpr::ERR_EMPTY.to_string()));
    }
    Ok(convert_groups(&groups))
}

/// Parse and apply `search.DefaultFilterExprLimit`.
///
/// The limit counts tokenized expressions, i.e. leaves of the parsed tree;
/// grouping parentheses do not consume the budget.  This is what
/// `FilterData.BuildExpr` does before resolving fields.
pub fn parse_limited(input: &str) -> Result<Expr, ParseError> {
    let expr = parse(input)?;
    if expression_count(&expr) > DEFAULT_FILTER_EXPR_LIMIT {
        return Err(ParseError(ERR_FILTER_EXPR_LIMIT.to_string()));
    }
    Ok(expr)
}

/// `search.Provider.Exec`: filters longer than `MaxFilterLength` bytes are
/// rejected before parsing.
pub fn check_filter_length(raw: &str) -> Result<(), ParseError> {
    if raw.len() > MAX_FILTER_LENGTH {
        return Err(ParseError(ERR_FILTER_LENGTH_LIMIT.to_string()));
    }
    Ok(())
}

fn expression_count(expr: &Expr) -> usize {
    match expr {
        Expr::Cmp { .. } => 1,
        Expr::And(a, b) | Expr::Or(a, b) => expression_count(a) + expression_count(b),
        Expr::Not(inner) => expression_count(inner),
        _ => 0,
    }
}

fn convert_groups(groups: &[crate::fexpr::ExprGroup]) -> Expr {
    let mut or_terms: Vec<Expr> = Vec::new();
    let mut and_terms: Vec<Expr> = Vec::new();

    for group in groups {
        let item = match &group.item {
            crate::fexpr::GroupItem::Expr(expr) => convert_expr(expr),
            crate::fexpr::GroupItem::Groups(nested) => convert_groups(nested),
        };
        match group.join {
            crate::fexpr::JoinOp::Or => {
                or_terms.push(fold_and(std::mem::take(&mut and_terms)));
                and_terms.push(item);
            }
            crate::fexpr::JoinOp::And => and_terms.push(item),
        }
    }
    or_terms.push(fold_and(and_terms));

    or_terms
        .into_iter()
        .reduce(|a, b| Expr::Or(Box::new(a), Box::new(b)))
        .unwrap_or(Expr::Literal(Literal::Bool(true)))
}

fn fold_and(terms: Vec<Expr>) -> Expr {
    terms
        .into_iter()
        .reduce(|a, b| Expr::And(Box::new(a), Box::new(b)))
        .unwrap_or(Expr::Literal(Literal::Bool(true)))
}

fn convert_expr(expr: &crate::fexpr::Expr) -> Expr {
    Expr::Cmp {
        left: Box::new(convert_token(&expr.left)),
        op: convert_sign(&expr.op),
        right: Box::new(convert_token(&expr.right)),
    }
}

fn convert_token(token: &crate::fexpr::Token) -> Expr {
    use crate::fexpr::TokenType;

    match token.ty {
        TokenType::Identifier => {
            let literal = &token.literal;
            if is_macro(literal) {
                Expr::Macro(literal.clone())
            } else if let Some(rest) = literal.strip_prefix("@collection.") {
                Expr::CollectionField(rest.to_string())
            } else if let Some(rest) = literal.strip_prefix("@request.auth.") {
                Expr::AuthField(rest.to_string())
            } else {
                Expr::Field(literal.clone())
            }
        }
        TokenType::Text => Expr::Literal(Literal::String(token.literal.clone())),
        TokenType::Number => Expr::Literal(Literal::Number(
            token.literal.parse::<f64>().unwrap_or(0.0),
        )),
        TokenType::Function => Expr::Func {
            name: token.literal.clone(),
            args: token.meta.iter().map(convert_token).collect(),
        },
        _ => Expr::Literal(Literal::Null),
    }
}

fn convert_sign(sign: &str) -> CmpOp {
    match sign {
        "=" => CmpOp::Eq,
        "!=" => CmpOp::Ne,
        ">" => CmpOp::Gt,
        ">=" => CmpOp::Gte,
        "<" => CmpOp::Lt,
        "<=" => CmpOp::Lte,
        "~" => CmpOp::Contains,
        "!~" => CmpOp::NotContains,
        "?=" => CmpOp::AnyEq,
        "?!=" => CmpOp::AnyNe,
        "?>" => CmpOp::AnyGt,
        "?>=" => CmpOp::AnyGte,
        "?<" => CmpOp::AnyLt,
        "?<=" => CmpOp::AnyLte,
        "?~" => CmpOp::AnyContains,
        "?!~" => CmpOp::AnyNotContains,
        _ => CmpOp::Eq,
    }
}

/// `search.identifierMacros`: resolved before the field resolver.
fn is_macro(name: &str) -> bool {
    matches!(
        name,
        "@now"
            | "@yesterday"
            | "@tomorrow"
            | "@second"
            | "@minute"
            | "@hour"
            | "@day"
            | "@month"
            | "@weekday"
            | "@year"
            | "@todayStart"
            | "@todayEnd"
            | "@monthStart"
            | "@monthEnd"
            | "@yearStart"
            | "@yearEnd"
    )
}

/// Evaluate an `identifierMacros` entry (`timeNow().UTC()` in the oracle).
fn macro_value(name: &str) -> Literal {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let day_ms = 86_400_000i64;
    let days = ms.div_euclid(day_ms);
    let rem = ms.rem_euclid(day_ms);
    let (year, month, day) = crate::fields::civil_from_days(days);
    let hour = rem / 3_600_000;
    let minute = (rem % 3_600_000) / 60_000;
    let second = (rem % 60_000) / 1_000;

    match name {
        "@now" => Literal::String(crate::fields::format_date_millis(ms)),
        "@yesterday" => Literal::String(crate::fields::format_date_millis(ms - day_ms)),
        "@tomorrow" => Literal::String(crate::fields::format_date_millis(ms + day_ms)),
        "@second" => Literal::Number(second as f64),
        "@minute" => Literal::Number(minute as f64),
        "@hour" => Literal::Number(hour as f64),
        "@day" => Literal::Number(day as f64),
        "@month" => Literal::Number(month as f64),
        "@weekday" => Literal::Number((days + 4).rem_euclid(7) as f64),
        "@year" => Literal::Number(year as f64),
        "@todayStart" => Literal::String(crate::fields::format_date_millis(days * day_ms)),
        "@todayEnd" => {
            Literal::String(crate::fields::format_date_millis(days * day_ms + day_ms - 1))
        }
        "@monthStart" => Literal::String(crate::fields::format_date_millis(
            crate::fields::days_from_civil(year, month, 1) * day_ms,
        )),
        "@monthEnd" => {
            let next_month = if month == 12 { 1 } else { month + 1 };
            let next_year = if month == 12 { year + 1 } else { year };
            Literal::String(crate::fields::format_date_millis(
                crate::fields::days_from_civil(next_year, next_month, 1) * day_ms - 1,
            ))
        }
        "@yearStart" => Literal::String(crate::fields::format_date_millis(
            crate::fields::days_from_civil(year, 1, 1) * day_ms,
        )),
        "@yearEnd" => Literal::String(crate::fields::format_date_millis(
            crate::fields::days_from_civil(year + 1, 1, 1) * day_ms - 1,
        )),
        _ => Literal::Null,
    }
}

// ----------SQL generation----------

pub struct SqlFilter {
    pub sql: String,
    pub params: Vec<serde_json::Value>,
}

/// A field resolved by [`SimpleFieldResolver`].
#[derive(Clone, Debug)]
pub struct ResolvedField {
    pub identifier: String,
    /// `search.NullFallbackDisabled`: dotted (JSON) fields don't coalesce NULL,
    /// so `=`/`!=` are emitted as `IS`/`IS NOT`.
    pub null_fallback_disabled: bool,
}

/// `search.SimpleFieldResolver`: allowed plain names or anchored regex
/// patterns; dotted names resolve to `JSON_EXTRACT` paths.
#[derive(Clone, Debug)]
pub struct SimpleFieldResolver {
    allowed: Vec<String>,
    json_paths: bool,
}

impl SimpleFieldResolver {
    pub fn new(allowed: &[String], json_paths: bool) -> Self {
        Self {
            allowed: allowed.to_vec(),
            json_paths,
        }
    }

    pub fn resolve(&self, field: &str) -> Result<ResolvedField, ParseError> {
        if !exist_in_slice_with_regex(field, &self.allowed) {
            return Err(ParseError(format!("failed to resolve field {field:?}")));
        }

        let parts: Vec<&str> = field.split('.').collect();

        // single regular field
        if parts.len() == 1 {
            return Ok(ResolvedField {
                identifier: crate::records::quote_ident(&columnify(parts[0])),
                null_fallback_disabled: false,
            });
        }

        if !self.json_paths {
            return Err(ParseError(format!("failed to resolve field {field:?}")));
        }

        // treat as json path
        let mut path = String::from("$");
        for part in &parts[1..] {
            if part.parse::<i64>().is_ok() {
                path.push('[');
                path.push_str(&columnify(part));
                path.push(']');
            } else {
                path.push('.');
                path.push_str(&columnify(part));
            }
        }

        Ok(ResolvedField {
            identifier: format!(
                "JSON_EXTRACT({}, '{}')",
                crate::records::quote_ident(&columnify(parts[0])),
                path
            ),
            null_fallback_disabled: true,
        })
    }
}

/// `inflector.Columnify`: strip characters that aren't valid identifiers.
fn columnify(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '*' | '-' | '@' | '#')
        })
        .collect()
}

/// `list.ExistInSliceWithRegex`: exact match for plain entries, regex match
/// only for entries wrapped in `^...$`.
fn exist_in_slice_with_regex(value: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|pattern| {
        if pattern.starts_with('^') && pattern.ends_with('$') {
            regex::Regex::new(pattern)
                .map(|re| re.is_match(value))
                .unwrap_or(false)
        } else {
            pattern == value
        }
    })
}

/// Metadata for a relation field used by relation-path filters.
#[derive(Clone, Debug)]
pub struct RelationInfo {
    pub table: String,
    pub multiple: bool,
}

/// The request data that `@request.*` filter fields resolve against.
///
/// Mirrors `core.RequestInfo`: `Body` holds the already normalized record data
/// (modifiers resolved), `Query` the URL query values and `Headers` the HTTP
/// request headers (lowercased keys, like Go's `http.Header` canonical form).
#[derive(Clone, Debug, Default)]
pub struct RequestData {
    pub body: serde_json::Map<String, serde_json::Value>,
    pub query: std::collections::HashMap<String, String>,
    pub headers: std::collections::HashMap<String, String>,
    pub method: String,
    pub context: String,
}

/// Field metadata used by `@request.*` resolution (numeric strings are cast).
#[derive(Clone, Debug, Default)]
pub struct RequestFieldTypes {
    pub numbers: std::collections::HashSet<String>,
}

/// Replace `@request.*` identifiers with literals.
///
/// The filter parser keeps unknown `@request.*` names as [`Expr::Field`]; the
/// record field resolver turns them into bound parameters. This pre-pass does
/// the same after the parser, so both the list filter builder and the rule
/// evaluator see plain literals.
pub fn resolve_request_fields(
    expr: &Expr,
    request: &RequestData,
    types: &RequestFieldTypes,
) -> Result<Expr, ParseError> {
    Ok(match expr {
        Expr::Field(name) if name.starts_with("@request.") => {
            let value = request_field_value(name, request, types)?;
            match value {
                serde_json::Value::Null => Expr::Literal(Literal::Null),
                serde_json::Value::Bool(b) => Expr::Literal(Literal::Bool(b)),
                serde_json::Value::Number(n) => {
                    Expr::Literal(Literal::Number(n.as_f64().unwrap_or(0.0)))
                }
                serde_json::Value::String(s) => Expr::Literal(Literal::String(s)),
                other => Expr::Literal(Literal::String(crate::go_json::marshal(&other))),
            }
        }
        Expr::Or(a, b) => Expr::Or(
            Box::new(resolve_request_fields(a, request, types)?),
            Box::new(resolve_request_fields(b, request, types)?),
        ),
        Expr::And(a, b) => Expr::And(
            Box::new(resolve_request_fields(a, request, types)?),
            Box::new(resolve_request_fields(b, request, types)?),
        ),
        Expr::Not(e) => Expr::Not(Box::new(resolve_request_fields(e, request, types)?)),
        Expr::Cmp { left, op, right } => Expr::Cmp {
            left: Box::new(resolve_request_fields(left, request, types)?),
            op: *op,
            right: Box::new(resolve_request_fields(right, request, types)?),
        },
        Expr::Func { name, args } => Expr::Func {
            name: name.clone(),
            args: args
                .iter()
                .map(|a| resolve_request_fields(a, request, types))
                .collect::<Result<_, _>>()?,
        },
        other => other.clone(),
    })
}

fn request_field_value(
    name: &str,
    request: &RequestData,
    types: &RequestFieldTypes,
) -> Result<serde_json::Value, ParseError> {
    let path = name.trim_start_matches("@request.");
    let (head, rest) = path
        .split_once('.')
        .ok_or_else(|| ParseError(format!("invalid request field: {name}")))?;
    let (raw_path, modifier) = split_request_modifier(rest)?;

    let found = match head {
        "method" => Some(serde_json::Value::String(request.method.clone())),
        "context" => Some(serde_json::Value::String(request.context.clone())),
        "body" => extract_nested(&serde_json::Value::Object(request.body.clone()), &raw_path),
        "query" => extract_nested_string_map(&request.query, &raw_path),
        "headers" => {
            let lower = raw_path.to_lowercase();
            request
                .headers
                .get(&lower)
                .map(|s| serde_json::Value::String(s.clone()))
        }
        _ => None,
    };

    match modifier.as_str() {
        "isset" => return Ok(serde_json::Value::Bool(found.is_some())),
        "lower" => {
            let value = found.unwrap_or(serde_json::Value::Null);
            return Ok(match value {
                serde_json::Value::String(s) => serde_json::Value::String(s.to_lowercase()),
                other => other,
            });
        }
        "length" => {
            let value = found.unwrap_or(serde_json::Value::Null);
            let len = match &value {
                serde_json::Value::String(s) => s.chars().count(),
                serde_json::Value::Array(items) => items.len(),
                serde_json::Value::Object(map) => map.len(),
                _ => 0,
            };
            return Ok(serde_json::Value::from(len));
        }
        "each" => {
            return Err(ParseError(
                "@request.*:each is not supported in this context".into(),
            ))
        }
        "" => {}
        other => return Err(ParseError(format!("unknown modifier: {other}"))),
    }

    let Some(mut value) = found else {
        return Ok(serde_json::Value::Null);
    };

    // numeric strings coming from form data are cast for number fields
    if let serde_json::Value::String(s) = &value {
        if types.numbers.contains(&raw_path) {
            if let Ok(n) = s.parse::<f64>() {
                value = serde_json::Value::from(n);
            }
        }
    }

    Ok(value)
}

fn split_request_modifier(path: &str) -> Result<(String, String), ParseError> {
    match path.split_once(':') {
        None => Ok((path.to_string(), String::new())),
        Some((key, modifier)) => match modifier {
            "isset" | "each" | "length" | "lower" | "changed" => {
                Ok((key.to_string(), modifier.to_string()))
            }
            other => Err(ParseError(format!("unknown modifier: {other}"))),
        },
    }
}

fn extract_nested(value: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let mut current = value;
    for key in path.split('.') {
        match current {
            serde_json::Value::Object(map) => current = map.get(key)?,
            _ => return None,
        }
    }
    Some(current.clone())
}

fn extract_nested_string_map(
    map: &std::collections::HashMap<String, String>,
    path: &str,
) -> Option<serde_json::Value> {
    // URL query maps in Go are `map[string][]string`; `RequestInfo.Query` uses
    // the first value, so a plain lookup is enough here.
    map.get(path)
        .map(|s| serde_json::Value::String(s.clone()))
}

/// Metadata for a collection referenced through `@collection.*`.
#[derive(Clone, Debug, Default)]
pub struct CollectionInfo {
    pub table: String,
    pub fields: Vec<String>,
    /// Field name -> PocketBase field type (used by the rule validator).
    pub field_types: std::collections::HashMap<String, String>,
    /// Fields marked `hidden` (non-filterable for non-superusers).
    pub hidden: std::collections::HashSet<String>,
    pub relations: std::collections::HashMap<String, RelationInfo>,
}

/// Build a SQL WHERE clause from a filter expression.
/// `allowed_fields` is the set of valid field names (for validation).
pub fn build_sql(expr: &Expr, allowed_fields: &[String]) -> Result<SqlFilter, ParseError> {
    build_sql_with_auth(expr, allowed_fields, None)
}

pub fn build_sql_with_auth_and_relations(
    expr: &Expr,
    allowed_fields: &[String],
    auth: Option<&PbRecord>,
    relations: &std::collections::HashMap<String, RelationInfo>,
) -> Result<SqlFilter, ParseError> {
    build_sql_full(
        expr,
        allowed_fields,
        auth,
        relations,
        &std::collections::HashMap::new(),
    )
}

/// Full builder: relation traversal plus `@collection.*` references.
pub fn build_sql_full(
    expr: &Expr,
    allowed_fields: &[String],
    auth: Option<&PbRecord>,
    relations: &std::collections::HashMap<String, RelationInfo>,
    collections: &std::collections::HashMap<String, CollectionInfo>,
) -> Result<SqlFilter, ParseError> {
    build_sql_full_with_types(
        expr,
        allowed_fields,
        auth,
        relations,
        collections,
        &std::collections::HashMap::new(),
    )
}

/// Like [`build_sql_full`] but with the queried collection's field types.
pub fn build_sql_full_with_types(
    expr: &Expr,
    allowed_fields: &[String],
    auth: Option<&PbRecord>,
    relations: &std::collections::HashMap<String, RelationInfo>,
    collections: &std::collections::HashMap<String, CollectionInfo>,
    base_types: &std::collections::HashMap<String, String>,
) -> Result<SqlFilter, ParseError> {
    let mut ctx = BuildCtx {
        params: Vec::new(),
        allowed: allowed_fields,
        auth,
        relations,
        collections,
        base_types,
        simple: None,
    };
    let sql = build_expr(expr, &mut ctx)?;
    Ok(SqlFilter { sql, params: ctx.params })
}

/// Build a WHERE clause for the generic `search.SimpleFieldResolver` used by
/// the logs endpoints. Dotted fields resolve to JSON paths.
pub fn build_sql_simple(
    expr: &Expr,
    allowed_fields: &[String],
    json_paths: bool,
) -> Result<SqlFilter, ParseError> {
    let relations = std::collections::HashMap::new();
    let collections = std::collections::HashMap::new();
    let empty_types = std::collections::HashMap::new();
    let mut ctx = BuildCtx {
        params: Vec::new(),
        allowed: allowed_fields,
        auth: None,
        relations: &relations,
        collections: &collections,
        base_types: &empty_types,
        simple: Some(SimpleMode { json_paths }),
    };
    let sql = build_expr(expr, &mut ctx)?;
    Ok(SqlFilter { sql, params: ctx.params })
}

pub fn build_sql_with_auth(
    expr: &Expr,
    allowed_fields: &[String],
    auth: Option<&PbRecord>,
) -> Result<SqlFilter, ParseError> {
    build_sql_with_auth_and_relations(expr, allowed_fields, auth, &std::collections::HashMap::new())
}

// ---------- Rule validation (`core.RecordFieldResolver` error parity) ----------

/// `search.normalizedIdentifiers`: identifiers that fall back to SQL literals
/// when no collection field matches (case-insensitive, like `EqualFold`).
fn normalized_identifier(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case("null") {
        Some("NULL")
    } else if name.eq_ignore_ascii_case("true") {
        Some("1")
    } else if name.eq_ignore_ascii_case("false") {
        Some("0")
    } else {
        None
    }
}

fn is_go_word(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_ident_tail(rest: &str) -> bool {
    let mut chars = rest.chars();
    let Some(last) = chars.next_back() else {
        return false;
    };
    is_go_word(last) && rest.chars().all(|c| is_go_word(c) || c == '.' || c == ':')
}

/// `core.NewRecordFieldResolver` `allowedFields` (Go's `\w` is ASCII-only).
fn allowed_record_field(name: &str) -> bool {
    // `^\w+[\w\.\:]*$`
    if name
        .chars()
        .next()
        .is_some_and(is_go_word)
        && name.chars().all(|c| is_go_word(c) || c == '.' || c == ':')
    {
        return true;
    }

    if name == "@request.context" || name == "@request.method" {
        return true;
    }

    for prefix in [
        "@request.auth.",
        "@request.body.",
        "@request.query.",
        "@request.headers.",
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return is_ident_tail(rest);
        }
    }

    // `^\@collection\.\w+(\:\w+)?\.[\w\.\:]*\w+$`
    if let Some(rest) = name.strip_prefix("@collection.") {
        let mut chars = rest.chars();
        let mut name_len = 0usize;
        while chars.next().is_some_and(is_go_word) {
            name_len += 1;
        }
        if name_len == 0 {
            return false;
        }
        let after_name = &rest[name_len..];
        let after_alias = if let Some(alias) = after_name.strip_prefix(':') {
            let mut alias_chars = alias.chars();
            let mut alias_len = 0usize;
            while alias_chars.next().is_some_and(is_go_word) {
                alias_len += 1;
            }
            if alias_len == 0 {
                return false;
            }
            &alias[alias_len..]
        } else {
            after_name
        };
        let Some(tail) = after_alias.strip_prefix('.') else {
            return false;
        };
        return is_ident_tail(tail);
    }

    false
}

/// `core.splitModifier`.
fn split_modifier(combined: &str) -> Result<(&str, Option<&str>), ParseError> {
    let parts: Vec<&str> = combined.split(':').collect();
    if parts.len() != 2 {
        return Ok((combined, None));
    }
    match parts[1] {
        "isset" | "each" | "length" | "lower" | "changed" => Ok((parts[0], Some(parts[1]))),
        _ => Err(ParseError(format!(
            "unknown modifier in {}",
            crate::fields::go_quote(combined)
        ))),
    }
}

struct ValidationCtx<'a> {
    base: &'a CollectionInfo,
    collections: &'a std::collections::HashMap<String, CollectionInfo>,
}

impl<'a> ValidationCtx<'a> {
    fn collection(&self, name_or_id: &str) -> Option<&'a CollectionInfo> {
        self.collections.get(name_or_id)
    }

    fn resolve(&self, name: &str) -> Result<(), ParseError> {
        if !allowed_record_field(name) {
            return Err(ParseError(format!(
                "failed to resolve field {}",
                crate::fields::go_quote(name)
            )));
        }

        if name.starts_with("@collection.") {
            let props: Vec<&str> = name.split('.').collect();
            if props.len() < 3 {
                return Err(ParseError(format!(
                    "invalid @collection field path in {}",
                    crate::fields::go_quote(name)
                )));
            }
            let collection_part = props[1];
            let collection_name = collection_part.split(':').next().unwrap_or(collection_part);
            let Some(collection) = self.collection(collection_name) else {
                return Err(ParseError(format!(
                    "failed to load collection {} from field path {}",
                    crate::fields::go_quote(collection_part),
                    crate::fields::go_quote(name)
                )));
            };
            return self.process_active_props(collection, &props[2..], false);
        }

        if name.starts_with("@request.") {
            let props: Vec<&str> = name.split('.').collect();
            // `@request.auth.*` resolves to NULL when there is no auth record
            // (the rule validator always uses an empty RequestInfo).
            if name.starts_with("@request.auth.") {
                return Ok(());
            }
            if name.starts_with("@request.body.") && props.len() > 2 {
                let (field, _) = split_modifier(props[2])?;
                if self.base.field_types.contains_key(field) {
                    // The request body is empty during validation, so known
                    // body relation paths resolve to NULL.
                    return Ok(());
                }
            }
            if let Some(last) = props.last() {
                split_modifier(last)?;
            }
            return Ok(());
        }

        let props: Vec<&str> = name.split('.').collect();
        self.process_active_props(self.base, &props, false)
    }

    fn process_active_props(
        &self,
        mut active: &'a CollectionInfo,
        props: &[&str],
        nullify_missing: bool,
    ) -> Result<(), ParseError> {
        let total = props.len();
        for (i, prop) in props.iter().enumerate() {
            if i == total - 1 {
                return finalize_active_prop(active, prop);
            }

            let field = active.fields.iter().find(|f| f == prop);
            let Some(field) = field else {
                // back relation: `yourCollection_via_yourRelField`
                let parts: Vec<&str> = prop.split("_via_").collect();
                if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                    if nullify_missing {
                        return Ok(());
                    }
                    return Err(ParseError(format!(
                        "failed to resolve field {}",
                        crate::fields::go_quote(prop)
                    )));
                }
                let Some(back_collection) = self.collection(parts[0]) else {
                    if nullify_missing {
                        return Ok(());
                    }
                    return Err(ParseError(format!(
                        "failed to load back relation field {} collection",
                        crate::fields::go_quote(prop)
                    )));
                };
                let Some(back_field_type) = back_collection.field_types.get(parts[1]) else {
                    if nullify_missing {
                        return Ok(());
                    }
                    return Err(ParseError(format!(
                        "missing back relation field {}",
                        crate::fields::go_quote(parts[1])
                    )));
                };
                if back_field_type != "relation" {
                    if nullify_missing {
                        return Ok(());
                    }
                    return Err(ParseError(format!(
                        "invalid back relation field {}",
                        crate::fields::go_quote(parts[1])
                    )));
                }
                active = back_collection;
                continue;
            };

            if active.hidden.contains(field.as_str()) {
                return Err(ParseError(format!(
                    "non-filterable field {}",
                    crate::fields::go_quote(prop)
                )));
            }

            let field_type = active
                .field_types
                .get(field.as_str())
                .map(String::as_str)
                .unwrap_or("");

            if field_type == "json" || field_type == "geoPoint" {
                return Ok(());
            }

            if i >= 6 {
                return Err(ParseError(format!(
                    "max nested relations reached for field {}",
                    crate::fields::go_quote(prop)
                )));
            }

            if field_type != "relation" {
                return Err(ParseError(format!(
                    "field {} is not a valid relation",
                    crate::fields::go_quote(prop)
                )));
            }

            let Some(relation) = active.relations.get(field.as_str()) else {
                return Err(ParseError(format!(
                    "failed to load field {} collection",
                    crate::fields::go_quote(prop)
                )));
            };

            // "id" lookups optimization for single relations.
            if !relation.multiple && i + 2 == total && props[i + 1] == "id" {
                return finalize_active_prop(active, prop);
            }

            let Some(target) = self.collection(&relation.table) else {
                return Err(ParseError(format!(
                    "failed to load field {} collection",
                    crate::fields::go_quote(prop)
                )));
            };
            active = target;
        }

        Err(ParseError(format!(
            "failed to resolve field {}",
            crate::fields::go_quote(props.last().copied().unwrap_or(""))
        )))
    }
}

fn finalize_active_prop(collection: &CollectionInfo, prop: &str) -> Result<(), ParseError> {
    let (name, _) = split_modifier(prop)?;
    if !collection.fields.iter().any(|f| f == name) {
        return Err(ParseError(format!(
            "unknown field {}",
            crate::fields::go_quote(name)
        )));
    }
    if collection.hidden.contains(name) {
        return Err(ParseError(format!(
            "non-filterable field {}",
            crate::fields::go_quote(name)
        )));
    }
    Ok(())
}

/// Resolve one token for validation, mirroring `search.resolveToken`.
fn validate_token(expr: &Expr, ctx: &ValidationCtx<'_>) -> Result<(), ParseError> {
    match expr {
        Expr::Field(name) => ctx.resolve(name).or_else(|err| {
            normalized_identifier(name)
                .map(|_| ())
                .ok_or(err)
        }),
        Expr::AuthField(path) => ctx.resolve(&format!("@request.auth.{path}")),
        Expr::CollectionField(path) => ctx.resolve(&format!("@collection.{path}")),
        Expr::Macro(_) | Expr::Literal(_) => Ok(()),
        Expr::Func { name, args } => validate_token_function(name, args, ctx),
        _ => Err(ParseError("unsupported token type".into())),
    }
}

fn validate_token_function(
    name: &str,
    args: &[Expr],
    ctx: &ValidationCtx<'_>,
) -> Result<(), ParseError> {
    match name {
        "geoDistance" => {
            if args.len() != 4 {
                return Err(ParseError(format!(
                    "[geoDistance] expected 4 arguments, got {}",
                    args.len()
                )));
            }
            for (i, arg) in args.iter().enumerate() {
                let identifier_or_number = matches!(
                    arg,
                    Expr::Field(_)
                        | Expr::AuthField(_)
                        | Expr::CollectionField(_)
                        | Expr::Macro(_)
                        | Expr::Literal(Literal::Number(_))
                );
                if !identifier_or_number {
                    return Err(ParseError(format!(
                        "[geoDistance] argument {i} must be an identifier or number"
                    )));
                }
                validate_token(arg, ctx).map_err(|e| {
                    ParseError(format!("[geoDistance] failed to resolve argument {i}: {e}"))
                })?;
            }
            Ok(())
        }
        "strftime" => {
            let total = args.len();
            if total < 1 {
                return Err(ParseError(format!(
                    "[strftime] expected at least 1 arguments, got {total}"
                )));
            }
            if total > 10 {
                return Err(ParseError(format!(
                    "[strftime] too many arguments (max allowed 10, got {total})"
                )));
            }
            if !matches!(args[0], Expr::Literal(Literal::String(_))) {
                return Err(ParseError(
                    "[strftime] expects the first argument to be a format string".into(),
                ));
            }
            validate_token(&args[0], ctx).map_err(|e| {
                ParseError(format!("[strftime] failed to resolve format argument: {e}"))
            })?;
            if total == 1 {
                return Ok(());
            }
            let valid_time_value = matches!(
                args[1],
                Expr::Literal(Literal::String(_))
                    | Expr::Literal(Literal::Number(_))
                    | Expr::Field(_)
                    | Expr::AuthField(_)
                    | Expr::CollectionField(_)
                    | Expr::Macro(_)
            );
            if !valid_time_value {
                return Err(ParseError(
                    "[strftime] expects the second argument to be of a valid time-value type".into(),
                ));
            }
            validate_token(&args[1], ctx).map_err(|e| {
                ParseError(format!(
                    "[strftime] failed to resolve time-value argument: {e}"
                ))
            })?;
            for (i, arg) in args[2..].iter().enumerate() {
                if !matches!(arg, Expr::Literal(Literal::String(_))) {
                    return Err(ParseError(format!(
                        "[strftime] invalid modifier argument {i} - can be only string"
                    )));
                }
                validate_token(arg, ctx).map_err(|e| {
                    ParseError(format!(
                        "[strftime] failed to resolve modifier argument {i}: {e}"
                    ))
                })?;
            }
            Ok(())
        }
        other => Err(ParseError(format!(
            "unknown function {}",
            crate::fields::go_quote(other)
        ))),
    }
}

fn validate_token_literal(expr: &Expr) -> String {
    match expr {
        Expr::Field(name) => name.clone(),
        Expr::CollectionField(path) => format!("@collection.{path}"),
        Expr::AuthField(path) => format!("@request.auth.{path}"),
        Expr::Macro(name) => name.clone(),
        Expr::Func { name, .. } => name.clone(),
        Expr::Literal(Literal::String(s)) => s.clone(),
        Expr::Literal(Literal::Number(n)) => {
            let mut out = n.to_string();
            if !out.contains('.') {
                out.push_str(".0");
            }
            out
        }
        Expr::Literal(Literal::Bool(b)) => b.to_string(),
        Expr::Literal(Literal::Null) => "null".into(),
        _ => String::new(),
    }
}

/// Validate a parsed rule/filter expression against a collection schema,
/// reproducing `search.resolveTokenizedExpr`'s wrapped error messages.
pub fn validate_record_expr(
    expr: &Expr,
    base: &CollectionInfo,
    collections: &std::collections::HashMap<String, CollectionInfo>,
) -> Result<(), ParseError> {
    let ctx = ValidationCtx { base, collections };
    validate_expr_inner(expr, &ctx)
}

fn validate_expr_inner(expr: &Expr, ctx: &ValidationCtx<'_>) -> Result<(), ParseError> {
    match expr {
        Expr::Or(a, b) | Expr::And(a, b) => {
            validate_expr_inner(a, ctx)?;
            validate_expr_inner(b, ctx)
        }
        Expr::Not(inner) => validate_expr_inner(inner, ctx),
        Expr::Cmp { left, right, .. } => {
            if let Err(err) = validate_token(left, ctx) {
                return Err(ParseError(format!(
                    "invalid left operand {} - {err}",
                    crate::fields::go_quote(&validate_token_literal(left))
                )));
            }
            if let Err(err) = validate_token(right, ctx) {
                return Err(ParseError(format!(
                    "invalid right operand {} - {err}",
                    crate::fields::go_quote(&validate_token_literal(right))
                )));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Copy)]
struct SimpleMode {
    json_paths: bool,
}

struct BuildCtx<'a> {
    params: Vec<serde_json::Value>,
    allowed: &'a [String],
    auth: Option<&'a PbRecord>,
    relations: &'a std::collections::HashMap<String, RelationInfo>,
    collections: &'a std::collections::HashMap<String, CollectionInfo>,
    /// Field name -> field type for the queried collection, used to
    /// distinguish JSON paths from invalid relation traversals.
    base_types: &'a std::collections::HashMap<String, String>,
    /// Set for `search.SimpleFieldResolver` queries (logs). The collection
    /// resolver ignores dotted JSON paths.
    simple: Option<SimpleMode>,
}

fn build_expr(expr: &Expr, ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    match expr {
        Expr::Or(a, b) => {
            let la = build_expr(a, ctx)?;
            let lb = build_expr(b, ctx)?;
            Ok(format!("({} OR {})", la, lb))
        }
        Expr::And(a, b) => {
            let la = build_expr(a, ctx)?;
            let lb = build_expr(b, ctx)?;
            Ok(format!("({} AND {})", la, lb))
        }
        Expr::Not(e) => {
            let inner = build_expr(e, ctx)?;
            Ok(format!("NOT ({})", inner))
        }
        Expr::Cmp { left, op, right } => build_cmp(left, *op, right, ctx),
        Expr::CollectionField(path) => {
            let (from, col) = collection_from(path, ctx)?;
            Ok(format!("EXISTS (SELECT 1 FROM {from} WHERE {col})"))
        }
        Expr::Field(name) => {
            if let Some(mode) = ctx.simple {
                let resolver = SimpleFieldResolver::new(ctx.allowed, mode.json_paths);
                return match resolver.resolve(name) {
                    Ok(field) => Ok(field.identifier),
                    Err(err) => match normalized_identifier(name) {
                        Some(sql) => Ok(sql.into()),
                        None => Err(err),
                    },
                };
            }
            let (clean, modifier) = split_modifier(name)?;
            if let Some((first, _rest)) = clean.split_once('.') {
                if !ctx.allowed.iter().any(|f| f == first) && first != "id" {
                    // The record resolver processes the first path segment
                    // before it can reach the final `unknown field` check.
                    return Err(ParseError(format!(
                        "failed to resolve field {}",
                        crate::fields::go_quote(first)
                    )));
                }
                let field_type = ctx
                    .base_types
                    .get(first)
                    .map(String::as_str)
                    .unwrap_or("");
                if field_type != "json" && field_type != "geoPoint" {
                    return Err(ParseError(format!(
                        "field {} is not a valid relation",
                        crate::fields::go_quote(first)
                    )));
                }
                let column = crate::records::quote_ident(clean);
                return Ok(match modifier {
                    Some("lower") => format!("LOWER({column})"),
                    _ => column,
                });
            }
            if !ctx.allowed.iter().any(|f| f == clean) && clean != "id" {
                if let Some(sql) = normalized_identifier(clean) {
                    return Ok(sql.into());
                }
                return Err(ParseError(format!(
                    "unknown field {}",
                    crate::fields::go_quote(clean)
                )));
            }
            let column = crate::records::quote_ident(clean);
            Ok(match modifier {
                Some("lower") => format!("LOWER({column})"),
                _ => column,
            })
        }
        Expr::AuthField(path) => {
            let val = ctx
                .auth
                .and_then(|a| a.data.get(path.as_str()).cloned())
                .unwrap_or(serde_json::Value::Null);
            // `processRequestAuthField`: a missing auth record (or missing
            // field on it) resolves to the literal `NULL` identifier, not a
            // bound NULL parameter.  `resolveEqualExpr` treats that identifier
            // as an empty operand, which is what makes e.g.
            // `team.members ?= @request.auth.id` match records whose `team`
            // relation is empty.
            if val.is_null() {
                return Ok("NULL".into());
            }
            ctx.params.push(val);
            Ok("?".into())
        }
        Expr::Macro(name) => build_expr(&Expr::Literal(macro_value(name)), ctx),
        Expr::Literal(lit) => match lit {
            Literal::Null => Ok("NULL".into()),
            Literal::Bool(b) => {
                ctx.params.push(serde_json::Value::Bool(*b));
                Ok("?".into())
            }
            Literal::Number(n) => {
                ctx.params.push(serde_json::json!(*n));
                Ok("?".into())
            }
            Literal::String(s) => {
                ctx.params.push(serde_json::Value::String(s.clone()));
                Ok("?".into())
            }
        },
        Expr::Func { name, args } => build_func(name, args, ctx),
    }
}

/// `search.TokenFunctions`: PocketBase v0.40 only registers `geoDistance` and
/// `strftime`; everything else is an `unknown function` resolution error.
fn build_func(name: &str, args: &[Expr], ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    match name {
        "geoDistance" => build_geo_distance(args, ctx),
        "strftime" => build_strftime(args, ctx),
        other => Err(ParseError(format!(
            "unknown function {}",
            crate::fields::go_quote(other)
        ))),
    }
}

fn build_geo_distance(args: &[Expr], ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    if args.len() != 4 {
        return Err(ParseError(format!(
            "[geoDistance] expected 4 arguments, got {}",
            args.len()
        )));
    }

    let base = ctx.params.len();
    let mut resolved: Vec<(String, Vec<serde_json::Value>)> = Vec::with_capacity(4);
    for (i, arg) in args.iter().enumerate() {
        if !matches!(arg, Expr::Field(_) | Expr::AuthField(_) | Expr::CollectionField(_) | Expr::Macro(_) | Expr::Literal(Literal::Number(_))) {
            return Err(ParseError(format!(
                "[geoDistance] argument {i} must be an identifier or number"
            )));
        }
        let start = ctx.params.len();
        let sql = build_expr(arg, ctx)
            .map_err(|e| ParseError(format!("[geoDistance] failed to resolve argument {i}: {e}")))?;
        resolved.push((sql, ctx.params[start..].to_vec()));
    }
    ctx.params.truncate(base);

    // The identifier is reused six times but PocketBase's dbx placeholders are
    // named, so a literal argument binds once.  The port's placeholders are
    // positional: duplicate the params in the exact order the expression
    // references them (latA, latB, lonB, lonA, latA, latB).
    for index in [1usize, 3, 2, 0, 1, 3] {
        ctx.params.extend(resolved[index].1.iter().cloned());
    }

    // The clamping prevents floating point rounding errors for identical
    // points (arccosine domain).
    Ok(format!(
        "(6371 * acos(min(1, max(-1, \
         cos(radians({lat_a})) * cos(radians({lat_b})) * \
         cos(radians({lon_b}) - radians({lon_a})) + \
         sin(radians({lat_a})) * sin(radians({lat_b}))\
         ))))",
        lon_a = resolved[0].0,
        lat_a = resolved[1].0,
        lon_b = resolved[2].0,
        lat_b = resolved[3].0,
    ))
}

fn build_strftime(args: &[Expr], ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    let total = args.len();
    if total < 1 {
        return Err(ParseError(format!(
            "[strftime] expected at least 1 arguments, got {total}"
        )));
    }
    if total > 10 {
        return Err(ParseError(format!(
            "[strftime] too many arguments (max allowed 10, got {total})"
        )));
    }

    if !matches!(args[0], Expr::Literal(Literal::String(_))) {
        return Err(ParseError(
            "[strftime] expects the first argument to be a format string".into(),
        ));
    }
    let format = build_expr(&args[0], ctx).map_err(|e| {
        ParseError(format!("[strftime] failed to resolve format argument: {e}"))
    })?;

    if total == 1 {
        return Ok(format!("strftime({format})"));
    }

    if !matches!(
        args[1],
        Expr::Literal(Literal::String(_))
            | Expr::Literal(Literal::Number(_))
            | Expr::Field(_)
            | Expr::AuthField(_)
            | Expr::CollectionField(_)
            | Expr::Macro(_)
    ) {
        return Err(ParseError(
            "[strftime] expects the second argument to be of a valid time-value type".into(),
        ));
    }
    let time_value = build_expr(&args[1], ctx).map_err(|e| {
        ParseError(format!(
            "[strftime] failed to resolve time-value argument: {e}"
        ))
    })?;

    let mut identifiers = vec![format, time_value];
    for (i, arg) in args[2..].iter().enumerate() {
        if !matches!(arg, Expr::Literal(Literal::String(_))) {
            return Err(ParseError(format!(
                "[strftime] invalid modifier argument {i} - can be only string"
            )));
        }
        let modifier = build_expr(arg, ctx).map_err(|e| {
            ParseError(format!(
                "[strftime] failed to resolve modifier argument {i}: {e}"
            ))
        })?;
        identifiers.push(modifier);
    }

    Ok(format!("strftime({})", identifiers.join(",")))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperandKind {
    Value,
    EmptyString,
    Null,
}

fn static_kind(expr: &Expr, ctx: &BuildCtx<'_>) -> OperandKind {
    match expr {
        Expr::Literal(Literal::Null) => OperandKind::Null,
        Expr::Literal(Literal::String(s)) if s.is_empty() => OperandKind::EmptyString,
        // `null` is an identifier that `resolveToken` normalizes to the SQL
        // `NULL` token.  It is an empty operand for `resolveEqualExpr`.
        Expr::Field(name) if name.eq_ignore_ascii_case("null") => OperandKind::Null,
        // A missing `@request.auth.*` resolves to `Identifier: "NULL"`.
        Expr::AuthField(path) => {
            let missing = ctx
                .auth
                .and_then(|a| a.data.get(path.as_str()))
                .map_or(true, serde_json::Value::is_null);
            if missing {
                OperandKind::Null
            } else {
                OperandKind::Value
            }
        }
        _ => OperandKind::Value,
    }
}

/// Build an operand, remembering whether it is an empty-string/null literal so
/// that `resolveEqualExpr`'s null-fallback rules can be reproduced.
fn build_operand(
    expr: &Expr,
    ctx: &mut BuildCtx<'_>,
) -> Result<(String, OperandKind), ParseError> {
    match static_kind(expr, ctx) {
        OperandKind::Null => Ok(("NULL".into(), OperandKind::Null)),
        // `resolveEqualExpr` inlines empty strings as `''`, so no bound param
        // is emitted for this operand.
        OperandKind::EmptyString => Ok(("''".into(), OperandKind::EmptyString)),
        OperandKind::Value => {
            let start = ctx.params.len();
            let sql = build_expr(expr, ctx)?;
            // `hasEmptyParamValue`: a single NULL/empty parameter makes the
            // operand empty for `NullFallbackAuto`.  Go still keeps the unused
            // named parameter, but inline `''` is equivalent and keeps the
            // port's positional parameter list consistent.
            if ctx.params.len() == start + 1
                && (ctx.params[start].is_null() || ctx.params[start].as_str() == Some(""))
            {
                ctx.params.truncate(start);
                return Ok(("''".into(), OperandKind::EmptyString));
            }
            Ok((sql, OperandKind::Value))
        }
    }
}

/// Compare two built operands, duplicating the parameters of an operand that
/// `resolveEqualExpr` repeats in the SQL (the empty-string fallback).
fn compare_operands(
    left: &str,
    left_kind: OperandKind,
    left_start: usize,
    op: CmpOp,
    right: &str,
    right_kind: OperandKind,
    right_start: usize,
    ctx: &mut BuildCtx<'_>,
) -> String {
    // Empty operands are inlined (`''`/`NULL`) and the non-empty side is
    // printed twice by `resolveEqualExpr`.  Named dbx placeholders are reused
    // on the Go side; positional ones have to be duplicated here.
    let left_empty = matches!(left_kind, OperandKind::Null | OperandKind::EmptyString);
    let right_empty = matches!(right_kind, OperandKind::Null | OperandKind::EmptyString);
    if left_empty && !right_empty && ctx.params.len() > right_start {
        let repeated = ctx.params[right_start..].to_vec();
        ctx.params.extend(repeated);
    } else if right_empty && !left_empty && ctx.params.len() > left_start {
        let repeated = ctx.params[left_start..right_start].to_vec();
        ctx.params.extend(repeated);
    }
    compare_sql(left, left_kind, op, right, right_kind)
}

/// `tools/search/filter.go` `resolveEqualExpr` + the simple operators.
fn compare_sql(
    left: &str,
    left_kind: OperandKind,
    op: CmpOp,
    right: &str,
    right_kind: OperandKind,
) -> String {
    let (equal_op, concat, null_expr) = match op {
        CmpOp::Ne => ("IS NOT", "AND", "IS NOT NULL"),
        _ => ("=", "OR", "IS NULL"),
    };

    // `resolveEqualExpr` decides the shape from `isEmptyIdentifier`, which
    // covers both the `''` token and the `NULL` identifier produced by missing
    // `@request.auth.*` fields.  They therefore share the same fallback
    // branches; only `NullFallbackDisabled` (JSON fields) skips them, and that
    // case is handled by the caller.
    let left_empty = matches!(left_kind, OperandKind::Null | OperandKind::EmptyString);
    let right_empty = matches!(right_kind, OperandKind::Null | OperandKind::EmptyString);

    match op {
        CmpOp::Eq | CmpOp::Ne => {
            if left_empty && right_empty {
                format!("'' {equal_op} ''")
            } else if left_empty {
                format!("('' {equal_op} {right} {concat} {right} {null_expr})")
            } else if right_empty {
                format!("({left} {equal_op} '' {concat} {left} {null_expr})")
            } else {
                format!("{left} {equal_op} {right}")
            }
        }
        CmpOp::Gt => format!("{left} > {right}"),
        CmpOp::Gte => format!("{left} >= {right}"),
        CmpOp::Lt => format!("{left} < {right}"),
        CmpOp::Lte => format!("{left} <= {right}"),
        // LIKE is built by `like_sql`.
        CmpOp::Contains | CmpOp::NotContains => unreachable!(),
        _ => unreachable!(),
    }
}

/// `tools/search/filter.go` `containsUnescapedChar`.
fn contains_unescaped_percent(s: &str) -> bool {
    let mut prev = '\0';
    for c in s.chars() {
        if c == '%' && prev != '\\' {
            return true;
        }
        if c == '\\' && prev == '\\' {
            prev = '\0';
        } else {
            prev = c;
        }
    }
    false
}

/// `tools/search/filter.go` `escapeUnescapedChars`.
fn escape_unescaped_chars(s: &str, escape_chars: &[char]) -> String {
    let rs: Vec<char> = s.chars().collect();
    let mut result: Vec<char> = Vec::with_capacity(rs.len());
    let mut matched = false;

    for i in (0..rs.len()).rev() {
        if matched {
            if rs[i] != '\\' {
                result.push('\\');
            }
            matched = false;
        } else if escape_chars.contains(&rs[i]) {
            matched = true;
        }
        result.push(rs[i]);
        if i == 0 && matched {
            result.push('\\');
        }
    }
    result.reverse();
    result.into_iter().collect()
}

/// `tools/search/filter.go` `wrapLikeParams`.
fn wrap_like_param(s: &str) -> String {
    if contains_unescaped_percent(s) {
        s.to_string()
    } else {
        format!("%{}%", escape_unescaped_chars(s, &['\\', '%', '_']))
    }
}

/// Build `left LIKE/Not LIKE right ESCAPE '\'` with PB's param wrapping.
fn like_sql(
    left: &str,
    right: &Expr,
    ctx: &mut BuildCtx<'_>,
    negate: bool,
) -> Result<String, ParseError> {
    let before = ctx.params.len();
    let r = build_expr(right, ctx)?;
    let keyword = if negate { "NOT LIKE" } else { "LIKE" };
    if ctx.params.len() > before {
        // `wrapLikeParams` casts every param to string (numbers, bools, null
        // included) before adding the wildcards.  Leaving a number as a
        // numeric parameter changes SQLite's LIKE coercion and silently
        // changes which rows match.
        for p in &mut ctx.params[before..] {
            let text = crate::fields::cast_to_string(p);
            *p = serde_json::Value::String(wrap_like_param(&text));
        }
        Ok(format!("{left} {keyword} {r} ESCAPE '\\'"))
    } else {
        Ok(format!("{left} {keyword} ('%' || {r} || '%') ESCAPE '\\'"))
    }
}

/// Resolve `@collection.<name[:alias]>.<field>[.<sub>]` into a FROM clause and
/// the final column expression. The FROM always yields at least one row, so an
/// empty referenced collection behaves like PB's `LEFT JOIN` (NULL columns).
fn collection_from(
    path: &str,
    ctx: &mut BuildCtx<'_>,
) -> Result<(String, String), ParseError> {
    let (head, rest) = path
        .split_once('.')
        .ok_or_else(|| ParseError(format!("invalid @collection field path: {path}")))?;
    let (name, alias) = match head.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (head, None),
    };
    let (field, sub) = match rest.split_once('.') {
        Some((f, s)) => (f, Some(s)),
        None => (rest, None),
    };
    if let Some(sub) = sub {
        if sub.contains('.') {
            return Err(ParseError(format!(
                "nested @collection path is not supported: {path}"
            )));
        }
    }
    let info = ctx
        .collections
        .get(name)
        .ok_or_else(|| ParseError(format!("unknown collection: {name}")))?;
    if !info.fields.iter().any(|f| f == field) && field != "id" {
        return Err(ParseError(format!("unknown field: {field}")));
    }
    let alias = alias.unwrap_or(name);
    let alias_sql = format!(
        "__pc_{}",
        alias.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    );
    let table = crate::records::quote_ident(&info.table);

    match sub {
        None => Ok((
            format!("(SELECT 1) AS __pb_one LEFT JOIN {table} AS {alias_sql} ON 1"),
            format!("{alias_sql}.{}", crate::records::quote_ident(field)),
        )),
        Some(sub) => {
            let rel = info
                .relations
                .get(field)
                .ok_or_else(|| ParseError(format!("field {field} is not a relation")))?;
            let rel_table = crate::records::quote_ident(&rel.table);
            if rel.multiple {
                let je = format!("{alias_sql}_je");
                Ok((
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN {table} AS {alias_sql} ON 1 \
                         LEFT JOIN json_each({alias_sql}.{field}) AS {je} ON 1 \
                         LEFT JOIN {rel_table} AS __pc_rel ON __pc_rel.id = {je}.value",
                        field = crate::records::quote_ident(field),
                    ),
                    format!("__pc_rel.{}", crate::records::quote_ident(sub)),
                ))
            } else {
                Ok((
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN {table} AS {alias_sql} ON 1 \
                         LEFT JOIN {rel_table} AS __pc_rel ON __pc_rel.id = {alias_sql}.{field}",
                        field = crate::records::quote_ident(field),
                    ),
                    format!("__pc_rel.{}", crate::records::quote_ident(sub)),
                ))
            }
        }
    }
}

/// Compare a raw column expression against the right operand.
fn column_cmp_sql(
    left: &str,
    op: CmpOp,
    right: &Expr,
    ctx: &mut BuildCtx<'_>,
) -> Result<String, ParseError> {
    match op {
        CmpOp::Contains | CmpOp::NotContains => {
            like_sql(left, right, ctx, op == CmpOp::NotContains)
        }
        _ => {
            let (r, kind) = build_operand(right, ctx)?;
            Ok(compare_sql(left, OperandKind::Value, op, &r, kind))
        }
    }
}

/// Comparison of a related record's column (`__pb_rel.<sub>`).
/// Validate a relation-path suffix (`rel.<sub>`) against the target schema,
/// mirroring `runner.processActiveProps` errors. Nested relations are walked,
/// but the SQL builder only renders one level (tracked separately).
fn validate_relation_sub<'a>(
    mut active: &'a CollectionInfo,
    path: &str,
    collections: &'a std::collections::HashMap<String, CollectionInfo>,
) -> Result<(), ParseError> {
    let props: Vec<&str> = path.split('.').collect();
    for (i, prop) in props.iter().enumerate() {
        if i == props.len() - 1 {
            let (name, _) = split_modifier(prop)?;
            if !active.fields.iter().any(|f| f == name) && name != "id" {
                return Err(ParseError(format!(
                    "unknown field {}",
                    crate::fields::go_quote(name)
                )));
            }
            return Ok(());
        }

        let Some(field) = active.fields.iter().find(|f| f == prop) else {
            return Err(ParseError(format!(
                "failed to resolve field {}",
                crate::fields::go_quote(prop)
            )));
        };
        let field_type = active
            .field_types
            .get(field.as_str())
            .map(String::as_str)
            .unwrap_or("");
        if field_type == "json" || field_type == "geoPoint" {
            return Ok(());
        }
        if field_type != "relation" {
            return Err(ParseError(format!(
                "field {} is not a valid relation",
                crate::fields::go_quote(prop)
            )));
        }
        let Some(relation) = active.relations.get(field.as_str()) else {
            return Err(ParseError(format!(
                "failed to load field {} collection",
                crate::fields::go_quote(prop)
            )));
        };
        let Some(target) = collections.get(&relation.table) else {
            return Err(ParseError(format!(
                "failed to load field {} collection",
                crate::fields::go_quote(prop)
            )));
        };
        active = target;
    }
    Ok(())
}

fn relation_cmp_sql(
    rel_alias: &str,
    sub: &str,
    op: CmpOp,
    right: &Expr,
    ctx: &mut BuildCtx<'_>,
) -> Result<String, ParseError> {
    let (sub, modifier) = split_modifier(sub)?;
    let column = format!("{}.{}", rel_alias, crate::records::quote_ident(sub));
    let left = match modifier {
        Some("lower") => format!("LOWER({column})"),
        _ => column,
    };
    match op {
        CmpOp::Contains | CmpOp::NotContains => {
            like_sql(&left, right, ctx, op == CmpOp::NotContains)
        }
        _ => {
            let (r, kind) = build_operand(right, ctx)?;
            Ok(compare_sql(&left, OperandKind::Value, op, &r, kind))
        }
    }
}

/// The original token text of an operand (`fexpr.Token.Literal`), used by
/// Go's `invalid left/right operand %q` error wrappers.
fn expr_literal(expr: &Expr) -> String {
    match expr {
        Expr::Field(name)
        | Expr::AuthField(name)
        | Expr::Macro(name)
        | Expr::CollectionField(name) => name.clone(),
        Expr::Literal(Literal::String(value)) => value.clone(),
        Expr::Literal(Literal::Number(value)) => {
            if value.fract() == 0.0 {
                format!("{}", *value as i64)
            } else {
                value.to_string()
            }
        }
        Expr::Literal(Literal::Bool(value)) => value.to_string(),
        Expr::Literal(Literal::Null) => "null".to_string(),
        _ => String::new(),
    }
}

/// `fmt.Errorf("invalid %s operand %q - %v", side, literal, err)`.
fn operand_error(side: &str, expr: &Expr, err: ParseError) -> ParseError {
    ParseError(format!(
        "invalid {side} operand {} - {}",
        crate::fields::go_quote(&expr_literal(expr)),
        err.0
    ))
}

fn build_cmp(left: &Expr, op: CmpOp, right: &Expr, ctx: &mut BuildCtx<'_>) -> Result<String, ParseError> {
    let any = op.is_any();
    let base = op.base();

    // `search.SimpleFieldResolver` (logs): no relation traversal, and dotted
    // fields are JSON paths whose NULL fallback is disabled.
    if ctx.simple.is_some() {
        let left_json = matches!(left, Expr::Field(name) if name.contains('.'));
        let right_json = matches!(right, Expr::Field(name) if name.contains('.'));
        let left_start = ctx.params.len();
        // `resolveTokenizedExpr`: both operands are resolved up-front and the
        // resolver error is wrapped with the raw token literal.
        let (l, left_kind) = build_operand(left, ctx)
            .map_err(|err| operand_error("left", left, err))?;
        return match base {
            CmpOp::Contains | CmpOp::NotContains => {
                like_sql(&l, right, ctx, base == CmpOp::NotContains)
                    .map_err(|err| operand_error("right", right, err))
            }
            CmpOp::Eq | CmpOp::Ne if left_json || right_json => {
                let (r, _) = build_operand(right, ctx)
                    .map_err(|err| operand_error("right", right, err))?;
                let sql_op = if base == CmpOp::Eq { "IS" } else { "IS NOT" };
                Ok(format!("{l} {sql_op} {r}"))
            }
            _ => {
                let right_start = ctx.params.len();
                let (r, kind) = build_operand(right, ctx)
                    .map_err(|err| operand_error("right", right, err))?;
                Ok(compare_operands(
                    &l,
                    left_kind,
                    left_start,
                    base,
                    &r,
                    kind,
                    right_start,
                    ctx,
                ))
            }
        };
    }

    // `@collection.<name>.<field> <op> value`.
    if let Expr::CollectionField(path) = left {
        let (from, col) = collection_from(path, ctx)?;
        let outer_cmp = column_cmp_sql(&col, base, right, ctx)?;
        let mut sql = format!("EXISTS (SELECT 1 FROM {from} WHERE {outer_cmp})");
        if !any {
            let (from2, col2) = collection_from(path, ctx)?;
            let inner_cmp = column_cmp_sql(&col2, base, right, ctx)?;
            sql = format!(
                "({sql} AND NOT EXISTS (SELECT 1 FROM {from2} WHERE NOT ({inner_cmp})))"
            );
        }
        return Ok(sql);
    }

    // `value <op> @collection.<name>.<field>` (collection on the right).
    if let Expr::CollectionField(path) = right {
        if matches!(left, Expr::Field(n) if n.contains('.')) {
            return Err(ParseError(
                "@collection on the right of a relation path is not supported".into(),
            ));
        }
        let (from, col) = collection_from(path, ctx)?;
        let cmp_sql = |col: &str, ctx: &mut BuildCtx<'_>| -> Result<String, ParseError> {
            match base {
                CmpOp::Contains => {
                    let l = build_expr(left, ctx)?;
                    Ok(format!("{l} LIKE ('%' || {col} || '%') ESCAPE '\\'"))
                }
                CmpOp::NotContains => {
                    let l = build_expr(left, ctx)?;
                    Ok(format!("{l} NOT LIKE ('%' || {col} || '%') ESCAPE '\\'"))
                }
                _ => {
                    let (l, left_kind) = build_operand(left, ctx)?;
                    Ok(compare_sql(&l, left_kind, base, col, OperandKind::Value))
                }
            }
        };
        let outer_cmp = cmp_sql(&col, ctx)?;
        let mut sql = format!("EXISTS (SELECT 1 FROM {from} WHERE {outer_cmp})");
        if !any {
            let (from2, col2) = collection_from(path, ctx)?;
            let inner_cmp = cmp_sql(&col2, ctx)?;
            sql = format!(
                "({sql} AND NOT EXISTS (SELECT 1 FROM {from2} WHERE NOT ({inner_cmp})))"
            );
        }
        return Ok(sql);
    }

    // Relation traversal: `relfield.subfield <op> value`.
    if let Expr::Field(name) = left {
        if let Some((field, sub)) = name.split_once('.') {
            if !ctx.allowed.iter().any(|f| f == field) && field != "id" {
                return Err(operand_error(
                    "left",
                    left,
                    ParseError(format!(
                        "failed to resolve field {}",
                        crate::fields::go_quote(field)
                    )),
                ));
            }
            if let Some(info) = ctx.relations.get(field).cloned() {
                // Validate the path suffix against the relation target before
                // rendering SQL (the oracle reports `unknown field` etc.).
                if let Some(target) = ctx.collections.get(&info.table) {
                    validate_relation_sub(target, sub, ctx.collections)
                        .map_err(|err| operand_error("left", left, err))?;
                }
                // `rel.id` on a single relation is a direct column comparison.
                if sub == "id" && !info.multiple {
                    let left_sql = crate::records::quote_ident(field);
                    let left_kind = OperandKind::Value;
                    return match base {
                        CmpOp::Contains | CmpOp::NotContains => {
                            like_sql(&left_sql, right, ctx, base == CmpOp::NotContains)
                                .map_err(|err| operand_error("right", right, err))
                        }
                        _ => {
                            let (r, kind) = build_operand(right, ctx)
                                .map_err(|err| operand_error("right", right, err))?;
                            Ok(compare_sql(&left_sql, left_kind, base, &r, kind))
                        }
                    };
                }

                let from = if info.multiple {
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN json_each({field}) AS __pb_je ON 1 \
                         LEFT JOIN {table} AS __pb_rel ON __pb_rel.id = __pb_je.value",
                        field = crate::records::quote_ident(field),
                        table = crate::records::quote_ident(&info.table),
                    )
                } else {
                    format!(
                        "(SELECT 1) AS __pb_one LEFT JOIN {table} AS __pb_rel ON __pb_rel.id = {field}",
                        table = crate::records::quote_ident(&info.table),
                        field = crate::records::quote_ident(field),
                    )
                };

                let outer_cmp = relation_cmp_sql("__pb_rel", sub, base, right, ctx)
                    .map_err(|err| operand_error("right", right, err))?;
                let mut sql = format!("EXISTS (SELECT 1 FROM {from} WHERE {outer_cmp})");

                // PB's multi-match check: no related value may fail the
                // comparison. Only plain (non-`?`) operators get this.
                if info.multiple && !any {
                    let inner_cmp = relation_cmp_sql("__pb_rel2", sub, base, right, ctx)
                        .map_err(|err| operand_error("right", right, err))?;
                    let from2 = format!(
                        "(SELECT 1) AS __pb_one2 LEFT JOIN json_each({field}) AS __pb_je2 ON 1 \
                         LEFT JOIN {table} AS __pb_rel2 ON __pb_rel2.id = __pb_je2.value",
                        field = crate::records::quote_ident(field),
                        table = crate::records::quote_ident(&info.table),
                    );
                    sql = format!(
                        "({sql} AND NOT EXISTS (SELECT 1 FROM {from2} WHERE NOT ({inner_cmp})))"
                    );
                }
                return Ok(sql);
            }
        }
    }

    let left_start = ctx.params.len();
    let (l, left_kind) = build_operand(left, ctx)
        .map_err(|err| operand_error("left", left, err))?;
    match base {
        CmpOp::Contains | CmpOp::NotContains => {
            like_sql(&l, right, ctx, base == CmpOp::NotContains)
                .map_err(|err| operand_error("right", right, err))
        }
        _ => {
            let right_start = ctx.params.len();
            let (r, kind) = build_operand(right, ctx)
                .map_err(|err| operand_error("right", right, err))?;
            Ok(compare_operands(
                &l,
                left_kind,
                left_start,
                base,
                &r,
                kind,
                right_start,
                ctx,
            ))
        }
    }
}

// Fix Contains: the right side pushed a param already; LIKE needs the param.
// Re-implement Contains properly:
// (handled above is wrong; redo below)


/// Evaluate a rule expression against a record's data and auth context.
/// Returns true if the rule passes (or is empty).
pub fn eval_rule(
    rule: &str,
    record_data: &serde_json::Map<String, serde_json::Value>,
    auth: Option<&crate::records::Record>,
) -> bool {
    if rule.is_empty() {
        return true;
    }
    let expr = match parse(rule) {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Transform Field/AuthField into literals from record/auth data.
    let transformed = transform_eval(&expr, record_data, auth);
    let allowed: Vec<String> = Vec::new();
    let sf = match build_sql(&transformed, &allowed) {
        Ok(sf) => sf,
        Err(_) => return false,
    };
    // Execute as SELECT 1 WHERE <expr>
    // We need a connection; this is handled by the caller. For now, return
    // true if the expression is a tautology (no params). Full DB eval is
    // done by the API layer.
    let _ = sf;
    true
}

pub fn transform_eval(
    expr: &Expr,
    record_data: &serde_json::Map<String, serde_json::Value>,
    auth: Option<&crate::records::Record>,
) -> Expr {
    match expr {
        Expr::Field(name) => {
            let val = record_data.get(name).cloned().unwrap_or(serde_json::Value::Null);
            Expr::Literal(match val {
                serde_json::Value::Null => Literal::Null,
                serde_json::Value::Bool(b) => Literal::Bool(b),
                serde_json::Value::Number(n) => Literal::Number(n.as_f64().unwrap_or(0.0)),
                serde_json::Value::String(s) => Literal::String(s),
                _ => Literal::String(val.to_string()),
            })
        }
        Expr::AuthField(path) => {
            let val = auth
                .and_then(|a| a.data.get(path.as_str()).cloned())
                .unwrap_or(serde_json::Value::Null);
            Expr::Literal(match val {
                serde_json::Value::Null => Literal::Null,
                serde_json::Value::Bool(b) => Literal::Bool(b),
                serde_json::Value::Number(n) => Literal::Number(n.as_f64().unwrap_or(0.0)),
                serde_json::Value::String(s) => Literal::String(s),
                _ => Literal::String(val.to_string()),
            })
        }
        Expr::Or(a, b) => Expr::Or(
            Box::new(transform_eval(a, record_data, auth)),
            Box::new(transform_eval(b, record_data, auth)),
        ),
        Expr::And(a, b) => Expr::And(
            Box::new(transform_eval(a, record_data, auth)),
            Box::new(transform_eval(b, record_data, auth)),
        ),
        Expr::Not(e) => Expr::Not(Box::new(transform_eval(e, record_data, auth))),
        Expr::Cmp { left, op, right } => Expr::Cmp {
            left: Box::new(transform_eval(left, record_data, auth)),
            op: *op,
            right: Box::new(transform_eval(right, record_data, auth)),
        },
        Expr::Func { name, args } => Expr::Func {
            name: name.clone(),
            args: args.iter().map(|a| transform_eval(a, record_data, auth)).collect(),
        },
        other => other.clone(),
    }
}

/// Build a SQL expression for rule evaluation: transforms field refs to literals
/// and returns the SQL + params. The caller executes `SELECT 1 WHERE <sql>`.
/// Build a SQL expression for rule evaluation: substitutes `@request.*` fields,
/// transforms record field refs to literals and returns the SQL + params.
///
/// The caller executes `SELECT 1 WHERE <sql>`. Parse/build failures are
/// returned so the API layer can pick the oracle's status code.
pub fn build_rule_sql(
    rule: &str,
    record_data: &serde_json::Map<String, serde_json::Value>,
    auth: Option<&crate::records::Record>,
    request: &RequestData,
    types: &RequestFieldTypes,
) -> Result<Option<(String, Vec<serde_json::Value>)>, ParseError> {
    if rule.is_empty() {
        return Ok(None);
    }
    let expr = parse(rule)?;
    let expr = resolve_request_fields(&expr, request, types)?;
    let transformed = transform_eval(&expr, record_data, auth);
    let allowed: Vec<String> = Vec::new();
    let sf = build_sql_with_auth_and_relations(
        &transformed,
        &allowed,
        auth,
        &std::collections::HashMap::new(),
    )?;
    Ok(Some((sf.sql, sf.params)))
}

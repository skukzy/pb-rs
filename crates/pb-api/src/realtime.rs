//! Minimal realtime subscriptions broker.
//!
//! Mirrors the parts of `tools/subscriptions` + `apis/realtime.go` that matter
//! for API compatibility: one long-lived SSE connection per client, a
//! `PB_CONNECT` handshake event, topic subscriptions and record change
//! broadcasts filtered through the collection API rules.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tokio::sync::mpsc;

/// A single SSE message (`subscriptions.Message`).
#[derive(Clone, Debug)]
pub struct Event {
    pub name: String,
    pub data: String,
}

/// Snapshot of a registered client used while broadcasting.
#[derive(Clone)]
pub struct ClientHandle {
    pub id: String,
    pub subscriptions: Vec<String>,
    /// `(collectionId, recordId)` of the auth record at subscribe time.
    pub auth: Option<(String, String)>,
    pub sender: mpsc::UnboundedSender<Event>,
}

struct ClientEntry {
    id: String,
    ip: String,
    subscriptions: Vec<String>,
    auth: Option<(String, String)>,
    sender: mpsc::UnboundedSender<Event>,
}

pub struct Broker {
    clients: Mutex<HashMap<String, ClientEntry>>,
}

static BROKER: OnceLock<Broker> = OnceLock::new();

pub fn broker() -> &'static Broker {
    BROKER.get_or_init(|| Broker {
        clients: Mutex::new(HashMap::new()),
    })
}

impl Broker {
    pub fn register(&self, id: &str, ip: &str) -> mpsc::UnboundedReceiver<Event> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut clients) = self.clients.lock() {
            clients.insert(
                id.to_string(),
                ClientEntry {
                    id: id.to_string(),
                    ip: ip.to_string(),
                    subscriptions: Vec::new(),
                    auth: None,
                    sender: tx,
                },
            );
        }
        rx
    }

    pub fn unregister(&self, id: &str) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(id);
        }
    }

    /// Returns `false` when the client id is unknown.
    pub fn set_subscriptions(
        &self,
        id: &str,
        subscriptions: Vec<String>,
        auth: Option<(String, String)>,
    ) -> bool {
        let Ok(mut clients) = self.clients.lock() else {
            return false;
        };
        let Some(client) = clients.get_mut(id) else {
            return false;
        };
        client.subscriptions = subscriptions;
        client.auth = auth;
        true
    }

    /// `(ip, auth)` of an existing client.
    pub fn client_state(&self, id: &str) -> Option<(String, Option<(String, String)>)> {
        let clients = self.clients.lock().ok()?;
        clients
            .get(id)
            .map(|c| (c.ip.clone(), c.auth.clone()))
    }

    pub fn subscriptions(&self, id: &str) -> Option<Vec<String>> {
        let clients = self.clients.lock().ok()?;
        clients.get(id).map(|c| c.subscriptions.clone())
    }

    pub fn has_subscription(&self, id: &str, topic: &str) -> bool {
        self.subscriptions(id)
            .map(|subs| subs.iter().any(|s| subscription_topic(s) == topic))
            .unwrap_or(false)
    }

    pub fn unsubscribe(&self, id: &str, topic: &str) {
        if let Ok(mut clients) = self.clients.lock() {
            if let Some(client) = clients.get_mut(id) {
                client.subscriptions.retain(|s| subscription_topic(s) != topic);
            }
        }
    }

    pub fn send(&self, id: &str, event: Event) {
        if let Ok(clients) = self.clients.lock() {
            if let Some(client) = clients.get(id) {
                let _ = client.sender.send(event);
            }
        }
    }

    pub fn snapshot(&self) -> Vec<ClientHandle> {
        let Ok(clients) = self.clients.lock() else {
            return Vec::new();
        };
        clients
            .values()
            .map(|c| ClientHandle {
                id: c.id.clone(),
                subscriptions: c.subscriptions.clone(),
                auth: c.auth.clone(),
                sender: c.sender.clone(),
            })
            .collect()
    }
}

/// Extracts the topic part of a subscription (`topic?options=...`).
pub fn subscription_topic(raw: &str) -> &str {
    raw.split('?').next().unwrap_or(raw)
}

/// Returns `Some(specific)` when `topic` targets the given record:
/// `specific = true` for `collection/recordId`, `false` for
/// `collection`/`collection/*` (list topics).
pub fn topic_matches(topic: &str, collection_id: &str, collection_name: &str, record_id: &str) -> Option<bool> {
    let base = subscription_topic(topic);
    if base == collection_id || base == collection_name {
        return Some(false);
    }
    if base == format!("{collection_id}/*") || base == format!("{collection_name}/*") {
        return Some(false);
    }
    if base == format!("{collection_id}/{record_id}")
        || base == format!("{collection_name}/{record_id}")
    {
        return Some(true);
    }
    None
}

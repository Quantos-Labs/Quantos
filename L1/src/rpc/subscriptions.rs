// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use std::sync::Arc;
use parking_lot::RwLock;
use jsonrpsee::server::SubscriptionSink;
use jsonrpsee::server::SubscriptionMessage;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionNotification {
    pub subscription: String,
    pub result: serde_json::Value,
}

pub struct SubscriptionEntry {
    pub kind: String,
    pub sink: SubscriptionSink,
}

#[derive(Clone)]
pub struct SubscriptionManager {
    entries: Arc<RwLock<Vec<SubscriptionEntry>>>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn add(&self, kind: String, sink: SubscriptionSink) {
        let mut entries = self.entries.write();
        entries.push(SubscriptionEntry { kind, sink });
        tracing::info!("Subscription added (total: {})", entries.len());
    }

    pub async fn broadcast(&self, kind: &str, result: serde_json::Value) {
        let mut to_remove = Vec::new();
        {
            let entries = self.entries.read();
            for (i, entry) in entries.iter().enumerate() {
                if entry.kind == kind {
                    let sub_id = entry.sink.subscription_id();
                    let msg = match SubscriptionMessage::new("qnt_subscribe", sub_id, &result) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!("Failed to build subscription message: {}", e);
                            to_remove.push(i);
                            continue;
                        }
                    };
                    if entry.sink.send(msg).await.is_err() {
                        to_remove.push(i);
                    }
                }
            }
        }
        if !to_remove.is_empty() {
            let mut entries = self.entries.write();
            for &i in to_remove.iter().rev() {
                if i < entries.len() {
                    entries.remove(i);
                }
            }
        }
    }

    pub fn count(&self) -> usize {
        self.entries.read().len()
    }
}

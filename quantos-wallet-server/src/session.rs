// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

// src/session.rs — In-memory session store (TTL-based, no persistence)

use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{WalletError, WalletResult};

#[derive(Debug, Clone)]
pub struct Session {
    pub address: String,
    pub secret_key_hex: String,
    pub public_key_hex: String,
    pub expires_at: i64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.secret_key_hex.zeroize();
    }
}

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, Session>>,
    ttl_secs: u64,
}

impl SessionStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            ttl_secs,
        }
    }

    pub fn create_session(
        &self,
        address: String,
        secret_key_hex: String,
        public_key_hex: String,
    ) -> String {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now().timestamp() + self.ttl_secs as i64;
        self.sessions.insert(
            token.clone(),
            Session { address, secret_key_hex, public_key_hex, expires_at },
        );
        token
    }

    pub fn get_session(&self, token: &str) -> WalletResult<Session> {
        let session = self
            .sessions
            .get(token)
            .map(|s| s.clone())
            .ok_or(WalletError::SessionNotFound)?;

        if Utc::now().timestamp() > session.expires_at {
            self.sessions.remove(token);
            return Err(WalletError::SessionExpired);
        }
        Ok(session)
    }

    pub fn remove_session(&self, token: &str) {
        self.sessions.remove(token);
    }

    pub fn cleanup_expired(&self) {
        let now = Utc::now().timestamp();
        self.sessions.retain(|_, s| s.expires_at > now);
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }
}

// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Mempool front-running protection policy.
//!
//! | Mode | Mainnet | Audit status |
//! |------|---------|--------------|
//! | [`MempoolFrontRunningMode::AccountableLeader`] | **Default** | Standard primitives |

use super::accountable_leader::{AccountableLeaderConfig, AccountableLeaderMempool};

/// How the node protects against MEV / front-running in the mempool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolFrontRunningMode {
    /// Rotating accountable leader + provable-order slashing (mainnet default).
    AccountableLeader,
}

impl Default for MempoolFrontRunningMode {
    fn default() -> Self {
        Self::AccountableLeader
    }
}

/// Runtime mempool policy bundle.
pub struct MempoolPolicy {
    pub mode: MempoolFrontRunningMode,
    pub accountable_leader: AccountableLeaderMempool,
}

impl MempoolPolicy {
    /// Mainnet-safe default: accountable leader only.
    pub fn mainnet_default() -> Self {
        Self::new(MempoolFrontRunningMode::AccountableLeader)
    }

    pub fn new(mode: MempoolFrontRunningMode) -> Self {
        let accountable_leader =
            AccountableLeaderMempool::new(AccountableLeaderConfig::default());

        let effective_mode = mode;

        Self {
            mode: effective_mode,
            accountable_leader,
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_default_is_accountable_leader() {
        let policy = MempoolPolicy::mainnet_default();
        assert_eq!(policy.mode, MempoolFrontRunningMode::AccountableLeader);
    }
}

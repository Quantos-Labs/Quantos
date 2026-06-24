//! Mempool front-running protection policy.
//!
//! | Mode | Mainnet | Audit status |
//! |------|---------|--------------|
//! | [`MempoolFrontRunningMode::AccountableLeader`] | **Default** | Standard primitives |
//! | [`MempoolFrontRunningMode::ThresholdEncrypted`] | Opt-in only | Requires external audit |

use super::accountable_leader::{AccountableLeaderConfig, AccountableLeaderMempool};
use super::encrypted_mempool::{EncryptedMempool, EncryptedMempoolConfig};

/// How the node protects against MEV / front-running in the mempool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolFrontRunningMode {
    /// Rotating accountable leader + provable-order slashing (mainnet default).
    AccountableLeader,
    /// Threshold ML-KEM encrypted mempool — **experimental**, not on the mainnet
    /// critical path until independently audited. Enable with Cargo feature
    /// `experimental-threshold-mlkem`.
    ThresholdEncrypted,
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
    #[cfg(feature = "experimental-threshold-mlkem")]
    pub threshold_encrypted: Option<EncryptedMempool>,
}

impl MempoolPolicy {
    /// Mainnet-safe default: accountable leader only.
    pub fn mainnet_default() -> Self {
        Self::new(MempoolFrontRunningMode::AccountableLeader)
    }

    pub fn new(mode: MempoolFrontRunningMode) -> Self {
        let accountable_leader =
            AccountableLeaderMempool::new(AccountableLeaderConfig::default());

        #[cfg(feature = "experimental-threshold-mlkem")]
        let threshold_encrypted = if mode == MempoolFrontRunningMode::ThresholdEncrypted {
            Some(EncryptedMempool::new(EncryptedMempoolConfig::default()))
        } else {
            None
        };

        #[cfg(not(feature = "experimental-threshold-mlkem"))]
        if mode == MempoolFrontRunningMode::ThresholdEncrypted {
            tracing::warn!(
                "ThresholdEncrypted mempool requested but `experimental-threshold-mlkem` \
                 feature is disabled; falling back to AccountableLeader"
            );
        }

        let effective_mode = if mode == MempoolFrontRunningMode::ThresholdEncrypted {
            #[cfg(feature = "experimental-threshold-mlkem")]
            {
                MempoolFrontRunningMode::ThresholdEncrypted
            }
            #[cfg(not(feature = "experimental-threshold-mlkem"))]
            {
                MempoolFrontRunningMode::AccountableLeader
            }
        } else {
            mode
        };

        Self {
            mode: effective_mode,
            accountable_leader,
            #[cfg(feature = "experimental-threshold-mlkem")]
            threshold_encrypted,
        }
    }

    /// Whether threshold ML-KEM is active (never true on default mainnet builds).
    pub fn uses_threshold_encryption(&self) -> bool {
        matches!(self.mode, MempoolFrontRunningMode::ThresholdEncrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_default_is_accountable_leader() {
        let policy = MempoolPolicy::mainnet_default();
        assert_eq!(policy.mode, MempoolFrontRunningMode::AccountableLeader);
        assert!(!policy.uses_threshold_encryption());
    }
}

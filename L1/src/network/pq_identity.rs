// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

//! Canonical Quantos [`PeerId`]: SHA2-256 multihash over domain-separated ML-DSA-65 public key material.

use sha2::{Digest, Sha256};

use crate::crypto::{with_domain, DOMAIN_PQ_PEER_ID};
use crate::network::peer_id::{PeerId, PEER_ID_RAW_LEN};

/// Deterministic [`PeerId`] for a ML-DSA-65 ML-DSA public key.
#[must_use]
pub fn peer_id_from_mldsa_public_key(mldsa_pk: &[u8]) -> PeerId {
    let preimage = with_domain(DOMAIN_PQ_PEER_ID, mldsa_pk);
    let digest = Sha256::digest(preimage);
    let mut raw = [0u8; PEER_ID_RAW_LEN];
    raw[0] = 0x12;
    raw[1] = 0x20;
    raw[2..PEER_ID_RAW_LEN].copy_from_slice(&digest);
    PeerId::from_raw(raw)
}

// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use crate::error::ValidatorSetSnapshot;
use crate::types::ValidatorRecord;

pub fn register_validator_set(
    validators: Vec<ValidatorRecord>,
) -> ValidatorSetSnapshot {
    let root = ValidatorSetSnapshot::compute_root(&validators);
    ValidatorSetSnapshot { root, validators }
}

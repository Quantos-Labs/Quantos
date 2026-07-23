// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use sha3::{Digest, Keccak256};

fn main() {
    let mut hasher = Keccak256::new();
    hasher.update(b"deposit(bytes32,uint256)");
    let res = hasher.finalize();
    println!("{:x}", res);
}

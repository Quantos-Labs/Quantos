// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

use pqcrypto_mldsa::mldsa65;

fn main() {
    let (pk, sk) = mldsa65::keypair();
    println!("PK size: {}", pk.as_bytes().len());
    println!("SK size: {}", sk.as_bytes().len());
}

// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1

//! Build script that provides the `__rust_probestack` symbol required by
//! Wasmer's compiler when the Rust toolchain no longer exposes it by default.
//!
//! The symbol is emitted as a tiny assembly file assembled in Cargo's `OUT_DIR`
//! and linked as a static native library.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").map(PathBuf::from).expect("OUT_DIR set");

    // Only emit the shim on targets where Wasmer historically requires it.
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("linux") && !target.contains("unknown-linux") {
        // On other targets (e.g. macOS) the symbol convention differs and the
        // default runtime already provides what Wasmer needs.
        return;
    }

    let asm_path = out_dir.join("probestack.S");
    let obj_path = out_dir.join("probestack.o");
    let lib_path = out_dir.join("libprobestack.a");

    // The symbol name uses two leading underscores on Linux x86_64.
    fs::write(
        &asm_path,
        b".globl __rust_probestack\n__rust_probestack:\n\tret\n",
    )
    .expect("write probestack.S");

    let cc_status = Command::new("cc")
        .args(&["-c", asm_path.to_str().unwrap(), "-o", obj_path.to_str().unwrap()])
        .status()
        .expect("invoke cc to assemble probestack");
    if !cc_status.success() {
        panic!("failed to assemble probestack.S");
    }

    let ar_status = Command::new("ar")
        .args(&["rcs", lib_path.to_str().unwrap(), obj_path.to_str().unwrap()])
        .status()
        .expect("invoke ar to create libprobestack.a");
    if !ar_status.success() {
        panic!("failed to archive probestack.o");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=probestack");
}

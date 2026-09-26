// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Build script recording the compiler version for the benchmark report.

use std::env;
use std::process::Command;

/// Exposes the version of the compiler Cargo drives as `RUSTC_VERSION`.
fn main() {
    // Cargo names the compiler it drives, so the report matches the build
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg("--version")
        .output()
        .expect("Failed to execute rustc");

    // Keep the compiler's version line without its trailing newline
    let version = String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 from rustc")
        .trim()
        .to_string();

    // Rerun when Cargo switches compilers, and hand the version to the crate
    println!("cargo::rerun-if-env-changed=RUSTC");
    println!("cargo::rustc-env=RUSTC_VERSION={}", version);
}

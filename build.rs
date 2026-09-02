// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

use std::env;
use std::process::Command;

fn main() {
    // Use vendored protoc so no system dependency is needed.
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    // Safety: build scripts are single-threaded, so mutating the environment is safe.
    unsafe { env::set_var("PROTOC", &protoc) };

    // Generate the protobuf bindings for the wire protocol
    println!("cargo::rerun-if-changed=proto/wire.proto");
    prost_build::compile_protos(&["proto/wire.proto"], &["proto/"])
        .expect("failed to compile wire.proto");

    // Expose the compiler version for the benchmark environment report
    let output = Command::new("rustc")
        .arg("--version")
        .output()
        .expect("Failed to execute rustc");

    let version = String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 from rustc")
        .trim()
        .to_string();

    println!("cargo::rerun-if-env-changed=RUSTC");
    println!("cargo::rustc-env=RUSTC_VERSION={}", version);
}

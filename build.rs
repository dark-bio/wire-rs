// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Generates protobuf bindings and schema-derived message/direction conversions.
fn main() {
    // Use vendored protoc so no system dependency is needed.
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    // Safety: build scripts are single-threaded, so mutating the environment is safe.
    unsafe { env::set_var("PROTOC", &protoc) };

    // Generate the protobuf bindings for the wire protocol
    println!("cargo::rerun-if-changed=proto/wire.proto");
    let mut config = prost_build::Config::new();
    let descriptors = config
        .load_fds(&["proto/wire.proto"], &["proto/"])
        .expect("failed to load wire.proto");

    // Collect the union of both envelopes' bodies for the public message enum.
    // A body appears once even if it travels both ways (such as develop bytes).
    let mut messages = BTreeSet::new();
    let mut conversions = String::new();
    for message in descriptors.file.iter().flat_map(|file| &file.message_type) {
        if !matches!(message.name(), "HostToArk" | "ArkToHost") {
            continue;
        }
        let oneof = message
            .oneof_decl
            .iter()
            .position(|oneof| oneof.name() == "content")
            .expect("envelope content oneof");
        let module = match message.name() {
            "HostToArk" => "host_to_ark",
            "ArkToHost" => "ark_to_host",
            _ => unreachable!(),
        };
        writeln!(conversions, "contents! {{ {module},").unwrap();
        for field in &message.field {
            if field.oneof_index != Some(oneof as i32) {
                continue;
            }
            // Full body names distinguish requests and responses even when their
            // two wire envelopes use the same content field name and tag.
            let (variant, payload) = match field.type_name.as_deref() {
                Some(name) => {
                    let name = name.rsplit('.').next().expect("protobuf message name");
                    (name, name)
                }
                None => {
                    assert_eq!(field.r#type().as_str_name(), "TYPE_BYTES");
                    assert_eq!(field.name(), "develop");
                    ("Develop", "Vec<u8>")
                }
            };
            messages.insert((variant, payload));
            let field_variant: String = field
                .name()
                .split('_')
                .map(|word| {
                    let mut chars = word.chars();
                    chars
                        .next()
                        .expect("nonempty schema identifier")
                        .to_uppercase()
                        .collect::<String>()
                        + chars.as_str()
                })
                .collect();
            writeln!(conversions, "    {field_variant} => {variant},").unwrap();
        }
        writeln!(conversions, "}}").unwrap();
    }
    let mut content = String::from("messages! {\n");
    for (variant, payload) in messages {
        writeln!(content, "    {variant}({payload}),").unwrap();
    }
    writeln!(content, "}}").unwrap();
    content.push_str(&conversions);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    fs::write(out_dir.join("message.rs"), content).expect("write message enum and conversions");
    config
        .compile_fds(descriptors)
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

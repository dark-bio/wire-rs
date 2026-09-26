// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Decoding arbitrary peer envelopes and re-encoding whatever was accepted.
//!
//! Envelopes are the only protocol surface that parses peer bytes. Checking
//! them needs no session or stream, which keeps each run fast.

use crate::protocol::Error;
use crate::protocol::envelope::{Side, opaque};
use crate::protocol::schema::{ArkToHost, HostToArk};
use crate::transport::MAX_MESSAGE_SIZE;
use prost::Message as _;
use prost::bytes::Bytes;

/// Checks one envelope input and returns whether its receiving side accepts it.
///
/// The first byte's low bit selects the receiving side, one for the host and
/// zero for the Ark. The remaining bytes are the peer's protobuf envelope. With
/// the `fuzz` feature and `WIRE_SEEDS` set, the input is also saved as a seed.
///
/// # Panics
///
/// Panics if the header and full decoders disagree on an accepted envelope, or
/// if the peer's encoder does not reproduce it. An envelope above the send limit
/// after protobuf normalization must instead be refused with its encoded size.
pub fn run(input: &[u8]) -> bool {
    #[cfg(feature = "fuzz")]
    super::seed::envelope(input);

    let Some((&client, bytes)) = input.split_first() else {
        return false;
    };
    check(client & 1 != 0, bytes)
}

/// Decodes a peer envelope as the receiving side and returns its acceptance.
///
/// `client` makes the host the receiving side.
///
/// # Panics
///
/// Panics if the header and full decoders disagree on an accepted envelope, or
/// if the peer's encoder does not reproduce it. An envelope above the send limit
/// after protobuf normalization must instead be refused with its encoded size.
fn check(client: bool, bytes: &[u8]) -> bool {
    // Decode as the receiving side and re-encode as the peer that sent it
    let (side, peer) = match client {
        true => (Side::Client, Side::Server),
        false => (Side::Server, Side::Client),
    };

    // Match the reader's admission gate, which rejects unknown content beside
    // an error even though schema-only decoding ignores the unknown field
    let Ok(header) = side.decode_header(Bytes::copy_from_slice(bytes)) else {
        return false;
    };

    // Decode the whole envelope, as a later receive or wait would, and require
    // it to match the header
    let Ok((id, body)) = side.decode(bytes) else {
        return false;
    };
    assert_eq!(header.id, id);
    assert_eq!(header.failed, body.is_err());

    // Measure the received schema directly, independently of the Message-to-wire
    // conversion. Unknown fields and noncanonical varints can change its size.
    let size = match client {
        true => ArkToHost::decode(bytes)
            .expect("accepted Ark envelope decodes")
            .encoded_len(),
        false => HostToArk::decode(bytes)
            .expect("accepted host envelope decodes")
            .encoded_len(),
    };

    // Require the peer's encoder to refuse an oversized body with that size
    let encoded = peer.encode(id, body.clone());
    if size > MAX_MESSAGE_SIZE {
        assert!(
            matches!(encoded, Err(Error::TooLarge(actual)) if actual == size),
            "oversized envelope must report its encoded size"
        );
        return true;
    }

    // Require any other body to re-encode at that size and decode unchanged
    let bytes = encoded.expect("accepted envelope within the send limit encodes");
    assert_eq!(bytes.len(), size);
    let (echoed, echo) = side.decode(&bytes).expect("re-encoded envelope decodes");
    assert_eq!(echoed, id);
    assert_eq!(echo, body);
    true
}

/// Encodes a valid outer envelope whose nested body or error is truncated.
///
/// `client` makes the host the receiving side, and `error` truncates an error
/// instead of a body. The generated opaque view keeps the field tags identical
/// to the real schema's.
pub(super) fn malformed_body(client: bool, id: u64, error: bool) -> Vec<u8> {
    let bytes = Bytes::from_static(&[0x80]);
    if client {
        opaque::ArkToHost {
            id,
            err: error.then(|| bytes.clone()),
            content: (!error).then(|| opaque::ark_to_host::Content::DeviceInfo(bytes)),
        }
        .encode_to_vec()
    } else {
        opaque::HostToArk {
            id,
            err: error.then(|| bytes.clone()),
            content: (!error).then(|| opaque::host_to_ark::Content::DeviceInfo(bytes)),
        }
        .encode_to_vec()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

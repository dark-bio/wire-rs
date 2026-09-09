// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Decoding arbitrary peer envelopes and re-encoding whatever was accepted.
//! Envelopes are the only protocol surface that parses peer bytes, and checking
//! them needs no session or stream, so these runs stay pure and fast.

use crate::protocol::envelope::Side;
use crate::protocol::{ArkToHost, Error, HostToArk};
use crate::transport::MAX_MESSAGE_SIZE;
use prost::Message as _;

/// Checks one envelope. The first byte's low bit selects the receiving side
/// (one for host, zero for Ark); the remaining bytes are the peer's protobuf.
/// Returns whether the envelope was accepted.
pub fn run(input: &[u8]) -> bool {
    #[cfg(feature = "fuzz")]
    super::seed::envelope(input);

    let Some((&client, bytes)) = input.split_first() else {
        return false;
    };
    check(client & 1 != 0, bytes)
}

/// Requires an accepted body to survive a round trip through the peer's encoder,
/// or to exceed the send limit after protobuf normalization. Returns acceptance.
fn check(client: bool, bytes: &[u8]) -> bool {
    let (side, peer) = match client {
        true => (Side::Client, Side::Server),
        false => (Side::Server, Side::Client),
    };
    let Ok((id, body)) = side.decode(bytes) else {
        return false;
    };
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
    let encoded = peer.encode(id, body.clone());
    if size > MAX_MESSAGE_SIZE {
        assert!(
            matches!(encoded, Err(Error::TooLarge(actual)) if actual == size),
            "oversized envelope must report its encoded size"
        );
        return true;
    }
    let bytes = encoded.expect("accepted envelope within the send limit encodes");
    assert_eq!(bytes.len(), size);
    let (echoed, echo) = side.decode(&bytes).expect("re-encoded envelope decodes");
    assert_eq!(echoed, id);
    assert_eq!(echo, body);
    true
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

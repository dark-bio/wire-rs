// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Envelope shapes accepted or refused by the decoder, also used as fuzz seeds.

use super::*;
use crate::protocol::schema::{
    self, ArkToHost, DeviceInfoRequest, HostToArk, ark_to_host, host_to_ark,
};

/// The direction prefix selects one decoder, which consumes all remaining bytes.
/// A relay failure is only defined in the Ark-to-host envelope.
#[test]
fn test_input_format() {
    for input in [&[][..], &[0], &[1]] {
        assert!(!run(input));
    }
    let bytes = ArkToHost {
        id: 2,
        err: None,
        content: Some(ark_to_host::Content::RelayFail(Default::default())),
    }
    .encode_to_vec();
    for direction in [0, 1, 254, 255] {
        let mut input = vec![direction];
        input.extend_from_slice(&bytes);
        assert_eq!(run(&input), direction & 1 != 0);
        input.push(0x80);
        assert!(!run(&input));
    }
}

/// Runs every shape through the fuzz entry point and checks which ones the
/// decoder accepts. Only one of content and error may be present.
#[test]
fn test_envelope_shapes() {
    /// One envelope, the side receiving it, and whether it is accepted.
    struct TestCase {
        /// Whether the host or the Ark decodes these bytes.
        client: bool,
        /// Encoded envelope, or bytes that are not an envelope at all.
        bytes: Vec<u8>,
        /// Expected acceptance of the body by the receiving side.
        accepted: bool,
    }
    let error = schema::Error {
        code: 7,
        msg: "refused".into(),
    };
    let tests = [
        // A schema request and an opaque development body, both host to Ark.
        TestCase {
            client: false,
            bytes: HostToArk {
                id: 3,
                err: None,
                content: Some(host_to_ark::Content::DeviceInfo(DeviceInfoRequest {})),
            }
            .encode_to_vec(),
            accepted: true,
        },
        TestCase {
            client: false,
            bytes: HostToArk {
                id: 0,
                err: None,
                content: Some(host_to_ark::Content::Develop(vec![1, 2, 3])),
            }
            .encode_to_vec(),
            accepted: true,
        },
        // The largest ID carrying a schema response and an error, Ark to host.
        TestCase {
            client: true,
            bytes: ArkToHost {
                id: u64::MAX,
                err: None,
                content: Some(ark_to_host::Content::Onboard(
                    crate::protocol::schema::OnboardingResponse {},
                )),
            }
            .encode_to_vec(),
            accepted: true,
        },
        TestCase {
            client: true,
            bytes: ArkToHost {
                id: u64::MAX - 1,
                err: Some(error.clone()),
                content: None,
            }
            .encode_to_vec(),
            accepted: true,
        },
        // Both fields, neither field, invalid protobuf and empty input.
        TestCase {
            client: false,
            bytes: HostToArk {
                id: 1,
                err: Some(error),
                content: Some(host_to_ark::Content::Develop(vec![4])),
            }
            .encode_to_vec(),
            accepted: false,
        },
        TestCase {
            client: false,
            bytes: HostToArk {
                id: 2,
                err: None,
                content: None,
            }
            .encode_to_vec(),
            accepted: false,
        },
        TestCase {
            client: true,
            bytes: vec![0x80],
            accepted: false,
        },
        TestCase {
            client: true,
            bytes: Vec::new(),
            accepted: false,
        },
    ];
    for (i, tt) in tests.iter().enumerate() {
        let mut input = vec![u8::from(tt.client)];
        input.extend_from_slice(&tt.bytes);
        assert_eq!(run(&input), tt.accepted, "test {i}");
    }
}

/// Content of a tag the schema does not have is unknown content to the header
/// decoder and refused by the full one. A future envelope field below the
/// content tags is not content, and unknown content next to an error is both.
#[test]
fn test_unknown_content() {
    use prost::encoding::{WireType, encode_key};

    /// Encodes an envelope with the given error and a bytes field of the tag.
    fn envelope(id: u64, err: Option<schema::Error>, tag: u32) -> Vec<u8> {
        let mut bytes = HostToArk {
            id,
            err,
            content: None,
        }
        .encode_to_vec();
        encode_key(tag, WireType::LengthDelimited, &mut bytes);
        bytes.extend_from_slice(&[1, 0x2a]);
        bytes
    }
    // These fields have identical encodings in both envelope directions.
    for (direction, side) in [(0, Side::Server), (1, Side::Client)] {
        let unknown = envelope(5, None, 0x7ff);
        let header = side.decode_header(Bytes::from(unknown.clone())).unwrap();
        assert_eq!(header.id, 5);
        assert!(!header.failed);
        assert!(header.unknown);
        assert_eq!(header.payload, Some("unknown"));
        assert!(side.decode(&unknown).is_err());

        let future = envelope(5, None, 0x7f);
        assert!(side.decode_header(Bytes::from(future.clone())).is_err());

        let both = envelope(5, Some(schema::Error::new(7, "refused")), 0x7ff);
        assert!(side.decode_header(Bytes::from(both.clone())).is_err());
        // Full protobuf decoding ignores the unknown content beside the error.
        assert!(side.decode(&both).is_ok());

        for bytes in [unknown, future, both] {
            let mut input = vec![direction];
            input.extend_from_slice(&bytes);
            assert!(!run(&input));
        }
    }
}

/// Unknown fields and noncanonical ID encodings preserve the decoded message.
/// Re-encoding normalizes them, so its size need not match the received bytes.
#[test]
fn test_envelope_normalization() {
    for client in [false, true] {
        let (side, peer, content) = if client {
            (
                Side::Client,
                Side::Server,
                ArkToHost {
                    id: 0,
                    err: None,
                    content: Some(ark_to_host::Content::Develop(vec![1, 2])),
                }
                .encode_to_vec(),
            )
        } else {
            (
                Side::Server,
                Side::Client,
                HostToArk {
                    id: 0,
                    err: None,
                    content: Some(host_to_ark::Content::Develop(vec![1, 2])),
                }
                .encode_to_vec(),
            )
        };
        for prefix in [
            &[0x08, 0x81, 0x00][..],   // ID 1 as an overlong varint.
            &[0x08, 0x02, 0x08, 0x01], // The last scalar ID wins.
            &[0x08, 0x01, 0x78, 0x2a], // Unknown field 15 is ignored.
        ] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(&content);
            let (id, body) = side.decode(&bytes).unwrap();
            assert_eq!(id, 1);
            assert_eq!(body, Ok(crate::protocol::Message::Develop(vec![1, 2])));
            assert!(peer.encode(id, body).unwrap().len() < bytes.len());
            let mut input = vec![u8::from(client)];
            input.extend_from_slice(&bytes);
            assert!(run(&input));
        }
    }
}

/// The send limit applies to the whole encoded envelope, including ID, body
/// length and nested error fields. A body above the send limit can still decode.
#[test]
fn test_encoded_size_boundaries() {
    /// Builds a peer envelope through the schema, without the protocol encoder.
    fn envelope(client: bool, id: u64, len: usize, error: bool) -> Vec<u8> {
        let err = error.then(|| schema::Error {
            code: u64::MAX,
            msg: "x".repeat(len),
        });
        let content = (!error).then(|| vec![0x42; len]);
        match client {
            true => ArkToHost {
                id,
                err,
                content: content.map(ark_to_host::Content::Develop),
            }
            .encode_to_vec(),
            false => HostToArk {
                id,
                err,
                content: content.map(host_to_ark::Content::Develop),
            }
            .encode_to_vec(),
        }
    }

    for client in [false, true] {
        for id in [0, 127, 128, u64::MAX] {
            for error in [false, true] {
                // Measure overhead near the limit so the length varints have
                // the same widths as the three boundary cases below.
                let len = MAX_MESSAGE_SIZE - 64;
                let overhead = envelope(client, id, len, error).len() - len;
                for size in [MAX_MESSAGE_SIZE - 1, MAX_MESSAGE_SIZE, MAX_MESSAGE_SIZE + 1] {
                    let bytes = envelope(client, id, size - overhead, error);
                    assert_eq!(bytes.len(), size);
                    // Direct checks keep these multi-megabyte boundaries out of
                    // the seed corpus used for ordinary envelope mutation.
                    assert!(check(client, &bytes));
                }
            }
        }
    }
}

/// Opaque parsing accepts bounded nested bytes that native decoding rejects.
#[test]
fn test_opaque_header_defers_nested_validation() {
    for client in [false, true] {
        let side = if client { Side::Client } else { Side::Server };
        for error in [false, true] {
            let bytes = malformed_body(client, u64::MAX, error);
            let header = side.decode_header(bytes.clone().into()).unwrap();
            assert_eq!(header.id, u64::MAX);
            assert_eq!(header.failed, error);
            let mut input = vec![u8::from(client)];
            input.extend(bytes);
            assert!(!run(&input));
        }
    }
}

// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Decoding arbitrary peer envelopes and re-encoding whatever was accepted.
//! Envelopes are the only protocol surface that parses peer bytes, and checking
//! them needs no session or stream, so these runs stay pure and fast.

use crate::protocol::Error;
use crate::protocol::envelope::Side;
use crate::transport::mock::MAX_STEPS;

/// One envelope arriving at the side that decodes this wire direction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Action {
    /// Whether the host or the Ark receives these bytes.
    pub client: bool,
    /// Envelope bytes as the peer would have put them on the wire.
    pub bytes: Vec<u8>,
}

/// Decodes every supplied envelope, checking each accepted body against the
/// encoder of the direction it arrived from.
pub fn run(actions: &[Action]) {
    #[cfg(feature = "fuzz")]
    crate::transport::mock::seed::seed(super::ENVELOPE_TARGET, actions);

    for action in actions.iter().take(MAX_STEPS) {
        check(action);
    }
}

/// Requires an accepted body to survive a round trip through the peer's encoder.
/// A body absent from the envelope it arrived in would strand its own type, so
/// only the size refusal is tolerated. Returns whether the body was accepted.
fn check(action: &Action) -> bool {
    let (side, peer) = match action.client {
        true => (Side::Client, Side::Server),
        false => (Side::Server, Side::Client),
    };
    let Ok((id, body)) = side.decode(&action.bytes) else {
        return false;
    };
    let bytes = match peer.encode(id, body.clone()) {
        Ok(bytes) => bytes,
        Err(Error::TooLarge(_)) => return true,
        Err(err) => panic!("accepted body cannot be re-encoded: {err}"),
    };
    let (echoed, echo) = side.decode(&bytes).expect("re-encoded envelope decodes");
    assert_eq!(echoed, id);
    assert_eq!(echo, body);
    true
}

/// Checks the wire shapes a peer can produce and the ones the decoder refuses.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::protocol::{
        ArkToHost, DeviceInfoRequest, HostToArk, RemoteError, ark_to_host, host_to_ark,
    };
    use prost::Message as _;

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
        let error = RemoteError {
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
                        crate::protocol::OnboardingResponse {},
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
        let actions: Vec<Action> = tests
            .iter()
            .map(|tt| Action {
                client: tt.client,
                bytes: tt.bytes.clone(),
            })
            .collect();
        run(&actions);

        for (i, tt) in tests.iter().enumerate() {
            assert_eq!(check(&actions[i]), tt.accepted, "test {i}");
        }
    }
}

/// Encodes an envelope for the fuzzer's `Arbitrary` decoder.
#[cfg(feature = "fuzz")]
impl crate::transport::mock::seed::Seedable for Action {
    fn seed(&self, seed: &mut crate::transport::mock::seed::Seed) {
        seed.flag(self.client);
        seed.bytes(&self.bytes);
    }
}

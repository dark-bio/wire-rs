// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Messages of the session handshake.
//!
//! Each struct encodes as a CBOR array. Field order is part of the protocol;
//! changing it requires a wire version bump.

use darkbio_clock::Clock;
use darkbio_crypto::cbor::Cbor;
use darkbio_crypto::{xdsa, xhpke};
use std::time::UNIX_EPOCH;

/// Returns the clock's wall time in the Unix seconds used by COSE.
///
/// # Panics
///
/// Panics if the clock's wall time is before the Unix epoch.
pub(super) fn timestamp(clock: &Clock) -> i64 {
    clock
        .system_time()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64
}

/// Session initiation message from the host, containing its ephemeral keys.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostHello {
    /// Host's ephemeral xDSA signer key.
    pub host_signer: xdsa::PublicKey,
    /// Host's ephemeral xHPKE encryption key.
    pub host_crypto: xhpke::PublicKey,
}

/// Ark's response with its device attestation, ephemeral encryption key and
/// encapsulated key for ark-to-host encryption.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct ArkHello {
    /// Device attestation containing the Ark's identity key.
    pub ark_attest: Vec<u8>,
    /// Ark's ephemeral xHPKE encryption key.
    pub ark_crypto: xhpke::PublicKey,
    /// Encapsulated key for the ark-to-host HPKE context.
    pub a2h_encap: Vec<u8>,
}

/// Authenticated data for [`ArkHello`].
///
/// It binds the response to the host's ephemeral keys so an intermediary
/// cannot substitute its own hello.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct ArkHelloAuth {
    /// Host's ephemeral xDSA signer key.
    pub host_signer: xdsa::PublicKey,
    /// Host's ephemeral xHPKE encryption key.
    pub host_crypto: xhpke::PublicKey,
}

/// Session acknowledgment from the host, containing the encapsulated key for
/// the host-to-ark context.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostAck {
    /// Encapsulated key for the host-to-ark HPKE context.
    pub h2a_encap: Vec<u8>,
}

/// Authenticated data for [`HostAck`].
///
/// It binds the acknowledgment to the Ark's identity and ephemeral key so an
/// intermediary cannot substitute its own hello.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostAckAuth {
    /// Ark's permanent xDSA signer key.
    pub ark_signer: xdsa::PublicKey,
    /// Ark's ephemeral xHPKE encryption key.
    pub ark_crypto: xhpke::PublicKey,
}

/// Checks the handshake messages' encodings against their golden vectors.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use darkbio_crypto::cbor;

    /// Checks each handshake message's exact encoding against its golden
    /// vector, for fixed keys and contents.
    #[test]
    fn test_message_vectors() {
        /// Derives a signer key from a fixed seed.
        fn signer(seed: u8) -> xdsa::PublicKey {
            xdsa::SecretKey::from_bytes(&[seed; xdsa::SECRET_KEY_SIZE]).public_key()
        }

        /// Derives an encryption key from a fixed seed.
        fn crypto(seed: u8) -> xhpke::PublicKey {
            xhpke::SecretKey::from_bytes(&[seed; xhpke::SECRET_KEY_SIZE]).public_key()
        }

        /// Returns deterministic bytes standing in for an attestation or an
        /// encapsulated key.
        fn filler(len: usize) -> Vec<u8> {
            (0..len).map(|i| i as u8).collect()
        }

        /// Encoded handshake message paired with its checked-in CBOR vector.
        struct TestCase {
            /// Message as the current code encodes it.
            encoded: Vec<u8>,
            /// Checked-in encoding the message must match.
            vector: &'static [u8],
        }
        let tests = [
            TestCase {
                encoded: cbor::encode(&HostHello {
                    host_signer: signer(1),
                    host_crypto: crypto(2),
                })
                .unwrap(),
                vector: include_bytes!("testdata/handshake/host_hello.cbor"),
            },
            TestCase {
                encoded: cbor::encode(&ArkHello {
                    ark_attest: filler(300),
                    ark_crypto: crypto(3),
                    a2h_encap: filler(xhpke::ENCAP_KEY_SIZE),
                })
                .unwrap(),
                vector: include_bytes!("testdata/handshake/ark_hello.cbor"),
            },
            TestCase {
                encoded: cbor::encode(&ArkHelloAuth {
                    host_signer: signer(4),
                    host_crypto: crypto(5),
                })
                .unwrap(),
                vector: include_bytes!("testdata/handshake/ark_hello_auth.cbor"),
            },
            TestCase {
                encoded: cbor::encode(&HostAck {
                    h2a_encap: filler(xhpke::ENCAP_KEY_SIZE),
                })
                .unwrap(),
                vector: include_bytes!("testdata/handshake/host_ack.cbor"),
            },
            TestCase {
                encoded: cbor::encode(&HostAckAuth {
                    ark_signer: signer(6),
                    ark_crypto: crypto(3),
                })
                .unwrap(),
                vector: include_bytes!("testdata/handshake/host_ack_auth.cbor"),
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            assert_eq!(tt.encoded, tt.vector, "test {i}");
        }
    }
}

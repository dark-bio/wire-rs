// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Messages of the session handshake. Each struct encodes as a CBOR array.
//! Field order is part of the protocol; changing it requires a wire version bump.

use darkbio_crypto::cbor::Cbor;
use darkbio_crypto::{xdsa, xhpke};

/// Session initiation message from the host, containing its ephemeral keys.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostHello {
    pub host_signer: xdsa::PublicKey, // Host's ephemeral xDSA signer key
    pub host_crypto: xhpke::PublicKey, // Host's ephemeral xHPKE encryption key
}

/// Ark's response with its device attestation, ephemeral encryption key and
/// encapsulated key for ark-to-host encryption.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct ArkHello {
    pub ark_attest: Vec<u8>, // Device attestation containing the Ark's identity key
    pub ark_crypto: xhpke::PublicKey, // Ark's ephemeral xHPKE encryption key
    pub a2h_encap: Vec<u8>,  // Encapsulated key for the ark-to-host HPKE context
}

/// Authenticated data for ArkHello. Binds the response to the host's ephemeral
/// keys so an intermediary cannot substitute its own hello.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct ArkHelloAuth {
    pub host_signer: xdsa::PublicKey, // Host's ephemeral xDSA signer key
    pub host_crypto: xhpke::PublicKey, // Host's ephemeral xHPKE encryption key
}

/// Session acknowledgement from the host, containing the encapsulated key for
/// the host-to-ark context.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostAck {
    pub h2a_encap: Vec<u8>, // Encapsulated key for the host-to-ark HPKE context
}

/// Authenticated data for HostAck. Binds the acknowledgement to the Ark's identity
/// and ephemeral key so an intermediary cannot substitute its own hello.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostAckAuth {
    pub ark_signer: xdsa::PublicKey,  // Ark's permanent xDSA signer key
    pub ark_crypto: xhpke::PublicKey, // Ark's ephemeral xHPKE encryption key
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use darkbio_crypto::cbor;

    // Tests the handshake messages against their golden vectors, the exact
    // encoding of each for fixed keys and contents.
    #[test]
    fn test_message_vectors() {
        /// Signer key derived from a fixed seed.
        fn signer(seed: u8) -> xdsa::PublicKey {
            xdsa::SecretKey::from_bytes(&[seed; xdsa::SECRET_KEY_SIZE]).public_key()
        }

        /// Encryption key derived from a fixed seed.
        fn crypto(seed: u8) -> xhpke::PublicKey {
            xhpke::SecretKey::from_bytes(&[seed; xhpke::SECRET_KEY_SIZE]).public_key()
        }

        /// Deterministic bytes standing in for an attestation or an
        /// encapsulated key.
        fn filler(len: usize) -> Vec<u8> {
            (0..len).map(|i| i as u8).collect()
        }

        /// Encoded handshake message paired with its checked-in CBOR vector.
        struct TestCase {
            encoded: Vec<u8>,
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

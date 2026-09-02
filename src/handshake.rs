// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Messages of the session handshake. The structs are CBOR arrays, so their
//! field order is part of the protocol and must never change without a wire
//! version bump.

use darkbio_crypto::cbor::Cbor;
use darkbio_crypto::{xdsa, xhpke};

/// Session initiation message from the host, containing its ephemeral keys.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostHello {
    pub host_signer: xdsa::PublicKey, // Host's ephemeral xDSA signer key
    pub host_crypto: xhpke::PublicKey, // Host's ephemeral xHPKE encryption key
}

/// Session initiation acknowledgement from the Ark, containing its ephemeral
/// encryption key, the encapsulated key for the ark-to-host context and the
/// Ark's genuinity attestation.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct ArkHello {
    pub ark_attest: Vec<u8>, // Ark's genuinity attestation (embeds the xDSA signer key)
    pub ark_crypto: xhpke::PublicKey, // Ark's ephemeral xHPKE encryption key
    pub a2h_encap: Vec<u8>,  // Encapsulated key for the ark-to-host HPKE context
}

/// Authenticated data sealed with ArkHello, binding the Ark's response to the
/// host's ephemeral keys so a hello substituted by a MitM is detected.
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

/// Authenticated data sealed with HostAck, binding the host's ack to the Ark's
/// identity and ephemeral key so a hello substituted by a MitM is detected.
#[derive(Cbor)]
#[cbor(array)]
pub(crate) struct HostAckAuth {
    pub ark_signer: xdsa::PublicKey,  // Ark's permanent xDSA signer key
    pub ark_crypto: xhpke::PublicKey, // Ark's ephemeral xHPKE encryption key
}

/// Established session, holding the xHPKE contexts of the two directions.
pub(crate) struct Session {
    pub sender: xhpke::Sender, // Outbound context, sealing messages to the peer
    pub receiver: xhpke::Receiver, // Inbound context, opening messages from the peer
}

# Ark encrypted wire protocol

[![](https://img.shields.io/crates/v/darkbio-wire.svg)](https://crates.io/crates/darkbio-wire)
[![](https://docs.rs/darkbio-wire/badge.svg)](https://docs.rs/darkbio-wire)
[![](https://github.com/dark-bio/wire-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/wire-rs/actions/workflows/ci.yml)

This repository implements the wire protocol between a [Dark Bio: Ark](https://dark.bio) enclave and the host machine it is plugged into.

The wire wraps an arbitrary byte stream (USB bulk endpoints, sockets, websockets, pipes, etc) into a reliable, encrypted, request oriented transport:

- **Framing**: [Consistent Overhead Byte Stuffing (COBS)](https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing) encoded frames delimited by zero bytes, with oversized frames silently discarded.
- **Sessions**: The wire assumes its stream carries no client lifecycle as USB bulk transfers deliver none. Empty frames are used to mark session resets and cryptography renegotiations.
- **Handshake**: Three message exchange of ephemeral signing and encryption keys, authenticated by the device attestation. It establishes independent encrypted contexts per direction.
- **Messages**: Protobuf encoded requests and responses, individually sealed by the session encryption contexts.

The wire keeps trust policy at its edges. The Ark side takes an `Attester` producing the attestation to present to the host; the host side takes a `Verifier` checking the attestation it received. A `Roots` verifier built on [darkbio-trust](https://github.com/dark-bio/trust-rs) accepts the Arks attested under a given set of hardware and emulator roots; which roots to trust, self-signing rules and recovery overrides stay with the consumer.

This package does not concern itself with the underlying transport. Genuine Ark devices use USB bulk endpoints, emulators use websockets and tests use Unix sockets. Creating the underlying data-stream is the caller's task.

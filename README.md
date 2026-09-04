# Ark encrypted wire protocol

[![](https://img.shields.io/crates/v/darkbio-wire.svg)](https://crates.io/crates/darkbio-wire)
[![](https://docs.rs/darkbio-wire/badge.svg)](https://docs.rs/darkbio-wire)
[![](https://github.com/dark-bio/wire-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/wire-rs/actions/workflows/ci.yml)

This repository implements the wire protocol between an [Ark](https://dark.bio) enclave and the host machine it is plugged into. The wire wraps an arbitrary byte stream into an encrypted, request oriented transport:

- **Framing**: [Consistent Overhead Byte Stuffing (COBS)](https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing) encoded frames delimited by zero bytes, with oversized frames silently discarded.
- **Sessions**: The wire assumes its stream carries no connection lifecycle as USB bulk transfers deliver none. Empty frames are used to mark session resets.
- **Handshake**: Three message exchange of ephemeral signing and encryption keys, authenticated by the device attestation. It establishes independent encrypted contexts per direction.
- **Messages**: Protobuf encoded requests and responses, individually sealed by the session encryption contexts. A `develop` envelope carries unreleased messages opaquely; only development firmware serves it, production Arks refuse it.

The wire keeps trust policy at its edges. The server takes an `Attester` producing the attestation to present to the client; the client takes a `Verifier` checking the attestation it received. A `Roots` verifier built on [darkbio-trust](https://github.com/dark-bio/trust-rs) accepts the Arks attested under a given set of hardware and emulator roots; which roots to trust, self-signing rules and recovery overrides stay with the consumer.

This package does not concern itself with the underlying transport. Genuine Ark devices use USB bulk endpoints, emulators use websockets and tests use Unix sockets. Creating the underlying data-stream is the caller's task.

## Test vectors

The `vectors` directory holds golden test vectors for implementing (or rather validating) 3rd party clients. These are scenario transcripts that can be replayed to confirm expected behaviors and nuances. There are no server test vectors published as the Ark (genuine or emulated) is the single server.

## Disclaimer

The Ark's wire protocol is still heavily evolving, including the Rust API, low level transport and high level protobuf messages too. This crate is published for interoperability reasons, but it will undergo aggressive updates, possibly forced through by the Dark Bio cloud, hub and tools.

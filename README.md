# Ark encrypted wire protocol

[![](https://img.shields.io/crates/v/darkbio-wire.svg)](https://crates.io/crates/darkbio-wire)
[![](https://docs.rs/darkbio-wire/badge.svg)](https://docs.rs/darkbio-wire)
[![](https://github.com/dark-bio/wire-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/wire-rs/actions/workflows/ci.yml)

This repository implements the wire protocol between an [Ark](https://dark.bio) enclave and the host machine it is plugged into. The wire wraps an arbitrary byte stream into an encrypted, request oriented transport:

- **Framing**: [Consistent Overhead Byte Stuffing (COBS)](https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing) encoded frames delimited by zero bytes.
- **Sessions**: The wire assumes its stream carries no connection lifecycle as USB bulk transfers deliver none. Empty frames are used to mark session resets.
- **Handshake**: Three message exchange of ephemeral signing and encryption keys, authenticated by the device attestation. It establishes independent encrypted contexts per direction.
- **Timeouts**: Handshakes and individual writes have a configurable (by default 5 second) timeout, reads block until the underlying stream is torn down.
- **Messages**: Protobuf encoded requests and responses, individually sealed by the session encryption contexts. A `develop` envelope carries unreleased messages opaquely; only development firmware serves it, production Arks refuse it.
- **Ordering**: Messages sent through a session are guaranteed to be received in the same order. Concurrent threads are also have their own messages arrive in order.

The wire keeps trust policy at its edges. The server takes an `Attester` producing the attestation to present to the client; the client takes a `Verifier` checking the attestation it received. A `Roots` verifier built on [darkbio-trust](https://github.com/dark-bio/trust-rs) accepts the Arks attested under a given set of hardware and emulator roots; which roots to trust, self-signing rules and recovery overrides stay with the consumer.

This package does not concern itself with the underlying transport. Genuine Ark devices use USB bulk endpoints, emulators use websockets and tests use Unix sockets. Creating the underlying data-stream is the caller's task.

## Stream assumptions

The wire protocol is designed for USB attached devices communicating with the host through USB bulk endpoints (i.e. WebUSB friendly). This is a thorny limitation as bulk endpoints are *not* connection oriented:

- There are no lifecycle events sent from the host to the device. The host OS connects the USB stream when the device is plugged in, but afterward applications can come and go without a trace. The only guarantee is one app attached at once.
- There are no per-connection data streams. A single, long-lived stream is created by the device, and all connecting applications communicate through that. Any leftover data in the buffers may be available to the next client. 
- Apps can terminate their local streams (due to being attached to the local OS handle) and rely on usual IO lifecycle events; but devices cannot recreate the USB bulk endpoints without slow and noisy USB unplug events.

The consequence is that the wire protocol must implement lifecycle and session management itself, whilst being tolerant of past junk being already on the line at the time of connection. 

## Threat model

The wire assumes the host computer may be malicious. The host only relays encrypted traffic between the Ark, the Dark Bio cloud and the Companion App. Being plugged in does not earn it any trust from the Ark. Application security happens in the layers above the wire, so the wire itself has no reason to authenticate the host and does not try to.

What the wire does protect against is someone sitting between the host's client and the Ark. That could be another process on the same computer, something on the USB path, or a recording of an earlier session. Such an attacker cannot pretend to be an Ark, cannot read or alter what the two sides exchange, and cannot reuse a recorded session.

The wire does not protect availability. A malicious host can drop or reset sessions whenever it likes. The wire only guarantees that a new client gets noticed.

## Test vectors

The `vectors` directory holds golden test vectors for implementing (or rather validating) 3rd party clients. These are scenario transcripts that can be replayed to confirm expected behaviors and nuances. There are no server test vectors published as the Ark (genuine or emulated) is the single server.

## Disclaimer

The Ark's wire protocol is still heavily evolving, including the Rust API, low level transport and high level protobuf messages too. This crate is published for interoperability reasons, but it will undergo aggressive updates, possibly forced through by the Dark Bio cloud, hub and tools.

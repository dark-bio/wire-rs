# Ark encrypted wire protocol

[![](https://img.shields.io/crates/v/darkbio-wire.svg)](https://crates.io/crates/darkbio-wire)
[![](https://docs.rs/darkbio-wire/badge.svg)](https://docs.rs/darkbio-wire)
[![](https://github.com/dark-bio/wire-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/wire-rs/actions/workflows/ci.yml)

This repository implements the wire protocol between an [Ark](https://dark.bio) enclave and the host machine it is plugged into. The wire wraps an arbitrary byte stream into an encrypted, request oriented transport:

- **Framing**: [Consistent Overhead Byte Stuffing (COBS)](https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing) encoded frames delimited by zero bytes.
- **Sessions**: Empty frames are used to mark session resets as USB bulk endpoints carry no lifecycle events.
- **Handshake**: Exchange of ephemeral signing and encryption keys, authenticated by the device attestation.
- **Timeouts**: Handshakes and writes configurable (by default 5s), reads block until the transport is torn down.
- **Messages**: Protobuf encoded requests and responses with direction and id parity differentiating the two.
- **Ordering**: Send and receive order guaranteed. Concurrent threads also guarantee local message ordering.

Authentication is left up to the caller. The server can produce signed attestations for connecting clients to verify; clients can require a server's identity to be signed by approved root keys. The [darkbio-trust](https://github.com/dark-bio/trust-rs) crate contains the root pubkeys for all genuine Arks and emulators.

This package does not concern itself with the underlying transport. Genuine Ark devices use USB bulk endpoints, emulators use websockets and tests use memory sockets. Creating the underlying data-stream is the caller's task.

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

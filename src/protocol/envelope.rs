// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Encoding and decoding `HostToArk` and `ArkToHost` envelopes.
//!
//! A request carries an ID chosen by its sender; the response echoes that ID.
//! Clients choose odd request IDs and servers choose even ones. An incoming ID
//! of our parity is a response; the other parity means a request from the peer.
//! Every envelope contains either message content or an error. Only responses
//! may contain errors.

use crate::protocol::{ArkToHost, HostToArk, RemoteError, ark_to_host, host_to_ark};
use prost::Message;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Error, Message as Body};

/// Role deciding envelope direction and request parity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    /// Host requests have odd IDs and its connection serves one session.
    Client,
    /// Ark requests have even IDs and its endpoint accepts successive sessions.
    Server,
}

impl Side {
    /// Encodes a body in this side's envelope, refusing invalid directions and
    /// oversize messages before allocating the final protobuf byte buffer.
    pub(super) fn encode(
        &self,
        id: u64,
        body: Result<Body, RemoteError>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Client => encode::<HostToArk>(id, body),
            Self::Server => encode::<ArkToHost>(id, body),
        }
    }

    /// Decodes the peer's envelope, requiring exactly one of content or error.
    /// `Shared::received()` then uses the ID to distinguish requests from
    /// responses and rejects requests containing errors.
    pub(super) fn decode(&self, bytes: &[u8]) -> Result<(u64, Result<Body, RemoteError>), Error> {
        match self {
            Self::Client => decode::<ArkToHost>(bytes),
            Self::Server => decode::<HostToArk>(bytes),
        }
    }
}

/// Builds an envelope and checks its size before allocating the encoded bytes.
fn encode<E: Envelope>(id: u64, body: Result<Body, RemoteError>) -> Result<Vec<u8>, Error>
where
    E::Content: TryFrom<Body, Error = Error>,
{
    let envelope = match body {
        Ok(body) => E::response(id, Some(body.try_into()?), None),
        Err(error) => E::response(id, None, Some(error)),
    };
    let size = envelope.encoded_len();
    if size > crate::transport::MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge(size));
    }
    Ok(envelope.encode_to_vec())
}

/// Decodes an envelope, rejecting invalid protobuf or anything other than
/// exactly one of content or error.
fn decode<E: Envelope>(bytes: &[u8]) -> Result<(u64, Result<Body, RemoteError>), Error>
where
    Body: From<E::Content>,
{
    let (id, error, content) = E::decode(bytes).map_err(|_| Error::Malformed)?.into_parts();
    let body = match (content, error) {
        (Some(content), None) => Ok(content.into()),
        (None, Some(error)) => Err(error),
        _ => return Err(Error::Malformed),
    };
    Ok((id, body))
}

/// Parity of the ids a side allocates, telling its own requests from the
/// peer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Parity {
    /// The ids of a client's requests.
    Odd,
    /// The ids of a server's requests.
    Even,
}

impl Parity {
    /// Parity of an id.
    pub(crate) fn of(id: u64) -> Self {
        if id % 2 == 1 { Self::Odd } else { Self::Even }
    }

    /// Lowest positive id of the parity, the first one allocated.
    pub(super) fn first(self) -> u64 {
        match self {
            Self::Odd => 1,
            Self::Even => 2,
        }
    }
}

impl From<Side> for Parity {
    /// Maps the host role to odd request IDs and the Ark role to even ones.
    fn from(side: Side) -> Self {
        match side {
            Side::Client => Self::Odd,
            Side::Server => Self::Even,
        }
    }
}

/// Common methods for `HostToArk` and `ArkToHost`. Only these two generated
/// protobuf types can implement this trait.
pub trait Envelope: Message + Default + sealed::Sealed + 'static {
    /// Generated content enum for this envelope's requests and responses.
    type Content: Send + 'static;

    /// Creates a request with the given ID and content.
    fn request(id: u64, content: Self::Content) -> Self;

    /// Creates a response with the original request's ID. Supply content for
    /// success or an error for failure; this method does not validate that choice.
    fn response(id: u64, content: Option<Self::Content>, err: Option<RemoteError>) -> Self;

    /// Takes the envelope apart into its id, its error and its content.
    fn into_parts(self) -> (u64, Option<RemoteError>, Option<Self::Content>);
}

/// Prevents other crates from implementing `Envelope` for additional types.
mod sealed {
    /// Restricts envelope implementations to the two generated wire messages.
    pub trait Sealed {}

    impl Sealed for super::HostToArk {}
    impl Sealed for super::ArkToHost {}
}

impl Envelope for HostToArk {
    /// Payload variants available in the host-to-Ark envelope.
    type Content = host_to_ark::Content;

    /// Builds a host-to-Ark request with content and no application error.
    fn request(id: u64, content: Self::Content) -> Self {
        Self {
            id,
            err: None,
            content: Some(content),
        }
    }
    /// Builds a host-to-Ark response, preserving the supplied content and error.
    fn response(id: u64, content: Option<Self::Content>, err: Option<RemoteError>) -> Self {
        Self { id, err, content }
    }
    /// Takes the host-to-Ark envelope apart without validating its field combination.
    fn into_parts(self) -> (u64, Option<RemoteError>, Option<Self::Content>) {
        (self.id, self.err, self.content)
    }
}

impl Envelope for ArkToHost {
    /// Payload variants available in the Ark-to-host envelope.
    type Content = ark_to_host::Content;

    /// Builds an Ark-to-host request with content and no application error.
    fn request(id: u64, content: Self::Content) -> Self {
        Self {
            id,
            err: None,
            content: Some(content),
        }
    }
    /// Builds an Ark-to-host response, preserving the supplied content and error.
    fn response(id: u64, content: Option<Self::Content>, err: Option<RemoteError>) -> Self {
        Self { id, err, content }
    }
    /// Takes the Ark-to-host envelope apart without validating its field combination.
    fn into_parts(self) -> (u64, Option<RemoteError>, Option<Self::Content>) {
        (self.id, self.err, self.content)
    }
}

/// Whether an incoming envelope is a peer request or a response to our request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Peer request whose response must echo this ID.
    Request(u64),
    /// Response carrying the ID of one of our requests.
    Response(u64),
}

impl Kind {
    /// Uses our request parity to classify an incoming ID: matching parity
    /// means a response, opposite parity means a request.
    pub(crate) fn of(id: u64, parity: Parity) -> Self {
        if Parity::of(id) == parity {
            Self::Response(id)
        } else {
            Self::Request(id)
        }
    }
}

/// Atomic request ID allocator used by the legacy protocol. Hands out IDs of
/// one parity in order, starting at the lowest positive ID.
pub(crate) struct Ids {
    /// Next ID to hand out, incremented atomically by two to preserve parity.
    next: AtomicU64,
}

impl Ids {
    /// Creates the allocator of a side, starting at the lowest positive id
    /// of the parity.
    pub(crate) fn new(parity: Parity) -> Self {
        Self {
            next: AtomicU64::new(parity.first()),
        }
    }

    /// Hands out the next ID, wrapping on overflow. The new protocol uses
    /// `State::Open.next_id` instead and panics when it runs out of IDs.
    pub(crate) fn next(&self) -> u64 {
        self.next.fetch_add(2, Ordering::Relaxed)
    }
}

/// Checks the existing envelope construction and parity conventions.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Tests incoming ID classification: own parity means a response, the other
    /// parity means a peer request.
    #[test]
    fn test_kinds() {
        /// One received ID and its expected interpretation for the receiving side.
        struct TestCase {
            /// Incoming envelope ID, including zero and the largest IDs.
            id: u64,
            /// Parity allocated by the side receiving this envelope.
            parity: Parity,
            /// Expected request or response classification, retaining the same ID.
            kind: Kind,
        }
        let tests = [
            TestCase {
                id: 1,
                parity: Parity::Odd,
                kind: Kind::Response(1),
            },
            TestCase {
                id: 2,
                parity: Parity::Odd,
                kind: Kind::Request(2),
            },
            TestCase {
                id: 1,
                parity: Parity::Even,
                kind: Kind::Request(1),
            },
            TestCase {
                id: 2,
                parity: Parity::Even,
                kind: Kind::Response(2),
            },
            // An old Ark's message without an id decodes as zero, a request to a host
            TestCase {
                id: 0,
                parity: Parity::Odd,
                kind: Kind::Request(0),
            },
            TestCase {
                id: 0,
                parity: Parity::Even,
                kind: Kind::Response(0),
            },
            TestCase {
                id: u64::MAX,
                parity: Parity::Even,
                kind: Kind::Request(u64::MAX),
            },
        ];
        for (i, tt) in tests.iter().enumerate() {
            assert_eq!(Kind::of(tt.id, tt.parity), tt.kind, "test {i}");
        }
    }

    /// Tests the first IDs of both allocators and their interpretation on each side.
    #[test]
    fn test_ids() {
        let client = Ids::new(Parity::from(Side::Client));
        let server = Ids::new(Parity::from(Side::Server));

        let clients: Vec<u64> = (0..4).map(|_| client.next()).collect();
        let servers: Vec<u64> = (0..4).map(|_| server.next()).collect();
        assert_eq!(clients, vec![1, 3, 5, 7]);
        assert_eq!(servers, vec![2, 4, 6, 8]);

        for id in clients {
            assert_eq!(Kind::of(id, Parity::Odd), Kind::Response(id));
            assert_eq!(Kind::of(id, Parity::Even), Kind::Request(id));
        }
        for id in servers {
            assert_eq!(Kind::of(id, Parity::Even), Kind::Response(id));
            assert_eq!(Kind::of(id, Parity::Odd), Kind::Request(id));
        }
    }

    /// Tests that encoding preserves envelope IDs, content and application errors.
    #[test]
    fn test_envelopes() {
        let err = RemoteError {
            code: 7,
            msg: "nope".into(),
        };

        // A host request, opened by the Ark as a request with its content
        let request = HostToArk::request(3, host_to_ark::Content::Develop(vec![1, 2]));
        let (id, err_out, content) = HostToArk::decode(&request.encode_to_vec()[..])
            .unwrap()
            .into_parts();
        assert_eq!((id, err_out), (3, None));
        assert_eq!(content, Some(host_to_ark::Content::Develop(vec![1, 2])));

        // An Ark response failing the request, the error surviving the trip
        let response = ArkToHost::response(3, None, Some(err.clone()));
        let (id, err_out, content) = ArkToHost::decode(&response.encode_to_vec()[..])
            .unwrap()
            .into_parts();
        assert_eq!((id, err_out, content), (3, Some(err.clone()), None));

        // A host response failing an Ark request, its error field the new one
        let response = HostToArk::response(4, None, Some(err.clone()));
        let (id, err_out, content) = HostToArk::decode(&response.encode_to_vec()[..])
            .unwrap()
            .into_parts();
        assert_eq!((id, err_out, content), (4, Some(err), None));
    }
}

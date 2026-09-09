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
use prost::Message as ProtobufMessage;

use super::{Error, Message};

/// Role deciding envelope direction and request parity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    /// Host requests have odd IDs and its connection serves one session.
    Client,
    /// Ark requests have even IDs; the server accepts successive sessions.
    Server,
}

impl Side {
    /// Encodes a body in this side's envelope, refusing invalid directions and
    /// oversize messages before allocating the final protobuf byte buffer.
    pub(super) fn encode(
        &self,
        id: u64,
        body: Result<Message, RemoteError>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Client => encode::<HostToArk>(id, body),
            Self::Server => encode::<ArkToHost>(id, body),
        }
    }

    /// Decodes the peer's envelope, requiring exactly one of content or error.
    /// `SessionInner::handle_message()` classifies the ID and rejects requests
    /// containing errors.
    pub(super) fn decode(
        &self,
        bytes: &[u8],
    ) -> Result<(u64, Result<Message, RemoteError>), Error> {
        match self {
            Self::Client => decode::<ArkToHost>(bytes),
            Self::Server => decode::<HostToArk>(bytes),
        }
    }
}

/// Builds an envelope and checks its size before allocating the encoded bytes.
fn encode<E: Envelope>(id: u64, body: Result<Message, RemoteError>) -> Result<Vec<u8>, Error>
where
    E::Content: TryFrom<Message, Error = Error>,
{
    let envelope = match body {
        Ok(body) => E::from_parts(id, None, Some(body.try_into()?)),
        Err(error) => E::from_parts(id, Some(error), None),
    };
    let size = envelope.encoded_len();
    if size > crate::transport::MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge(size));
    }
    Ok(envelope.encode_to_vec())
}

/// Decodes an envelope, rejecting invalid protobuf or anything other than
/// exactly one of content or error.
fn decode<E: Envelope>(bytes: &[u8]) -> Result<(u64, Result<Message, RemoteError>), Error>
where
    Message: From<E::Content>,
{
    let (id, error, content) = E::decode(bytes).map_err(|_| Error::Malformed)?.into_parts();
    let body = match (content, error) {
        (Some(content), None) => Ok(content.into()),
        (None, Some(error)) => Err(error),
        _ => return Err(Error::Malformed),
    };
    Ok((id, body))
}

/// Parity of the IDs a side allocates, distinguishing its requests from the peer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Parity {
    /// The IDs of a client's requests.
    Odd,
    /// The IDs of a server's requests.
    Even,
}

impl Parity {
    /// Returns the parity of an ID, treating zero as even.
    fn of(id: u64) -> Self {
        if id % 2 == 1 { Self::Odd } else { Self::Even }
    }

    /// Returns the lowest positive ID of this parity, the first one allocated.
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
pub trait Envelope: ProtobufMessage + Default + sealed::Sealed + 'static {
    /// Generated content enum for this envelope's requests and responses.
    type Content: Send + 'static;

    /// Assembles the ID, error and content in the order returned by
    /// [`Self::into_parts`]. This does not validate the field combination or
    /// classify the envelope as a request or response.
    fn from_parts(id: u64, err: Option<RemoteError>, content: Option<Self::Content>) -> Self;

    /// Takes the envelope apart into its ID, error and content.
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

    /// Assembles a host-to-Ark envelope without validating its fields.
    fn from_parts(id: u64, err: Option<RemoteError>, content: Option<Self::Content>) -> Self {
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

    /// Assembles an Ark-to-host envelope without validating its fields.
    fn from_parts(id: u64, err: Option<RemoteError>, content: Option<Self::Content>) -> Self {
        Self { id, err, content }
    }

    /// Takes the Ark-to-host envelope apart without validating its field combination.
    fn into_parts(self) -> (u64, Option<RemoteError>, Option<Self::Content>) {
        (self.id, self.err, self.content)
    }
}

/// Whether an incoming envelope is a peer request or a response to our request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MessageKind {
    /// Peer request whose response must echo the received ID.
    Request,
    /// Response carrying the ID of one of our requests.
    Response,
}

impl MessageKind {
    /// Uses our request parity to classify an incoming ID: matching parity
    /// means a response, opposite parity means a request.
    pub(super) fn from_id(id: u64, parity: Parity) -> Self {
        if Parity::of(id) == parity {
            Self::Response
        } else {
            Self::Request
        }
    }
}

/// Checks incoming request and response classification by ID parity.
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
            /// Expected request or response classification.
            kind: MessageKind,
        }
        let tests = [
            TestCase {
                id: 1,
                parity: Parity::Odd,
                kind: MessageKind::Response,
            },
            TestCase {
                id: 2,
                parity: Parity::Odd,
                kind: MessageKind::Request,
            },
            TestCase {
                id: 1,
                parity: Parity::Even,
                kind: MessageKind::Request,
            },
            TestCase {
                id: 2,
                parity: Parity::Even,
                kind: MessageKind::Response,
            },
            // Zero is an ordinary even ID, with the same classification rules.
            TestCase {
                id: 0,
                parity: Parity::Odd,
                kind: MessageKind::Request,
            },
            TestCase {
                id: 0,
                parity: Parity::Even,
                kind: MessageKind::Response,
            },
            TestCase {
                id: u64::MAX,
                parity: Parity::Even,
                kind: MessageKind::Request,
            },
        ];
        for (i, tt) in tests.iter().enumerate() {
            assert_eq!(MessageKind::from_id(tt.id, tt.parity), tt.kind, "test {i}");
        }
    }
}

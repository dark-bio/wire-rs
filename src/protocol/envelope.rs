// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Encoding, retaining and decoding `HostToArk` and `ArkToHost` envelopes.
//!
//! A request carries an ID chosen by its sender; the response echoes that ID.
//! Clients choose odd request IDs and servers choose even ones. An incoming ID
//! of our parity is a response; the other parity means a request from the peer.
//! Every envelope contains either message content or an error. Only responses
//! may contain errors.

use crate::protocol::schema::{self, ArkToHost, HostToArk, ark_to_host, host_to_ark};
use prost::Message as ProtobufMessage;
use prost::bytes::Bytes;
use prost::encoding::{DecodeContext, decode_key, skip_field};

use super::session::SessionInner;
use super::{Error, Message};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

/// Role deciding envelope direction and request parity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    /// Host requests have odd IDs and its connection serves one session.
    Client,
    /// Ark requests have even IDs; the server accepts successive sessions.
    Server,
}

impl Side {
    /// Reads the envelope's routing fields without decoding its nested payload.
    /// The caller keeps the original bytes for full decoding later.
    pub(super) fn decode_header(&self, bytes: Bytes) -> Result<Header, Error> {
        // Parse out the message shape for request or response routing
        let length = bytes.len();
        let invalid = |error| self.malformed(None, length, "envelope", error);
        let (id, failed, payload) = match self {
            Self::Client => {
                let envelope = opaque::ArkToHost::decode(bytes.clone()).map_err(invalid)?;
                (
                    envelope.id,
                    envelope.err.is_some(),
                    envelope.content.as_ref().map(|content| content.name()),
                )
            }
            Self::Server => {
                let envelope = opaque::HostToArk::decode(bytes.clone()).map_err(invalid)?;
                (
                    envelope.id,
                    envelope.err.is_some(),
                    envelope.content.as_ref().map(|content| content.name()),
                )
            }
        };
        // Content the schema does not have is content still, just unknown. With
        // no known content decoded, any top level tag left in the content range
        // is probably a future message not yet known by this build.
        let unknown = payload.is_none() && {
            let mut rest = &bytes[..];
            loop {
                if rest.is_empty() {
                    break false;
                }
                let Ok((tag, wire_type)) = decode_key(&mut rest) else {
                    break false;
                };
                if tag >= 0x100 {
                    // first field tag of the content oneofs
                    break true;
                }
                if skip_field(wire_type, tag, &mut rest, DecodeContext::default()).is_err() {
                    break false;
                }
            }
        };
        let header = Header {
            id,
            failed,
            payload: payload
                .or(unknown.then_some("unknown"))
                .or(failed.then_some("err")),
            unknown,
        };
        // Require exactly one body; presence is preserved even for empty bytes.
        if (payload.is_some() || unknown) == failed {
            return Err(self.malformed(
                Some(header),
                length,
                "envelope",
                if failed {
                    "envelope contains both content and error"
                } else {
                    "envelope has neither content nor error"
                },
            ));
        }
        Ok(header)
    }

    /// Encodes a body in this side's envelope, refusing invalid directions and
    /// oversize messages before allocating the final protobuf byte buffer.
    pub(super) fn encode(
        &self,
        id: u64,
        body: Result<Message, schema::Error>,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Client => encode::<HostToArk>(id, body),
            Self::Server => encode::<ArkToHost>(id, body),
        }
    }

    /// Decodes the peer's envelope, requiring exactly one of content or error.
    /// `SessionInner::handle_message()` classifies the ID and rejects requests
    /// containing errors. Keeps decoder errors for the warning at the call site.
    pub(super) fn decode(
        &self,
        bytes: &[u8],
    ) -> Result<(u64, Result<Message, schema::Error>), DecodeError> {
        match self {
            Self::Client => decode::<ArkToHost>(bytes),
            Self::Server => decode::<HostToArk>(bytes),
        }
    }

    /// Logs one rejection with the metadata available at that point. Leaves ID
    /// and kind absent if the outer envelope could not be parsed.
    pub(super) fn malformed(
        &self,
        header: Option<Header>,
        length: usize,
        stage: &'static str,
        reason: impl std::fmt::Display,
    ) -> Error {
        if let Some(header) = header {
            let kind = match MessageKind::from_id(header.id, (*self).into()) {
                MessageKind::Request => "request",
                MessageKind::Response => "response",
            };
            tracing::warn!(
                "malformed protocol {} (id: {}, kind: {}, payload: {}, length: {}): {}",
                stage,
                header.id,
                kind,
                header.payload.unwrap_or("none"),
                length,
                reason,
            );
        } else {
            tracing::warn!(
                "malformed protocol {} (length: {}): {}",
                stage,
                length,
                reason
            );
        }
        Error::Malformed
    }
}

/// Routing fields of an envelope whose nested body has not been decoded yet.
#[derive(Clone, Copy)]
pub(super) struct Header {
    /// Final scalar ID, including Protobuf's default of zero.
    pub(super) id: u64,
    /// Whether the envelope carries an error instead of content.
    pub(super) failed: bool,
    /// Payload field name for log lines. Absent if the envelope has no body.
    pub(super) payload: Option<&'static str>,
    /// Whether the content is a field this build does not know.
    pub(super) unknown: bool,
}

/// One encoded envelope held by the request queue or a completed response promise.
pub(super) struct IncomingEnvelope {
    /// Original protobuf bytes, including repeated and unknown fields. Keeping
    /// these intact preserves nested message merging when decoded later.
    bytes: Bytes,
    /// Parsed metadata for warnings if deferred decoding fails.
    header: Header,
    /// Returns byte capacity to the original session when dropped.
    charge: ByteCharge,
    /// Wire direction used only when the application retrieves this message.
    side: Side,
    /// A malformed body closes its original session, never a replacement.
    session: Weak<SessionInner>,
}

impl IncomingEnvelope {
    /// Reserves bytes for an envelope that passed the outer checks. Counts its
    /// full encoded length against the session's shared byte limit.
    pub(super) fn new(
        bytes: Bytes,
        header: Header,
        retained_bytes: &Arc<AtomicUsize>,
        limit: usize,
        side: Side,
        session: Weak<SessionInner>,
    ) -> Result<Self, Error> {
        let charge = ByteCharge::reserve(retained_bytes, bytes.len(), limit)?;
        Ok(Self {
            bytes,
            header,
            charge,
            side,
            session,
        })
    }

    /// Releases the byte charge, then decodes the payload for the caller.
    /// Decoding work and decoded data are outside the inbound byte limit.
    pub(super) fn decode(self) -> Result<Message, Error> {
        let Self {
            bytes,
            header,
            charge,
            side,
            session,
        } = self;
        drop(charge);
        match side.decode(&bytes) {
            Ok((_, body)) => body.map_err(Error::Remote),
            Err(error) => {
                let error = side.malformed(Some(header), bytes.len(), "payload", error);
                if let Some(session) = session.upgrade() {
                    session.close(error.clone());
                }
                Err(error)
            }
        }
    }
}

/// Returns an envelope's byte charge to its original session counter on drop.
/// Keeps the counter alive while an unread response still holds bytes.
struct ByteCharge {
    /// Counter independent of the session lifetime and any replacement session.
    used: Arc<AtomicUsize>,
    /// Original encoded length; never recomputed from decoded or re-encoded data.
    bytes: usize,
}

impl ByteCharge {
    /// Adds to the byte count unless it would exceed the limit. Never waits for
    /// a consumer to release bytes.
    fn reserve(used: &Arc<AtomicUsize>, bytes: usize, limit: usize) -> Result<Self, Error> {
        // This atomic only tracks usage. The session lock and result channels
        // synchronize access to the messages themselves.
        used.try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            used.checked_add(bytes).filter(|total| *total <= limit)
        })
        .map_err(|used| {
            tracing::warn!(
                "inbound byte limit exceeded (used: {}, incoming: {}, limit: {})",
                used,
                bytes,
                limit
            );
            Error::InboundByteLimitExceeded(limit)
        })?;
        Ok(Self {
            used: used.clone(),
            bytes,
        })
    }
}

impl Drop for ByteCharge {
    /// Releases this envelope's bytes, including when delivery fails.
    fn drop(&mut self) {
        let previous = self.used.fetch_sub(self.bytes, Ordering::Relaxed);
        debug_assert!(previous >= self.bytes, "incoming byte charge underflow");
    }
}

/// Builds an envelope and checks its size before allocating the encoded bytes.
fn encode<E: Envelope>(id: u64, body: Result<Message, schema::Error>) -> Result<Vec<u8>, Error>
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
fn decode<E: Envelope>(bytes: &[u8]) -> Result<(u64, Result<Message, schema::Error>), DecodeError>
where
    Message: From<E::Content>,
{
    let (id, error, content) = E::decode(bytes)?.into_parts();
    let body = match (content, error) {
        (Some(content), None) => Ok(content.into()),
        (None, Some(error)) => Err(error),
        _ => return Err(DecodeError::Body),
    };
    Ok((id, body))
}

/// Keeps the decoder's reason until the caller logs it and returns `Malformed`.
#[derive(Debug, thiserror::Error)]
pub(super) enum DecodeError {
    /// Invalid protobuf, including a malformed nested payload.
    #[error("{0}")]
    Protobuf(#[from] prost::DecodeError),
    /// Missing body, or both a message and an error.
    #[error("expected exactly one of content or error")]
    Body,
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

/// Common encoding and decoding methods for the two wire envelopes.
trait Envelope: ProtobufMessage + Default {
    /// Generated content enum for this envelope's requests and responses.
    type Content;

    /// Assembles the ID, error and content in the order returned by
    /// [`Self::into_parts`]. This does not validate the field combination or
    /// classify the envelope as a request or response.
    fn from_parts(id: u64, err: Option<schema::Error>, content: Option<Self::Content>) -> Self;

    /// Takes the envelope apart into its ID, error and content.
    fn into_parts(self) -> (u64, Option<schema::Error>, Option<Self::Content>);
}

impl Envelope for HostToArk {
    /// Payload variants available in the host-to-Ark envelope.
    type Content = host_to_ark::Content;

    /// Assembles a host-to-Ark envelope without validating its fields.
    fn from_parts(id: u64, err: Option<schema::Error>, content: Option<Self::Content>) -> Self {
        Self { id, err, content }
    }

    /// Takes the host-to-Ark envelope apart without validating its field combination.
    fn into_parts(self) -> (u64, Option<schema::Error>, Option<Self::Content>) {
        (self.id, self.err, self.content)
    }
}

impl Envelope for ArkToHost {
    /// Payload variants available in the Ark-to-host envelope.
    type Content = ark_to_host::Content;

    /// Assembles an Ark-to-host envelope without validating its fields.
    fn from_parts(id: u64, err: Option<schema::Error>, content: Option<Self::Content>) -> Self {
        Self { id, err, content }
    }

    /// Takes the Ark-to-host envelope apart without validating its field combination.
    fn into_parts(self) -> (u64, Option<schema::Error>, Option<Self::Content>) {
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

/// Generated envelope views with nested messages left as bytes. These use the
/// same field numbers and oneofs as the full message bindings.
#[allow(clippy::all)]
#[allow(rustdoc::broken_intra_doc_links)]
pub(super) mod opaque {
    include!("generated/darkbio.wire.opaque.rs");
}

// Payload names follow the schema alongside the generated envelope views.
include!("generated/darkbio.wire.names.rs");

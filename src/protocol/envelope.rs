// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Conventions of the envelopes, the two messages the sides of the wire
//! exchange. Every message carries an id, a request one its sender chose and
//! a response the one of the request it answers, with an error in place of
//! content on failure. Clients allocate odd ids and servers even ones, so the
//! parity of an id tells a response to one's own request from a request of
//! the peer's.

use crate::protocol::{ArkToHost, Error, HostToArk, ark_to_host, host_to_ark};
use prost::Message;
use std::sync::atomic::{AtomicU64, Ordering};

/// Role in the protocol, deciding request parity and whether the mux serves
/// successive sessions. Independent of the transport's implementation roles.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    /// Host requests have odd IDs and its mux serves one session.
    Client,
    /// Ark requests have even IDs and its mux accepts successive sessions.
    Server,
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
    fn first(self) -> u64 {
        match self {
            Self::Odd => 1,
            Self::Even => 2,
        }
    }
}

impl From<Side> for Parity {
    fn from(side: Side) -> Self {
        match side {
            Side::Client => Self::Odd,
            Side::Server => Self::Even,
        }
    }
}

/// One of the two messages traveling the wire. Sealed, the two being the
/// only envelopes there are.
pub trait Envelope: Message + Default + sealed::Sealed + 'static {
    /// Content of the direction, its requests and responses, handed between
    /// the threads of a multiplexer.
    type Content: Send + 'static;

    /// A request with the id.
    fn request(id: u64, content: Self::Content) -> Self;

    /// A response to the request with the id, content on success and an
    /// error on failure.
    fn response(id: u64, content: Option<Self::Content>, err: Option<Error>) -> Self;

    /// Takes the envelope apart into its id, its error and its content.
    fn into_parts(self) -> (u64, Option<Error>, Option<Self::Content>);
}

/// Supertrait nobody outside the crate can implement, closing the envelopes.
mod sealed {
    pub trait Sealed {}

    impl Sealed for super::HostToArk {}
    impl Sealed for super::ArkToHost {}
}

impl Envelope for HostToArk {
    type Content = host_to_ark::Content;

    fn request(id: u64, content: Self::Content) -> Self {
        Self {
            id,
            err: None,
            content: Some(content),
        }
    }
    fn response(id: u64, content: Option<Self::Content>, err: Option<Error>) -> Self {
        Self { id, err, content }
    }
    fn into_parts(self) -> (u64, Option<Error>, Option<Self::Content>) {
        (self.id, self.err, self.content)
    }
}

impl Envelope for ArkToHost {
    type Content = ark_to_host::Content;

    fn request(id: u64, content: Self::Content) -> Self {
        Self {
            id,
            err: None,
            content: Some(content),
        }
    }
    fn response(id: u64, content: Option<Self::Content>, err: Option<Error>) -> Self {
        Self { id, err, content }
    }
    fn into_parts(self) -> (u64, Option<Error>, Option<Self::Content>) {
        (self.id, self.err, self.content)
    }
}

/// What an incoming envelope is to the side receiving it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A request of the peer's, to be answered with its id.
    Request(u64),
    /// A response to a request of one's own, the id naming it.
    Response(u64),
}

impl Kind {
    /// Classifies an incoming id on the side allocating ids of the parity,
    /// its own parity meaning a response, the other a request.
    pub(crate) fn of(id: u64, parity: Parity) -> Self {
        if Parity::of(id) == parity {
            Self::Response(id)
        } else {
            Self::Request(id)
        }
    }
}

/// Allocator of the request ids of one side, handing out the ids of its
/// parity in order, from any thread.
pub(crate) struct Ids {
    next: AtomicU64, // Next id to hand out
}

impl Ids {
    /// Creates the allocator of a side, starting at the lowest positive id
    /// of the parity.
    pub(crate) fn new(parity: Parity) -> Self {
        Self {
            next: AtomicU64::new(parity.first()),
        }
    }

    /// Hands out the next id.
    pub(crate) fn next(&self) -> u64 {
        self.next.fetch_add(2, Ordering::Relaxed)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // Tests the classification of incoming ids on both sides, the parity of
    // one's own requests meaning a response and the other one a request.
    #[test]
    fn test_kinds() {
        struct TestCase {
            id: u64,
            parity: Parity,
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

    // Tests that the allocators of the two sides hand out their parities in
    // order and never meet.
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

    // Tests that the envelopes of both directions build as the conventions
    // say and come apart the same after a trip through their encoding.
    #[test]
    fn test_envelopes() {
        let err = Error {
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

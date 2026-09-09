// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Shared message bodies, generated from both protobuf content oneofs.

use super::Error;
use super::generated::*;

macro_rules! messages {
    ($($variant:ident($payload:ty),)*) => {
        /// A request or successful response body, shared by hosts and servers.
        /// Variants and typed conversions are generated from the protobuf schema.
        /// Request IDs, wire envelopes and direction selection remain internal to
        /// the session API. A message's admissible direction is checked at runtime.
        ///
        /// Use `From`/`.into()` to submit a protobuf message, match variants to
        /// dispatch incoming work, and `TryFrom` to extract an expected body type.
        /// Extraction checks the variant and returns [`Error::UnexpectedResponse`]
        /// on mismatch. There is no static request/response pairing table.
        #[derive(Clone, Debug, PartialEq)]
        pub enum Message {
            $(
                #[doc = concat!("A `", stringify!($payload), "` payload.")]
                $variant($payload),
            )*
        }

        impl Message {
            fn message_type(&self) -> &'static str {
                match self {
                    $(Self::$variant(_) => stringify!($payload),)*
                }
            }
        }

        $(
            impl From<$payload> for Message {
                fn from(message: $payload) -> Self {
                    Self::$variant(message)
                }
            }

            impl TryFrom<Message> for $payload {
                type Error = Error;

                fn try_from(message: Message) -> Result<Self, Self::Error> {
                    match message {
                        Message::$variant(message) => Ok(message),
                        other => Err(Error::UnexpectedResponse {
                            expected: stringify!($payload),
                            received: other.message_type(),
                        }),
                    }
                }
            }
        )*
    };
}

include!(concat!(env!("OUT_DIR"), "/message.rs"));

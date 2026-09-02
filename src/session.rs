// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Established session state and the sealing of protobuf messages through it.

use crate::{Error, MAX_FRAME_SIZE};
use darkbio_cobs as cobs;
use darkbio_crypto::xhpke;
use prost::Message;

/// Established session, holding the xHPKE contexts of the two directions.
pub(crate) struct Session {
    pub sender: xhpke::Sender, // Outbound context, sealing messages to the peer
    pub receiver: xhpke::Receiver, // Inbound context, opening messages from the peer
}

impl Session {
    /// Bytes the session's AEAD adds to a sealed message (the Poly1305 tag).
    /// Sealing advances the HPKE sequence, so message sizes are bounded with
    /// this before sealing rather than by rejecting the sealed output afterwards.
    pub const SEAL_OVERHEAD: usize = 16;

    /// Protobuf encodes a message into the scratch buffer and seals it for the
    /// peer. Messages whose sealed and framed size would exceed MAX_FRAME_SIZE
    /// are rejected before sealing, leaving the HPKE sequence untouched; a
    /// failure of the sealing itself leaves the context unusable.
    pub fn seal<M: Message>(&mut self, msg: &M, scratch: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
        let len = msg.encoded_len();
        if cobs::encode_buffer(len + Self::SEAL_OVERHEAD) > MAX_FRAME_SIZE {
            return Err(Error::PacketTooLarge(len));
        }
        scratch.clear();
        msg.encode(scratch).map_err(Error::PacketEncodingFailed)?;

        self.sender
            .seal(scratch, &[])
            .map_err(|err| Error::EncryptionFailed(err.to_string()))
    }

    /// Opens a sealed packet from the peer and protobuf decodes it. A failure
    /// to decrypt means the HPKE sequence can no longer be followed, whereas a
    /// packet that decrypts but does not decode leaves the session intact.
    pub fn open<M: Message + Default>(&mut self, packet: &[u8]) -> Result<M, Error> {
        let blob = self
            .receiver
            .open(packet, &[])
            .map_err(|err| Error::EncryptionFailed(err.to_string()))?;

        M::decode(&blob[..]).map_err(Error::PacketDecodingFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that the sealing overhead constant matches what the session AEAD
    // actually adds, so a crypto upgrade cannot silently break size bounds.
    #[test]
    fn test_seal_overhead() {
        let secret = xhpke::SecretKey::generate();
        let (mut sender, _) = secret.public_key().new_sender(b"test").unwrap();

        for size in [0, 1, 255, 4096] {
            let sealed = sender.seal(&vec![0x42; size], &[]).unwrap();
            assert_eq!(
                sealed.len(),
                size + Session::SEAL_OVERHEAD,
                "overhead mismatch"
            );
        }
    }

    // Tests that an oversized message is rejected before sealing, leaving the
    // HPKE sequence untouched so the session stays in sync with its peer.
    #[test]
    fn test_seal_oversized() {
        /// Throwaway message carrying an arbitrary payload.
        #[derive(Clone, PartialEq, Message)]
        struct Blob {
            #[prost(bytes = "vec", tag = "1")]
            data: Vec<u8>,
        }

        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        let mut session = Session { sender, receiver };
        let mut scratch = Vec::new();

        // A message that fits the frame limit as plaintext, but not once the
        // sealing and framing overheads are added, must be rejected up front.
        let blob = Blob {
            data: vec![0x42; MAX_FRAME_SIZE - 32],
        };
        assert!(
            matches!(
                session.seal(&blob, &mut scratch),
                Err(Error::PacketTooLarge(_))
            ),
            "expected oversized packet rejection"
        );

        // The sequence must not have advanced, so the next sealed message must
        // still open as the first one on the receiving side.
        let blob = Blob {
            data: b"in sync".to_vec(),
        };
        let sealed = session.seal(&blob, &mut scratch).unwrap();
        let opened: Blob = session.open(&sealed).unwrap();
        assert_eq!(opened, blob, "message mismatch");
    }
}

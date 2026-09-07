// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Sealing of protobuf messages into packets with the xHPKE context of a
//! direction, and opening them again.

use crate::{Error, MAX_MESSAGE_SIZE};
use darkbio_crypto::xhpke;
use prost::Message;

/// Bytes the session's AEAD adds to a sealed message (the Poly1305 tag).
/// Sealing advances the HPKE sequence, so message sizes are bounded with this
/// before sealing rather than by rejecting the sealed output afterwards.
pub(crate) const OVERHEAD: usize = 16;

/// Protobuf encodes a message into the scratch buffer and seals it for the
/// peer with the outbound context. Messages above MAX_MESSAGE_SIZE are rejected
/// before sealing, leaving the HPKE sequence untouched; a failure of the
/// sealing itself leaves the context unusable.
pub(crate) fn seal<M: Message>(
    sender: &mut xhpke::Sender,
    msg: &M,
    scratch: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let len = msg.encoded_len();
    if len > MAX_MESSAGE_SIZE {
        return Err(Error::PacketTooLarge(len));
    }
    scratch.clear();
    msg.encode(scratch).map_err(Error::PacketEncodingFailed)?;

    sender
        .seal(scratch, &[])
        .map_err(|err| Error::EncryptionFailed(err.to_string()))
}

/// Opens a sealed packet from the peer with the inbound context and protobuf
/// decodes it. A failure to decrypt means the HPKE sequence can no longer be
/// followed, whereas a packet that decrypts but does not decode leaves the
/// context intact.
pub(crate) fn open<M: Message + Default>(
    receiver: &mut xhpke::Receiver,
    packet: &[u8],
) -> Result<M, Error> {
    let blob = receiver
        .open(packet, &[])
        .map_err(|err| Error::EncryptionFailed(err.to_string()))?;

    M::decode(&blob[..]).map_err(Error::PacketDecodingFailed)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::MAX_FRAME_SIZE;
    use darkbio_cobs as cobs;

    // Tests that the sealing overhead constant matches what the session AEAD
    // actually adds, so a crypto upgrade cannot silently break size bounds.
    #[test]
    fn test_seal_overhead() {
        let secret = xhpke::SecretKey::generate();
        let (mut sender, _) = secret.public_key().new_sender(b"test").unwrap();

        for size in [0, 1, 255, 4096] {
            let sealed = sender.seal(&vec![0x42; size], &[]).unwrap();
            assert_eq!(sealed.len(), size + OVERHEAD, "size {size}");
        }
    }

    // Tests that the message limit is exact against the frame limit. The sealed
    // and framed size of a maximal message fits a frame, the next byte pushing
    // it over.
    #[test]
    fn test_message_limit() {
        let framed = |size: usize| cobs::encode_buffer(size + OVERHEAD);

        assert!(framed(MAX_MESSAGE_SIZE) <= MAX_FRAME_SIZE);
        assert!(framed(MAX_MESSAGE_SIZE + 1) > MAX_FRAME_SIZE);
    }

    // Tests that a message at the limit seals into a frame sized packet and
    // that one over the limit is rejected before sealing. The rejection leaves
    // the HPKE sequence untouched, so the session stays in sync.
    #[test]
    fn test_seal_bounds() {
        /// Throwaway message carrying an arbitrary payload.
        #[derive(Clone, PartialEq, Message)]
        struct Blob {
            #[prost(bytes = "vec", tag = "1")]
            data: Vec<u8>,
        }

        /// Blob whose protobuf encoding is exactly the given size.
        fn blob_of(size: usize) -> Blob {
            let mut blob = Blob {
                data: vec![0x42; size],
            };
            blob.data.truncate(size - (blob.encoded_len() - size));
            assert_eq!(blob.encoded_len(), size);
            blob
        }

        let secret = xhpke::SecretKey::generate();
        let (mut sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let mut receiver = secret.new_receiver(&encap, b"test").unwrap();
        let mut scratch = Vec::new();

        // One byte over the limit must be rejected up front
        let blob = blob_of(MAX_MESSAGE_SIZE + 1);
        let result = seal(&mut sender, &blob, &mut scratch).map(|sealed| sealed.len());
        assert!(
            matches!(result, Err(Error::PacketTooLarge(_))),
            "{result:?}"
        );

        // A maximal message must seal, frame within the limit and, the
        // sequence not having advanced, open as the first message on the
        // receiving side
        let blob = blob_of(MAX_MESSAGE_SIZE);
        let sealed = seal(&mut sender, &blob, &mut scratch).unwrap();
        assert!(cobs::encode_buffer(sealed.len()) <= MAX_FRAME_SIZE);
        let opened: Blob = open(&mut receiver, &sealed).unwrap();
        assert_eq!(opened, blob);
    }
}

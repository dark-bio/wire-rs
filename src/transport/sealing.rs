// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Seals messages into packets and opens them using each direction's xHPKE context.

use crate::transport::{Error, MAX_MESSAGE_SIZE};
use darkbio_crypto::xhpke;

/// Bytes the session's AEAD adds to a sealed message (the Poly1305 tag).
/// Sealing advances the HPKE sequence, so message sizes are bounded with this
/// before sealing. Rejecting a packet after sealing would leave a sequence gap.
pub(crate) const OVERHEAD: usize = 16;

/// Seals a message for the peer with the outbound context. Messages above
/// MAX_MESSAGE_SIZE are rejected before sealing, leaving the HPKE sequence
/// untouched. A crypto failure leaves the context unusable.
pub(crate) fn seal(sender: &mut xhpke::Sender, message: &[u8]) -> Result<Vec<u8>, Error> {
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(Error::PacketTooLarge(message.len()));
    }
    sender
        .seal(message, &[])
        .map_err(|err| Error::EncryptionFailed(err.to_string()))
}

/// Opens a sealed packet from the peer with the inbound context. A failure to
/// decrypt means the HPKE sequence can no longer be followed.
pub(crate) fn open(receiver: &mut xhpke::Receiver, packet: &[u8]) -> Result<Vec<u8>, Error> {
    receiver
        .open(packet, &[])
        .map_err(|err| Error::EncryptionFailed(err.to_string()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::MAX_FRAME_SIZE;
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

    // Tests that the conservative message limit fits the worst-case sealing
    // and COBS overhead. The next byte exceeds that worst-case frame budget;
    // particular messages may still produce smaller frames.
    #[test]
    fn test_message_limit() {
        let framed = |size: usize| cobs::encode_buffer(size + OVERHEAD);

        assert!(framed(MAX_MESSAGE_SIZE) <= MAX_FRAME_SIZE);
        assert!(framed(MAX_MESSAGE_SIZE + 1) > MAX_FRAME_SIZE);
    }

    // Tests that a message at the limit seals into a packet that fits a frame and
    // that one over the limit is rejected before sealing. The rejection leaves
    // the HPKE sequence untouched, so the session stays in sync.
    #[test]
    fn test_seal_bounds() {
        let secret = xhpke::SecretKey::generate();
        let (mut sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let mut receiver = secret.new_receiver(&encap, b"test").unwrap();

        // One byte over the limit must be rejected up front
        let message = vec![0x42; MAX_MESSAGE_SIZE + 1];
        let result = seal(&mut sender, &message).map(|sealed| sealed.len());
        assert!(
            matches!(result, Err(Error::PacketTooLarge(_))),
            "{result:?}"
        );

        // The rejected message did not advance the sequence. A maximal message
        // must still seal, fit a frame and open as the receiver's first message.
        let message = vec![0x42; MAX_MESSAGE_SIZE];
        let sealed = seal(&mut sender, &message).unwrap();
        assert!(cobs::encode_buffer(sealed.len()) <= MAX_FRAME_SIZE);
        assert_eq!(open(&mut receiver, &sealed).unwrap(), message);
    }
}

// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scripted peers driving one real side of the wire through arbitrary frame
//! sequences. A script decides what the side under test reads next. A model
//! of the protocol's state machine predicts the reaction to each frame, and a
//! run panics at the first divergence between the two. The scenario tests and
//! the packet level fuzzers share this, so a fuzzer finding replays as a test.

pub mod ark;
pub mod host;

use crate::Attestation;
use darkbio_cobs as cobs;
use darkbio_crypto::cwt::claims::{self, eat};
use darkbio_crypto::{cwt, xdsa};
use std::cell::{Cell, RefCell};
use std::io::{self, Write};
use std::rc::Rc;

/// Most steps a script is run for. It bounds the runtime of a fuzz iteration
/// and keeps the unterminated frames a script can pile up well below the
/// frame limit.
pub const MAX_STEPS: usize = 64;

/// Self-signed attestation of a never onboarded Ark, embedding the identity
/// key that signs the handshake.
pub fn self_attestation(signer: &xdsa::SecretKey) -> Attestation {
    let claims = darkbio_trust::device::HardwareClaims {
        sub: claims::Subject { sub: "".into() },
        cnf: claims::Confirm::new(signer.public_key()),
        nbf: claims::NotBefore { nbf: 0 },
        iat: claims::IssuedAt { iat: 0 },
        oem: eat::Oemid::new_pen(0),
        hwm: eat::HwModel { hw_model: vec![] },
        hwv: eat::HwVersion::new("".into()),
    };
    let cwt = cwt::issue(
        &claims,
        signer,
        darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION,
    )
    .unwrap();
    Attestation::new(cwt).unwrap()
}

/// Well formed attestation of the wrong shape, a cloud signer attestation
/// issued under the device attestation domain. The wire refuses it as a device
/// attestation before any verifier sees it.
pub fn cloud_attestation(signer: &xdsa::SecretKey) -> Vec<u8> {
    let claims = darkbio_trust::cloud::SignerClaims {
        iss: claims::Issuer { iss: "".into() },
        sub: claims::Subject { sub: "".into() },
        nbf: claims::NotBefore { nbf: 0 },
        exp: claims::Expiration { exp: 1 },
        cnf: claims::Confirm::new(signer.public_key()),
    };
    cwt::issue(
        &claims,
        signer,
        darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION,
    )
    .unwrap()
}

/// COBS encodes a packet into a frame, delimiter included.
pub fn frame(packet: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; cobs::encode_buffer(packet.len())];
    let n = cobs::encode(packet, &mut buf).unwrap();
    buf.truncate(n);
    buf.push(0x00);
    buf
}

/// COBS decodes a frame, its delimiter already stripped, back into a packet.
pub fn unframe(frame: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; cobs::decode_buffer(frame.len())];
    let n = cobs::decode(frame, &mut buf).expect("side under test wrote an undecodable frame");
    buf.truncate(n);
    buf
}

/// The error a read fails with when a script yields.
pub fn would_block() -> io::Error {
    io::ErrorKind::WouldBlock.into()
}

/// Frames written by the side under test, drained by the scripted peer. Its
/// writes can be made to fail, standing in for a transport that died.
#[derive(Clone, Default)]
pub struct Outbox {
    bytes: Rc<RefCell<Vec<u8>>>,
    broken: Rc<Cell<bool>>,
}

impl Outbox {
    /// Takes the frames written so far, delimiters stripped. The sides write
    /// frames whole, so a trailing unterminated one is a bug.
    pub fn take_frames(&self) -> Vec<Vec<u8>> {
        let mut bytes = self.bytes.borrow_mut();
        assert!(
            bytes.last().is_none_or(|&b| b == 0),
            "side under test left a frame unterminated"
        );
        // Splitting at the delimiters leaves an empty tail after the last one
        let mut frames: Vec<Vec<u8>> = bytes.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
        frames.pop();
        bytes.clear();
        frames
    }

    /// Makes every write fail from here on, or work again.
    pub fn set_broken(&self, broken: bool) {
        self.broken.set(broken);
    }
}

impl Write for Outbox {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.broken.get() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

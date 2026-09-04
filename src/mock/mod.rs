// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Mock peers driving one real side of the wire through arbitrary frame
//! sequences. A script decides what the side under test reads next. A model
//! of the protocol's state machine predicts the reaction to each frame, and a
//! run panics at the first divergence between the two. The scenario tests and
//! the packet level fuzzers share this, so a fuzzer finding replays as a test.

pub mod client;
pub mod server;

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

/// Self-signed attestation of a never onboarded server, embedding the identity
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

/// Encoder for the byte stream the fuzzers' `Arbitrary` decoding reads a
/// script from, letting the scenario tests seed the corpus with theirs. It
/// mirrors arbitrary 1.4, integers little endian, a keep-going byte ahead of
/// every vector element and an enum variant picked as the high half of a
/// u32 scaled by the variant count.
#[cfg(feature = "fuzz")]
pub struct Seed(Vec<u8>);

#[cfg(feature = "fuzz")]
impl Seed {
    /// Picks the variant with the index out of the count.
    pub fn variant(&mut self, index: u32, count: u32) {
        let pick = (u64::from(index) << 32).div_ceil(u64::from(count)) as u32;
        self.0.extend_from_slice(&pick.to_le_bytes());
    }

    pub fn byte(&mut self, byte: u8) {
        self.0.push(byte);
    }

    pub fn word(&mut self, word: u16) {
        self.0.extend_from_slice(&word.to_le_bytes());
    }

    pub fn flag(&mut self, flag: bool) {
        self.0.push(flag as u8);
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.flag(true);
            self.byte(byte);
        }
        self.flag(false);
    }
}

/// A step able to write itself as the fuzzers read it.
#[cfg(feature = "fuzz")]
pub trait Seedable: for<'a> arbitrary::Arbitrary<'a> + PartialEq + std::fmt::Debug {
    fn seed(&self, seed: &mut Seed);
}

/// Writes the script into the seed corpus of the target, under the directory
/// the WIRE_SEEDS environment variable names, checking that the bytes decode
/// back into the same script. The file is named by the hash of its content,
/// so regenerating leaves an unchanged script untouched. Without the variable
/// set nothing happens.
#[cfg(feature = "fuzz")]
pub fn seed<S: Seedable>(target: &str, steps: &[S]) {
    use arbitrary::{Arbitrary, Unstructured};
    use sha2::{Digest, Sha256};

    let Ok(root) = std::env::var("WIRE_SEEDS") else {
        return;
    };
    let mut seed = Seed(Vec::new());
    for step in steps {
        seed.flag(true);
        step.seed(&mut seed);
    }
    seed.flag(false);

    let decoded =
        Vec::<S>::arbitrary_take_rest(Unstructured::new(&seed.0)).expect("seed failed to decode");
    assert_eq!(decoded, steps, "seed decoded into another script");

    let dir = std::path::Path::new(&root).join(target);
    std::fs::create_dir_all(&dir).expect("failed to create the seed directory");
    let name: String = Sha256::digest(&seed.0)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(dir.join(name), &seed.0).expect("failed to write the seed");
}

/// Where a write of the side under test is cut, standing in for a transport
/// dying under it. The points needing a body to cut, everything but `Start`,
/// leave a lone delimiter alone and fire on the next write with one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum CutPoint {
    /// Nothing of the write goes out.
    Start,
    /// A strict prefix of the body goes out, picked by the number.
    Middle(u16),
    /// Everything but the delimiter goes out.
    Delimiter,
    /// Everything goes out, the flush after it failing.
    Flush,
}

#[cfg(feature = "fuzz")]
impl Seedable for CutPoint {
    fn seed(&self, seed: &mut Seed) {
        match self {
            CutPoint::Start => seed.variant(0, 4),
            CutPoint::Middle(n) => {
                seed.variant(1, 4);
                seed.word(*n);
            }
            CutPoint::Delimiter => seed.variant(2, 4),
            CutPoint::Flush => seed.variant(3, 4),
        }
    }
}

/// Frames written by the side under test, drained by the mock peer. Its
/// writes can be cut short or made to fail, standing in for a transport that
/// died.
#[derive(Clone, Default)]
pub struct Outbox {
    bytes: Rc<RefCell<Vec<u8>>>,
    broken: Rc<Cell<bool>>,
    cut: Rc<Cell<Option<CutPoint>>>,
    flush_fails: Rc<Cell<bool>>,
}

impl Outbox {
    /// Takes the frames written so far, delimiters stripped. A trailing
    /// unterminated frame stays behind, the delimiter of the next write
    /// completing it.
    pub fn take_frames(&self) -> Vec<Vec<u8>> {
        let mut bytes = self.bytes.borrow_mut();
        // Splitting at the delimiters leaves the unterminated tail last, empty
        // if the last write ended on one
        let mut frames: Vec<Vec<u8>> = bytes.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
        let tail = frames.pop().expect("split yields at least one piece");
        *bytes = tail;
        frames
    }

    /// Whether an unterminated frame was left behind.
    pub fn has_tail(&self) -> bool {
        !self.bytes.borrow().is_empty()
    }

    /// Makes every write fail from here on, or work again.
    pub fn set_broken(&self, broken: bool) {
        self.broken.set(broken);
    }

    /// Cuts the next write the point applies to, firing ahead of a broken
    /// transport.
    pub fn set_cut(&self, point: CutPoint) {
        self.cut.set(Some(point));
    }
}

impl Write for Outbox {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // An armed cut fires ahead of a broken transport, on the first write
        // with enough of a body for it
        if let Some(point) = self.cut.get() {
            let accepted = match point {
                CutPoint::Start => Some(0),
                CutPoint::Middle(n) => (buf.len() > 2).then(|| 1 + n as usize % (buf.len() - 2)),
                CutPoint::Delimiter => (buf.len() > 1).then(|| buf.len() - 1),
                CutPoint::Flush => (buf.len() > 1).then_some(buf.len()),
            };
            if let Some(accepted) = accepted {
                self.cut.set(None);
                self.bytes.borrow_mut().extend_from_slice(&buf[..accepted]);
                if point == CutPoint::Flush {
                    self.flush_fails.set(true);
                    return Ok(accepted);
                }
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        if self.broken.get() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.flush_fails.replace(false) {
            true => Err(io::ErrorKind::BrokenPipe.into()),
            false => Ok(()),
        }
    }
}

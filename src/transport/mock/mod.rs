// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Mock peers driving one real side of the wire through arbitrary frame
//! sequences. A script decides what the side under test reads next. A model
//! of the protocol's state machine predicts the reaction to each frame, and a
//! run panics at the first divergence between the two. The scenario tests and
//! the packet level fuzzers share this, so a fuzzer finding replays as a test.

pub mod client;
pub mod duplex;
#[cfg(all(feature = "fuzz", getrandom_backend = "custom"))]
pub mod random;
#[cfg(feature = "fuzz")]
pub mod seed;
pub mod server;
pub mod vector;

use crate::transport::{Attestation, Error, MAX_MESSAGE_SIZE, Sender, Write};
use darkbio_cobs as cobs;
use darkbio_crypto::cwt::claims::{self, eat};
use darkbio_crypto::{cwt, xdsa};
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use vector::{Event, Vector};

/// Most steps a script is run for. It bounds the runtime of a fuzz iteration
/// and keeps the unterminated frames a script can pile up well below the
/// frame limit.
pub const MAX_STEPS: usize = 64;

/// Signing time stamped into everything the mocks and the drivers seal. The
/// wire never checks it, so a fixed one keeps the transcripts off the clock.
pub const TIMESTAMP: i64 = 0;

/// Message one byte past the send limit, used to assert refusal without advancing
/// encryption or touching the writer. Shared so fuzz steps need no large allocation.
pub(super) const OVERSIZED_MESSAGE: &[u8] = &[0x42; MAX_MESSAGE_SIZE + 1];

/// Payload of a message the mocks exchange, the tag as eight big endian
/// bytes. It only tells the messages apart, the transport never reads it.
pub fn payload(tag: u64) -> Vec<u8> {
    tag.to_be_bytes().to_vec()
}

/// Attempts a scripted send through the most recently delivered sender.
/// Before any successful handshake, the driver itself refuses the attempt;
/// no sender exists to call. Retaining ended senders exercises their refusal.
pub(super) fn send<W: Write>(sender: Option<&Sender<W>>, message: &[u8]) -> Result<(), Error> {
    match sender {
        Some(sender) => sender.send(message),
        None => Err(Error::EncryptionFailed("no active session".into())),
    }
}

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
    let cwt = cwt::issue_at(
        &claims,
        signer,
        darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        TIMESTAMP,
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
    cwt::issue_at(
        &claims,
        signer,
        darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        TIMESTAMP,
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

/// Transcript of the run in progress, shared by everything logging into it,
/// absent when the run is not recorded.
pub type Recorder = Arc<Mutex<Option<Vector>>>;

/// Logs an event into the transcript, if the run is recorded.
pub fn trace(recorder: &Recorder, event: impl FnOnce() -> Event) {
    if let Some(vector) = recorder.lock().unwrap().as_mut() {
        vector.log(event());
    }
}

/// Where a write of the side under test is cut, standing in for a transport
/// dying under it. A recovery delimiter belongs to the same write as its frame.
/// Only `Start` applies to a lone delimiter; `Middle` needs at least three bytes,
/// while `Delimiter` and `Flush` also apply to a two-delimiter signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum CutPoint {
    /// Nothing of the write goes out.
    Start,
    /// Accepts `1 + min(n, len - 3)` bytes of a write at least three bytes long.
    /// Zero accepts its first byte, which can be only the recovery delimiter.
    /// Larger offsets clamp before the final body byte and frame delimiter.
    Middle(u16),
    /// Everything but the delimiter goes out.
    Delimiter,
    /// Everything goes out, the flush after it failing.
    Flush,
}

/// Frames written by the side under test, drained by the mock peer. Its
/// writes can be cut short or made to fail, standing in for a transport that
/// died.
#[derive(Clone, Default)]
pub struct Outbox {
    shared: Arc<Output>,
    recorder: Recorder, // Transcript the writes are logged into
}

/// Written bytes and scripted failures, shared with a client's handshake writer.
#[derive(Default)]
struct Output {
    state: Mutex<OutputState>,
    changed: Condvar,
}

/// Output mutations under one lock, including the flush boundary a scripted
/// reader waits for before answering the new HostHello.
#[derive(Default)]
struct OutputState {
    bytes: Vec<u8>,
    broken: bool,
    cut: Option<CutPoint>,
    timeout: bool,
    write_error: Option<io::ErrorKind>, // Deferred until the call after accepted bytes
    flush_error: Option<io::ErrorKind>,
    flushes: usize,
    handshake: Option<usize>,
}

impl Outbox {
    /// Takes the frames written so far, delimiters stripped. A trailing
    /// unterminated frame stays behind, the delimiter of the next write
    /// completing it.
    pub fn take_frames(&self) -> Vec<Vec<u8>> {
        let mut state = self.shared.state.lock().unwrap();
        // Splitting at the delimiters leaves the unterminated tail last, empty
        // if the last write ended on one
        let mut frames: Vec<Vec<u8>> = state.bytes.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
        let tail = frames.pop().expect("split yields at least one piece");
        state.bytes = tail;
        frames
    }

    /// Whether an unterminated frame was left behind.
    pub fn has_tail(&self) -> bool {
        !self.shared.state.lock().unwrap().bytes.is_empty()
    }

    /// Makes every write fail from here on, or work again.
    pub fn set_broken(&self, broken: bool) {
        self.shared.state.lock().unwrap().broken = broken;
    }

    /// Cuts the next write the point applies to, firing ahead of a broken
    /// transport.
    pub fn set_cut(&self, point: CutPoint) {
        let mut state = self.shared.state.lock().unwrap();
        state.cut = Some(point);
        state.timeout = false;
    }

    /// Expires the next matching write or flush after the same prefix as a cut.
    /// Returning TimedOut represents an exhausted operation budget without a
    /// wall-clock sleep, keeping timeout scenarios fast and deterministic.
    pub fn set_timeout(&self, point: CutPoint) {
        let mut state = self.shared.state.lock().unwrap();
        state.cut = Some(point);
        state.timeout = true;
    }

    /// Makes synthetic reads wait until the next reset and HostHello have both
    /// flushed. The real duplex scenarios exercise reading during those writes;
    /// this gate keeps model predictions and vector ordering deterministic.
    pub fn prepare_handshake(&self) {
        let mut state = self.shared.state.lock().unwrap();
        state.handshake = Some(state.flushes + 2);
    }

    /// Releases the synthetic prefix gate after a handshake returns, including
    /// one whose failed writer could not flush the prefix.
    pub fn finish_handshake(&self) {
        self.shared.state.lock().unwrap().handshake = None;
        self.shared.changed.notify_all();
    }

    /// Waits for the scripted handshake prefix, releasing the output lock while
    /// waiting. A failed writer never reaches its goal, so the read poll expires
    /// and lets the transport observe the writer's cancellation signal.
    pub fn await_handshake(&self, deadline: Instant) -> bool {
        // A short synthetic poll keeps failed-helper fuzz cases fast. Real
        // adapter deadline behavior is covered by the bounded duplex scenarios.
        let deadline = deadline.min(Instant::now() + Duration::from_millis(1));
        let mut state = self.shared.state.lock().unwrap();
        loop {
            match state.handshake {
                Some(goal) if state.flushes < goal => {}
                _ => {
                    state.handshake = None;
                    return true;
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            state = self
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap()
                .0;
        }
    }

    /// How much of a write the transport takes and whether it reports failure.
    /// An armed cut fires ahead of a broken transport, on the first write with
    /// enough of a body for it.
    fn accept(state: &mut OutputState, buf: &[u8]) -> (usize, Option<io::ErrorKind>) {
        if let Some(point) = state.cut {
            let accepted = match point {
                CutPoint::Start => Some(0),
                CutPoint::Middle(n) => (buf.len() > 2).then(|| 1 + (n as usize).min(buf.len() - 3)),
                CutPoint::Delimiter => (buf.len() > 1).then(|| buf.len() - 1),
                CutPoint::Flush => (buf.len() > 1).then_some(buf.len()),
            };
            if let Some(accepted) = accepted {
                state.cut = None;
                let error = match std::mem::take(&mut state.timeout) {
                    true => io::ErrorKind::TimedOut,
                    false => io::ErrorKind::BrokenPipe,
                };
                if point == CutPoint::Flush {
                    state.flush_error = Some(error);
                    return (accepted, None);
                }
                return (accepted, Some(error));
            }
        }
        if state.broken {
            return (0, Some(io::ErrorKind::BrokenPipe));
        }
        (buf.len(), None)
    }
}

impl Write for Outbox {
    fn set_write_deadline(&mut self, _deadline: Instant) -> io::Result<()> {
        // Scripted faults determine expiry without wall-clock delays.
        // A new frame may follow cancellation before a deferred failure was
        // observed; that failure belongs only to the previous frame's output.
        let mut state = self.shared.state.lock().unwrap();
        state.write_error = None;
        state.flush_error = None;
        Ok(())
    }
}

impl io::Write for Outbox {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.shared.state.lock().unwrap();
        if let Some(error) = state.write_error.take() {
            return Err(error.into());
        }
        let (accepted, error) = Self::accept(&mut state, buf);
        state.bytes.extend_from_slice(&buf[..accepted]);
        trace(&self.recorder, || match error {
            Some(io::ErrorKind::TimedOut) => Event::WriteTimedOut {
                bytes: buf[..accepted].to_vec(),
            },
            _ => Event::Write {
                bytes: buf[..accepted].to_vec(),
                failed: error.is_some(),
            },
        });
        // Keep one logical failed-write event in the transcript, while each
        // standard call reports progress before surfacing the deferred error.
        match error {
            Some(error) if accepted > 0 => {
                state.write_error = Some(error);
                Ok(accepted)
            }
            Some(error) => Err(error.into()),
            None => Ok(accepted),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        if let Some(error) = state.write_error.take() {
            return Err(error.into());
        }
        match state.flush_error.take() {
            Some(error) => {
                trace(&self.recorder, || match error {
                    io::ErrorKind::TimedOut => Event::FlushTimedOut,
                    _ => Event::FlushFailed,
                });
                Err(error.into())
            }
            None => {
                state.flushes += 1;
                self.shared.changed.notify_all();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    // Tests that a scripted partial failure follows the standard write contract:
    // accepted bytes return Ok(n), the next call fails without accepting more,
    // and a fresh frame can complete the prefix on the same adapter.
    #[test]
    fn test_partial_write_reports_progress_before_failure() {
        let mut outbox = Outbox::default();
        outbox.set_cut(CutPoint::Delimiter);
        outbox
            .set_write_deadline(Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(outbox.write(&[1, 2, 0]).unwrap(), 2);
        assert_eq!(
            outbox.write(&[0]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(outbox.take_frames().is_empty());
        assert!(outbox.has_tail());

        outbox
            .set_write_deadline(Instant::now() + Duration::from_secs(1))
            .unwrap();
        outbox.write_all(&[0]).unwrap();
        outbox.flush().unwrap();
        assert_eq!(outbox.take_frames(), vec![vec![1, 2]]);
    }

    // Tests cancellation between accepting bytes and observing a scripted error.
    // Starting another output operation discards the abandoned error, even when
    // it reuses the original deadline for a failure notification.
    #[test]
    fn test_new_output_discards_abandoned_fault() {
        for cut in [CutPoint::Delimiter, CutPoint::Flush] {
            let mut outbox = Outbox::default();
            let deadline = Instant::now() + Duration::from_secs(1);
            outbox.set_cut(cut);
            outbox.set_write_deadline(deadline).unwrap();
            assert!(outbox.write(&[1, 2, 0]).unwrap() > 0);

            outbox.set_write_deadline(deadline).unwrap();
            outbox.write_all(&[0]).unwrap();
            outbox.flush().unwrap();
            assert!(!outbox.take_frames().is_empty());
            assert!(!outbox.has_tail());
        }
    }
}

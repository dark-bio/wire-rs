// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Scripted mock peers and concurrent scenarios for the transport.
//!
//! Each mock drives one real peer through a sequence of frames and failures.
//! A state machine predicts the peer's reaction and panics on a mismatch.
//! Duplex scenarios run both real peers over bounded pipes. Tests and fuzzers
//! share these runners so a fuzz finding can become a regression test.

pub mod client;
pub mod duplex;
#[cfg(all(feature = "fuzz", getrandom_backend = "custom"))]
pub mod random;
#[cfg(feature = "fuzz")]
pub mod seed;
pub mod server;
pub mod vector;

use crate::transport::{Attestation, Error, MAX_MESSAGE_SIZE, Sender, Write};
use darkbio_clock::Clock;
use darkbio_cobs as cobs;
use darkbio_crypto::cwt::claims::{self, eat};
use darkbio_crypto::{cwt, xdsa};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vector::{Event, Vector};

/// Maximum steps run from one script, limiting the work in a fuzz iteration.
pub const MAX_STEPS: usize = 64;

/// Fixed signing timestamp used by mocks and drivers to keep recorded output
/// independent of the clock.
pub const TIMESTAMP: i64 = 0;

/// Handshake budget of the peer under test in the scripted runners.
///
/// The models predict every result from the script alone. The clock must
/// therefore never expire a handshake that a slow script is still feeding.
pub const SCRIPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3600);

/// Message one byte past [`MAX_MESSAGE_SIZE`], used to assert refusal without
/// advancing encryption or touching the writer.
///
/// It is a constant, so fuzz steps need no large allocation.
pub(super) const OVERSIZED_MESSAGE: &[u8] = &[0x42; MAX_MESSAGE_SIZE + 1];

/// Encodes a tag as eight big-endian bytes to identify a test message.
///
/// The transport treats this payload as opaque bytes.
pub fn payload(tag: u64) -> Vec<u8> {
    tag.to_be_bytes().to_vec()
}

/// Sends a message through a scripted sender, if there is one.
///
/// Without a sender, as before the first handshake, the call fails with the
/// same [`Error::EncryptionFailed`] an ended session returns. Drivers keep
/// ended senders around to exercise that refusal.
pub(super) fn send<W: Write>(sender: Option<&Sender<W>>, message: &[u8]) -> Result<(), Error> {
    match sender {
        Some(sender) => sender.send(message),
        None => Err(Error::EncryptionFailed("no active session".into())),
    }
}

/// Creates a self-signed device attestation for a server without onboarding.
///
/// It embeds the signer's public key, so the same signer must sign the
/// handshake.
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

/// Creates a cloud signer attestation under the device attestation domain.
///
/// Its claims have the wrong shape for a device, so the client rejects it
/// before calling the verifier.
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

/// Encodes a packet with COBS and appends its frame delimiter.
pub fn frame(packet: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; cobs::encode_buffer(packet.len())];
    let n = cobs::encode(packet, &mut buf).unwrap();
    buf.truncate(n);
    buf.push(0x00);
    buf
}

/// Decodes a COBS frame whose delimiter has already been removed.
///
/// # Panics
///
/// Panics if the frame is not valid COBS, as when the side under test wrote a
/// broken frame.
pub fn unframe(frame: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; cobs::decode_buffer(frame.len())];
    let n = cobs::decode(frame, &mut buf).expect("side under test wrote an undecodable frame");
    buf.truncate(n);
    buf
}

/// Returns the read error used when a script yields control to its driver.
pub fn would_block() -> io::Error {
    io::ErrorKind::WouldBlock.into()
}

/// Shared transcript for the current run.
///
/// It holds `None` when recording is off.
pub type Recorder = Arc<Mutex<Option<Vector>>>;

/// Logs an event into the transcript, if the run is recorded.
///
/// The closure runs only when recording, so unrecorded runs never build the
/// event.
pub fn trace(recorder: &Recorder, event: impl FnOnce() -> Event) {
    if let Some(vector) = recorder.lock().unwrap().as_mut() {
        vector.log(event());
    }
}

/// Point where a scripted output failure occurs.
///
/// A recovery delimiter belongs to the same write as its frame. Only
/// [`Start`](CutPoint::Start) applies to a lone delimiter.
/// [`Middle`](CutPoint::Middle) needs at least three bytes, while
/// [`Delimiter`](CutPoint::Delimiter) and [`Flush`](CutPoint::Flush) also
/// apply to a two-delimiter signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum CutPoint {
    /// Failure before any bytes are accepted.
    Start,
    /// Failure after `1 + min(n, len - 3)` bytes of a write at least three
    /// bytes long.
    ///
    /// An offset of zero accepts only the first byte, which is the recovery
    /// delimiter when one leads the write. Larger offsets clamp, leaving the
    /// final body byte and the frame delimiter unwritten.
    Middle(u16),
    /// Failure after everything but the final delimiter is accepted.
    Delimiter,
    /// Failure during the flush, after all bytes are accepted.
    Flush,
}

/// Output adapter capturing what the peer under test writes, for the mock to
/// consume.
///
/// Scripts can inject partial writes, timeouts and persistent write failures.
/// Clones share the captured bytes and the armed faults.
#[derive(Clone)]
pub struct Outbox {
    /// Clock shared with the scripted input adapter.
    clock: Clock,
    /// Captured bytes and armed faults, shared by every clone.
    shared: Arc<Mutex<OutputState>>,
    /// Transcript the writes are logged into, when the run is recorded.
    recorder: Recorder,
}

/// Captured bytes and injected faults under one lock.
#[derive(Default)]
struct OutputState {
    /// Accepted bytes not yet taken as frames.
    bytes: Vec<u8>,
    /// Whether writes fail with `BrokenPipe` until cleared.
    broken: bool,
    /// Cut armed for the next write it applies to.
    cut: Option<CutPoint>,
    /// Whether the armed cut reports `TimedOut` instead of `BrokenPipe`.
    timeout: bool,
    /// Error deferred to the call after a write that accepted bytes.
    write_error: Option<io::ErrorKind>,
    /// Error the next flush returns, armed by a [`CutPoint::Flush`] cut.
    flush_error: Option<io::ErrorKind>,
}

impl Outbox {
    /// Creates empty output on the scenario's clock, with recording off.
    pub fn new(clock: &Clock) -> Self {
        Self {
            clock: clock.clone(),
            shared: Arc::default(),
            recorder: Recorder::default(),
        }
    }

    /// Removes and returns all delimited frames, without their delimiters.
    ///
    /// Any unfinished tail stays until a later write supplies its delimiter.
    pub fn take_frames(&self) -> Vec<Vec<u8>> {
        let mut state = self.shared.lock().unwrap();
        // The final piece is the unfinished tail, or empty after a delimiter
        let mut frames: Vec<Vec<u8>> = state.bytes.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
        let tail = frames.pop().expect("split yields at least one piece");
        state.bytes = tail;
        frames
    }

    /// Reports whether captured output contains an unfinished frame.
    pub fn has_tail(&self) -> bool {
        !self.shared.lock().unwrap().bytes.is_empty()
    }

    /// Enables or clears a persistent write failure.
    pub fn set_broken(&self, broken: bool) {
        self.shared.lock().unwrap().broken = broken;
    }

    /// Arms a `BrokenPipe` failure for the next write this cut point applies to.
    ///
    /// The cut takes priority over a persistent write failure.
    pub fn set_cut(&self, point: CutPoint) {
        let mut state = self.shared.lock().unwrap();
        state.cut = Some(point);
        state.timeout = false;
    }

    /// Arms a timeout at the selected cut point.
    ///
    /// The failing write or flush reports `TimedOut` at once, whatever the
    /// deadline, so scripted timeout tests need no clock advances.
    pub fn set_timeout(&self, point: CutPoint) {
        let mut state = self.shared.lock().unwrap();
        state.cut = Some(point);
        state.timeout = true;
    }

    /// Chooses how many bytes of a write to accept and which error follows them.
    ///
    /// An applicable cut takes priority over a persistent write failure. A
    /// [`CutPoint::Flush`] cut accepts the write and arms its error for the
    /// flush instead.
    fn accept(state: &mut OutputState, buf: &[u8]) -> (usize, Option<io::ErrorKind>) {
        // Fire an armed cut if it applies to this write, disarming it
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

        // Without a cut, a broken stream refuses the whole write
        if state.broken {
            return (0, Some(io::ErrorKind::BrokenPipe));
        }
        (buf.len(), None)
    }
}

impl Write for Outbox {
    fn clock(&self) -> Clock {
        self.clock.clone()
    }

    fn set_write_deadline(&mut self, _deadline: Instant) -> io::Result<()> {
        // Scripted faults determine expiry without wall-clock delays.
        // Starting a new frame discards deferred errors from previous output.
        let mut state = self.shared.lock().unwrap();
        state.write_error = None;
        state.flush_error = None;
        Ok(())
    }
}

impl io::Write for Outbox {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Fail on an error deferred by the previous write
        let mut state = self.shared.lock().unwrap();
        if let Some(error) = state.write_error.take() {
            return Err(error.into());
        }

        // Capture the accepted prefix and log it together with any failure
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

        // The transcript records accepted bytes and failure as one event.
        // Standard I/O reports them separately, as `Ok(n)` and then an error.
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
        let mut state = self.shared.lock().unwrap();
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
            None => Ok(()),
        }
    }
}

/// Tests of the scripted output adapter.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::time::Duration;

    /// Tests that a scripted partial failure follows the standard write contract.
    ///
    /// Accepted bytes return `Ok(n)`, and the next call fails without accepting
    /// more. A fresh frame can then complete the prefix on the same adapter.
    #[test]
    fn test_partial_write_reports_progress_before_failure() {
        // Inject a partial failure on a paused clock
        let tester = crate::transport::testing::test_clock();
        let clock = tester.clock();
        let mut outbox = Outbox::new(&clock);
        outbox.set_cut(CutPoint::Delimiter);
        outbox
            .set_write_deadline(clock.now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(outbox.write(&[1, 2, 0]).unwrap(), 2);
        assert_eq!(
            outbox.write(&[0]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(outbox.take_frames().is_empty());
        assert!(outbox.has_tail());

        // Complete the partial frame with a fresh output operation
        outbox
            .set_write_deadline(clock.now() + Duration::from_secs(1))
            .unwrap();
        outbox.write_all(&[0]).unwrap();
        outbox.flush().unwrap();
        assert_eq!(outbox.take_frames(), vec![vec![1, 2]]);
    }

    /// Tests that starting new output discards the error of abandoned output.
    ///
    /// The new operation may reuse the original deadline, as a failure
    /// notification does.
    #[test]
    fn test_new_output_discards_abandoned_fault() {
        for cut in [CutPoint::Delimiter, CutPoint::Flush] {
            // Accept a prefix and leave its failure unobserved
            let tester = crate::transport::testing::test_clock();
            let clock = tester.clock();
            let mut outbox = Outbox::new(&clock);
            let deadline = clock.now() + Duration::from_secs(1);
            outbox.set_cut(cut);
            outbox.set_write_deadline(deadline).unwrap();
            assert!(outbox.write(&[1, 2, 0]).unwrap() > 0);

            // Start another output operation with the same deadline
            outbox.set_write_deadline(deadline).unwrap();
            outbox.write_all(&[0]).unwrap();
            outbox.flush().unwrap();
            assert!(!outbox.take_frames().is_empty());
            assert!(!outbox.has_tail());
        }
    }
}

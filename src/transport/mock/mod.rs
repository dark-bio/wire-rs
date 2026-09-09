// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

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
use darkbio_cobs as cobs;
use darkbio_crypto::cwt::claims::{self, eat};
use darkbio_crypto::{cwt, xdsa};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use vector::{Event, Vector};

/// Maximum steps run from one script, limiting the work in a fuzz iteration.
pub const MAX_STEPS: usize = 64;

/// Fixed signing timestamp used by mocks and drivers to keep recorded output
/// independent of the clock.
pub const TIMESTAMP: i64 = 0;

/// Message one byte past the send limit, used to assert refusal without advancing
/// encryption or touching the writer. Shared so fuzz steps need no large allocation.
pub(super) const OVERSIZED_MESSAGE: &[u8] = &[0x42; MAX_MESSAGE_SIZE + 1];

/// Encodes a tag as eight big-endian bytes to identify a test message.
/// The transport treats this payload as opaque bytes.
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

/// Creates a self-signed device attestation for a server without onboarding.
/// It embeds the server's handshake signing key.
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
/// Its claims have the wrong shape for a device, so the transport rejects it
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

/// COBS encodes a packet and appends its frame delimiter.
pub fn frame(packet: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; cobs::encode_buffer(packet.len())];
    let n = cobs::encode(packet, &mut buf).unwrap();
    buf.truncate(n);
    buf.push(0x00);
    buf
}

/// COBS decodes a frame whose delimiter has already been removed.
/// Panics if the side under test wrote an invalid frame.
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

/// Shared transcript for the current run. Contains `None` when recording is off.
pub type Recorder = Arc<Mutex<Option<Vector>>>;

/// Logs an event into the transcript, if the run is recorded.
pub fn trace(recorder: &Recorder, event: impl FnOnce() -> Event) {
    if let Some(vector) = recorder.lock().unwrap().as_mut() {
        vector.log(event());
    }
}

/// Point where a scripted output failure occurs.
/// A recovery delimiter belongs to the same write as its frame.
/// Only `Start` applies to a lone delimiter; `Middle` needs at least three bytes,
/// while `Delimiter` and `Flush` also apply to a two-delimiter signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum CutPoint {
    /// Fails before accepting any bytes.
    Start,
    /// Accepts `1 + min(n, len - 3)` bytes of a write at least three bytes long.
    /// Zero accepts its first byte, which can be only the recovery delimiter.
    /// Larger offsets clamp before the final body byte and frame delimiter.
    Middle(u16),
    /// Accepts everything except the final delimiter, then fails.
    Delimiter,
    /// Accepts all bytes, then fails during flush.
    Flush,
}

/// Captures output for the mock peer to consume.
/// Scripts can inject partial writes, timeouts and persistent write failures.
#[derive(Clone, Default)]
pub struct Outbox {
    shared: Arc<Mutex<OutputState>>,
    recorder: Recorder, // Transcript the writes are logged into
}

/// Captured bytes and injected faults under one lock.
#[derive(Default)]
struct OutputState {
    bytes: Vec<u8>,
    broken: bool,
    cut: Option<CutPoint>,
    timeout: bool,
    write_error: Option<io::ErrorKind>, // Deferred until the call after accepted bytes
    flush_error: Option<io::ErrorKind>,
}

impl Outbox {
    /// Removes and returns all delimited frames, without their delimiters.
    /// Keeps any unfinished tail until a later write supplies its delimiter.
    pub fn take_frames(&self) -> Vec<Vec<u8>> {
        let mut state = self.shared.lock().unwrap();
        // The final piece is the unfinished tail, or empty after a delimiter.
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

    /// Arms a failure for the next write to which this cut point applies.
    /// The cut takes priority over a persistent write failure.
    pub fn set_cut(&self, point: CutPoint) {
        let mut state = self.shared.lock().unwrap();
        state.cut = Some(point);
        state.timeout = false;
    }

    /// Arms a timeout at the selected cut point.
    /// Returns `TimedOut` without sleeping so scripted timeout tests stay fast.
    pub fn set_timeout(&self, point: CutPoint) {
        let mut state = self.shared.lock().unwrap();
        state.cut = Some(point);
        state.timeout = true;
    }

    /// Chooses how many bytes to accept and which error to report afterwards.
    /// An applicable cut takes priority over a persistent write failure.
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
        // Starting a new frame discards deferred errors from previous output.
        let mut state = self.shared.lock().unwrap();
        state.write_error = None;
        state.flush_error = None;
        Ok(())
    }
}

impl io::Write for Outbox {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.shared.lock().unwrap();
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
        // The transcript records accepted bytes and failure as one event.
        // Standard I/O reports them separately: Ok(n), then an error.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::time::Duration;

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

    // Tests abandoning output between accepting bytes and observing its error.
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

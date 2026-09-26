// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COBS framing over a raw byte stream, with independent reading and writing
//! halves.
//!
//! Frames end with a zero. COBS encoding removes zeros from the payload. The
//! byte stream need not report peer connections or disconnections. For
//! example, a WebUSB client may crash and reconnect without the server noticing.
//! Session boundaries therefore use signals in the byte stream itself.
//!
//! An empty frame is not valid COBS, so it serves as a session signal. A client
//! starts a handshake with two zeros. The first terminates any interrupted frame.
//! The second signals the reset. A server sends an empty frame when it has no
//! session for the input it received.
//!
//! A failed send may have put part of its frame on the stream already. The
//! next frame or signal starts with an extra delimiter to terminate that prefix.
//! A failed flush also requires this recovery delimiter. Some adapters report a
//! lost transfer only when flushed.

use crate::transport::io::check_deadline;
use crate::transport::stream::{ReadHalf, WriteHalf};
use crate::transport::{Closer, Error, MAX_FRAME_SIZE, Read, Write};
use darkbio_cobs as cobs;
use std::ops::Range;
use std::time::Instant;
use tracing::debug;

/// Reader that decodes frames from its own input buffers.
///
/// The writing half can run on another thread without sharing these buffers.
pub(crate) struct FrameReader<R: Read> {
    /// Input adapter with shutdown accounting.
    reader: ReadHalf<R>,

    /// Received bytes not yet consumed, holding partial or multiple frames.
    buffer: Vec<u8>,
    /// Number of received bytes in `buffer`.
    filled: usize,
    /// Start of the next frame in `buffer`.
    offset: usize,
    /// End of the region already checked for a delimiter, where the next
    /// search resumes.
    search: usize,
    /// Whether an oversized frame was reported and its remainder is still being
    /// discarded through the delimiter.
    discard: bool,

    /// Last decoded packet, handed out as a view until the next read.
    packet: Vec<u8>,
}

impl<R: Read> FrameReader<R> {
    /// Creates the reading half of a framed transport around a low level reader.
    pub fn new(reader: R, close: Closer) -> Self {
        Self {
            reader: ReadHalf {
                inner: reader,
                closer: close,
            },
            // The extra byte holds the delimiter or proves overflow
            buffer: vec![0u8; MAX_FRAME_SIZE + 1],
            filled: 0,
            offset: 0,
            search: 0,
            discard: false,
            packet: vec![0u8; MAX_FRAME_SIZE],
        }
    }

    /// Reads and decodes one packet, returning a view valid until the next read.
    ///
    /// An empty frame signals a session boundary and returns `None`. An encoded
    /// empty packet returns an empty slice instead.
    ///
    /// A handshake deadline applies to buffered frames and all read and discard
    /// progress. Expiry retains unread bytes for the next attempt. Buffered
    /// frames remain readable after closure, and needing more input then returns
    /// [`Error::Terminated`].
    #[inline]
    pub fn next_packet(&mut self, deadline: Option<Instant>) -> Result<Option<&[u8]>, Error> {
        // Find the next frame between zero delimiters
        let frame = self.next_frame(deadline)?;

        // An empty frame is a session signal, not a COBS packet
        if frame.start == frame.end {
            return Ok(None);
        }

        // Decode it with COBS. The framer split the stream at the first zero,
        // so the frame is guaranteed zero free and the cheaper decoder applies.
        let size = cobs::decode_nonzero(&self.buffer[frame.start..frame.end], &mut self.packet)
            .map_err(Error::FrameDecodingFailed)?;
        Ok(Some(&self.packet[..size]))
    }

    /// Finds the next frame and returns its range within `buffer` without
    /// copying.
    ///
    /// More than [`MAX_FRAME_SIZE`] nonzero bytes report an error immediately,
    /// before the frame's full length is known. Later calls discard the
    /// remainder through its delimiter. They neither report the frame again nor
    /// treat its delimiter as a reset. Read failures preserve this discard
    /// state.
    #[inline]
    fn next_frame(&mut self, deadline: Option<Instant>) -> Result<Range<usize>, Error> {
        'outer: loop {
            // Refuse to continue once the handshake deadline has passed
            if let Some(deadline) = deadline {
                check_deadline(&self.reader.inner.clock(), deadline).map_err(Error::RecvFailed)?;
            }

            // Search for the frame delimiter, starting from where we left off
            if let Some(found) = memchr::memchr(0, &self.buffer[self.search..self.filled]) {
                // Consume the frame and its delimiter from the buffer
                let start = self.offset;
                let end = self.search + found;

                self.offset = end + 1; // skip the zero marker
                self.search = end + 1; // skip the zero marker

                // The oversized frame was already reported. Its delimiter only
                // finishes the discard; any following zero remains a reset.
                if self.discard {
                    self.discard = false;
                    continue 'outer;
                }

                // The frame fits within the size limit
                return Ok(Range { start, end });
            }

            // The searched region is delimiter free, don't rescan it later
            self.search = self.filled;

            // Frame delimiter not found, we only have fragments
            if !self.discard {
                if self.offset > 0 {
                    // Move the partial frame to the start to make room for more input
                    let used = self.filled - self.offset;
                    self.buffer.copy_within(self.offset..self.filled, 0);
                    self.filled = used;
                    self.offset = 0;
                    self.search = used;
                }
            } else {
                // Discard this portion of the oversized frame
                self.filled = 0;
                self.offset = 0;
                self.search = 0
            }

            // A full delimiter-free buffer proves overflow. Report it before
            // reading further, retaining only the need to drain its remainder.
            if self.filled == MAX_FRAME_SIZE + 1 {
                self.discard = true;
                self.filled = 0;
                self.offset = 0;
                self.search = 0;
                return Err(Error::FrameTooLarge(MAX_FRAME_SIZE + 1));
            }

            // Read more data to try and find the next frame marker
            match self.reader.read(&mut self.buffer[self.filled..], deadline) {
                // Adapter or deadline setter failure
                Err(err) => {
                    debug!("wire read failed: {}", err);
                    return Err(Error::RecvFailed(err));
                }
                // EOF or permanent closure
                Ok(0) => {
                    debug!("wire stream ended");
                    return Err(Error::Terminated);
                }
                // Keep the newly read bytes
                Ok(n) => self.filled += n,
            }
        }
    }

    /// Reads an encoded frame as a slice for tests, benchmarks and fuzzing.
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_frame_blob(&mut self) -> Result<&[u8], Error> {
        let frame = self.next_frame(None)?;
        Ok(&self.buffer[frame])
    }
}

/// Writer that encodes frames into its own output buffer.
///
/// The reading half can run on another thread without sharing this buffer.
/// Every send takes one absolute deadline for writing and flushing. A flush
/// that returns after the deadline fails the complete frame.
pub(crate) struct FrameWriter<W: Write> {
    /// Output adapter with shutdown accounting.
    writer: WriteHalf<W>,

    /// Whether the last send failed or never finished, possibly leaving a frame
    /// unterminated.
    resync: bool,
    /// Leading recovery zero, encoded frame and trailing delimiter.
    frame: Vec<u8>,
}

impl<W: Write> FrameWriter<W> {
    /// Creates the writing half of a framed transport around a low level writer.
    pub fn new(writer: W, close: Closer) -> Self {
        Self {
            writer: WriteHalf {
                inner: writer,
                closer: close,
            },
            resync: false,
            frame: vec![0u8; MAX_FRAME_SIZE + 2], // recovery prefix and frame delimiter
        }
    }

    /// Signals a session reset with two zeros.
    ///
    /// The first terminates any partial frame, including one left by a previous
    /// client. The second forms the empty reset frame. No extra recovery
    /// delimiter is needed. Both bytes and flush share the supplied absolute
    /// deadline.
    pub fn send_reset(&mut self, deadline: Instant) -> Result<(), Error> {
        self.resync = false;

        // Send two zeros, one to finish an old frame and one to signal the reset
        self.frame[1] = 0;
        self.send_frame(1, deadline)
    }

    /// Signals a dropped session with an empty frame.
    ///
    /// After a failed send, an extra delimiter first terminates its partial
    /// frame. Both delimiters and flush share the supplied absolute deadline.
    pub fn send_dropped(&mut self, deadline: Instant) -> Result<(), Error> {
        // Send an empty frame, preceded by a recovery delimiter if needed
        self.send_frame(0, deadline)
    }

    /// Encodes a packet with COBS and sends it as a delimited frame.
    ///
    /// Packets whose maximum encoding size would exceed [`MAX_FRAME_SIZE`] are
    /// rejected with [`Error::FrameTooLarge`] before any output. Encoding, any
    /// recovery delimiter, partial writes and flush all share the supplied
    /// absolute deadline.
    #[inline]
    pub fn send_packet(&mut self, packet: &[u8], deadline: Instant) -> Result<(), Error> {
        // Encode the packet with COBS, refusing one whose worst case cannot fit
        let len = cobs::encode_buffer(packet.len());
        if len > MAX_FRAME_SIZE {
            return Err(Error::FrameTooLarge(len));
        }
        let size = cobs::encode(packet, &mut self.frame[1..=MAX_FRAME_SIZE])
            .expect("frame buffer holds any packet passing the size check");

        // Send the encoded frame with its trailing delimiter
        self.send_frame(size, deadline)
    }

    /// Writes and flushes `size` bytes starting at buffer index one, followed
    /// by a delimiter.
    ///
    /// After a failed send, the slice also includes the reserved leading zero
    /// to terminate the previous partial frame. The resync flag stays raised
    /// until writing and flushing succeed within the deadline. Transport reuse
    /// after a panic is unsupported.
    #[inline]
    fn send_frame(&mut self, size: usize, deadline: Instant) -> Result<(), Error> {
        // Index zero stays reserved for recovery; the frame begins at one
        self.frame[size + 1] = 0;
        let start = if std::mem::replace(&mut self.resync, true) {
            0
        } else {
            1
        };
        let result = self.writer.write(&self.frame[start..size + 2], deadline);

        // Fail the frame if output finished late. Individual writes must still
        // report accepted bytes even when they return after the deadline.
        let result = check_deadline(&self.writer.inner.clock(), deadline).and(result);

        // The next send needs a recovery delimiter if this one failed
        self.resync = result.is_err();
        result.map_err(Error::SendFailed)
    }

    /// Writes an encoded frame from a slice for tests, benchmarks and fuzzing.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is longer than [`MAX_FRAME_SIZE`].
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), Error> {
        assert!(bytes.len() <= MAX_FRAME_SIZE, "frame fits the send buffer");
        self.frame[1..bytes.len() + 1].copy_from_slice(bytes);
        self.send_frame(bytes.len(), deadline)
    }
}

/// Checks frame encoding and decoding, oversized frames, recovery delimiters
/// and deadlines.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::DEFAULT_WRITE_TIMEOUT;
    use crate::transport::testing::{Memory, test_clock};
    use darkbio_clock::Clock;
    use std::collections::VecDeque;
    use std::io::{self, Cursor};
    use std::panic::{self, AssertUnwindSafe};
    use std::time::{Duration, Instant};

    /// Checks that an expired attempt leaves a frame buffered by an earlier
    /// read for the next attempt to find.
    #[test]
    fn test_deadline_preserves_buffered_frames() {
        // Buffer two frames on a paused clock and consume the first
        let tester = test_clock();
        let clock = tester.clock();
        let mut reader = FrameReader::new(
            Memory::new(&[2, 1, 0, 2, 2, 0][..], &clock),
            Closer::new(&clock, || {}),
        );
        assert_eq!(reader.next_packet(None).unwrap(), Some(&[1][..]));

        // Reject the expired attempt without consuming the second frame
        assert!(matches!(
            reader.next_packet(Some(clock.now())),
            Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(reader.next_packet(None).unwrap(), Some(&[2][..]));
    }

    /// Checks that bytes from a late read stay in the framer when their attempt
    /// expires, for both a partial and a complete frame.
    #[test]
    fn test_deadline_preserves_late_read_bytes() {
        /// Reader whose first read returns a prefix of its input only at the
        /// installed deadline.
        struct LateReader {
            /// Clock governing the delayed read.
            clock: Clock,
            /// Encoded frame the reader hands out.
            input: Cursor<Vec<u8>>,
            /// Length of the late first read, taken when it happens.
            first: Option<usize>,
            /// Latest installed read deadline.
            deadline: Option<Instant>,
        }
        impl Read for LateReader {
            fn clock(&self) -> Clock {
                self.clock.clone()
            }

            fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
                self.deadline = deadline;
                Ok(())
            }
        }
        impl io::Read for LateReader {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                let len = if let Some(len) = self.first.take() {
                    self.clock.sleep_until(self.deadline.unwrap());
                    len.min(bytes.len())
                } else {
                    bytes.len()
                };
                io::Read::read(&mut self.input, &mut bytes[..len])
            }
        }
        for first in [1, 3] {
            // Start a read that returns bytes only after its deadline
            let mut tester = test_clock();
            let clock = tester.clock();
            let deadline = clock.now() + Duration::from_millis(20);
            let mut reader = FrameReader::new(
                LateReader {
                    clock: clock.clone(),
                    input: Cursor::new(vec![2, 42, 0]),
                    first: Some(first),
                    deadline: None,
                },
                Closer::new(&clock, || {}),
            );
            let result = std::thread::scope(|scope| {
                let reading = scope.spawn(|| reader.next_packet(Some(deadline)).map(|_| ()));
                tester.wait_blocked(1);
                tester.advance_to(deadline);
                reading.join().unwrap()
            });

            // Preserve the late bytes for a new attempt
            assert!(matches!(result,
                Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::TimedOut
            ));
            assert_eq!(reader.next_packet(None).unwrap(), Some(&[42][..]));
        }
    }

    /// Checks that expiry while discarding an oversized frame keeps the discard
    /// state, so the frame's tail is never served as a frame or a reset.
    #[test]
    fn test_deadline_preserves_oversized_discard() {
        // Reject an oversized prefix on a paused clock
        let tester = test_clock();
        let clock = tester.clock();
        let mut input = vec![1; MAX_FRAME_SIZE + 1];
        input.extend_from_slice(&[1, 0, 2, 42, 0]);
        let mut reader = FrameReader::new(
            Memory::new(Cursor::new(input), &clock),
            Closer::new(&clock, || {}),
        );
        assert!(matches!(
            reader.next_packet(None),
            Err(Error::FrameTooLarge(_))
        ));

        // Keep discarding across expiry until the original delimiter arrives
        assert!(matches!(
            reader.next_packet(Some(clock.now())),
            Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(reader.next_packet(None).unwrap(), Some(&[42][..]));
    }

    /// Checks that closing leaves complete buffered frames readable before
    /// reporting EOF.
    #[test]
    fn test_close_drains_buffered_frames() {
        // Read one frame while leaving another buffered
        let tester = test_clock();
        let clock = tester.clock();
        let closer = Closer::new(&clock, || {});
        let mut reader = FrameReader::new(
            Memory::new(&[0x02, 1, 0, 0x02, 2, 0][..], &clock),
            closer.clone(),
        );
        assert_eq!(reader.next_packet(None).unwrap(), Some(&[1][..]));

        // Drain the buffered frame after closure before reporting EOF
        closer.close();
        assert_eq!(reader.next_packet(None).unwrap(), Some(&[2][..]));
        assert!(matches!(reader.next_packet(None), Err(Error::Terminated)));
    }

    /// Checks decoding of empty packets, embedded zeros and COBS length
    /// boundaries.
    #[test]
    fn test_next_packet() {
        // Define framing boundaries on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();

        /// Input and expected result for one framing boundary case.
        struct TestCase {
            /// Encoded frame with its delimiter.
            input: Vec<u8>,
            /// Decoded packet, or `None` if the frame fails to decode.
            expected: Option<Vec<u8>>,
        }
        let tests = [
            // Empty packet, no zeroes encoded
            TestCase {
                input: [0x01, 0x00].to_vec(),
                expected: Some(b"".to_vec()),
            },
            // Simple packet, no zeroes encoded
            TestCase {
                input: [0x04, 0x66, 0x6f, 0x6f, 0x00].to_vec(),
                expected: Some(b"foo".to_vec()),
            },
            // Simple packet, various zeroes
            TestCase {
                input: [0x02, 0x0a, 0x01, 0x01, 0x01, 0x00].to_vec(),
                expected: Some([0x0a, 0x00, 0x00, 0x00].to_vec()),
            },
            // A COBS run holds at most 254 payload bytes. Decode a full run.
            TestCase {
                input: std::iter::once(0xff)
                    .chain(1..=0xfe)
                    .chain(std::iter::once(0x00))
                    .collect(),
                expected: Some((1..=0xfe).collect()),
            },
            // A 255-byte payload spans two COBS runs. Decode both together.
            TestCase {
                input: std::iter::once(0xff)
                    .chain(1..=0xfe)
                    .chain([0x02, 0xff, 0x00])
                    .collect(),
                expected: Some((1..=0xff).collect()),
            },
            // A COBS code promising more bytes than the frame carries fails
            TestCase {
                input: [0xff, 0x01, 0x00].to_vec(),
                expected: None,
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            // Decode each packet and compare it with the independent wire fixture
            let mut host_to_wire = Cursor::new(tt.input);
            let mut framing = FrameReader::new(
                Memory::new(&mut host_to_wire, &clock),
                Closer::new(&clock, || {}),
            );
            match tt.expected {
                Some(expected) => {
                    let packet = framing
                        .next_packet(None)
                        .unwrap()
                        .expect("expected a COBS packet");
                    assert_eq!(packet, expected, "test {i}");
                }
                None => {
                    let result = framing.next_packet(None);
                    assert!(
                        matches!(result, Err(Error::FrameDecodingFailed(_))),
                        "test {i}: {result:?}"
                    );
                }
            }
        }
    }

    /// Checks encoding at COBS length boundaries, and that a packet too large
    /// for the frame buffer is refused before output.
    #[test]
    fn test_send_packet() {
        // Define encoding boundaries on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();

        /// Input and expected result for one framing boundary case.
        struct TestCase {
            /// Packet to encode.
            input: Vec<u8>,
            /// Bytes on the wire, or `None` if the packet is refused.
            expected: Option<Vec<u8>>,
        }
        let tests = [
            // Empty packet, no zeroes encoded
            TestCase {
                input: b"".to_vec(),
                expected: Some([0x01, 0x00].to_vec()),
            },
            // Simple packet, no zeroes encoded
            TestCase {
                input: b"foo".to_vec(),
                expected: Some([0x04, 0x66, 0x6f, 0x6f, 0x00].to_vec()),
            },
            // Simple packet, various zeroes
            TestCase {
                input: [0x0a, 0x00, 0x00, 0x00].to_vec(),
                expected: Some([0x02, 0x0a, 0x01, 0x01, 0x01, 0x00].to_vec()),
            },
            // A COBS run holds at most 254 payload bytes. Encode a full run.
            TestCase {
                input: (1..=0xfe).collect(),
                expected: Some(
                    std::iter::once(0xff)
                        .chain(1..=0xfe)
                        .chain(std::iter::once(0x00))
                        .collect(),
                ),
            },
            // A 255-byte payload must be split across two COBS runs
            TestCase {
                input: (1..=0xff).collect(),
                expected: Some(
                    std::iter::once(0xff)
                        .chain(1..=0xfe)
                        .chain([0x02, 0xff, 0x00])
                        .collect(),
                ),
            },
            // A packet whose encoding would not fit a frame is refused up front
            TestCase {
                input: vec![0x01; MAX_FRAME_SIZE],
                expected: None,
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            // Encode each packet within a fixed clock deadline
            let mut wire_to_host = Cursor::new(Vec::<u8>::new());
            let mut framing = FrameWriter::new(
                Memory::new(&mut wire_to_host, &clock),
                Closer::new(&clock, || {}),
            );
            match tt.expected {
                Some(expected) => {
                    framing
                        .send_packet(&tt.input, clock.now() + DEFAULT_WRITE_TIMEOUT)
                        .unwrap();

                    let written = &wire_to_host.get_ref()[..];
                    assert_eq!(written, expected, "test {i}");
                }
                None => {
                    let result =
                        framing.send_packet(&tt.input, clock.now() + DEFAULT_WRITE_TIMEOUT);
                    assert!(
                        matches!(result, Err(Error::FrameTooLarge(_))),
                        "test {i}: {result:?}"
                    );
                    assert!(wire_to_host.get_ref().is_empty(), "test {i}");
                }
            }
        }
    }

    /// Checks reading empty, small and maximum-sized frames from the byte
    /// stream.
    #[test]
    fn test_next_frame() {
        // Define raw frame boundaries on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();

        /// Raw input and the frame it must deliver.
        struct TestCase {
            /// Bytes on the wire, delimiter included.
            input: Vec<u8>,
            /// Frame the reader must deliver, without its delimiter.
            expected: Vec<u8>,
        }
        let tests = [
            // Empty packet
            TestCase {
                input: b"\0".to_vec(),
                expected: b"".to_vec(),
            },
            // Simple packet
            TestCase {
                input: b"foo\0".to_vec(),
                expected: b"foo".to_vec(),
            },
            // A frame at the exact size limit is accepted
            TestCase {
                input: std::iter::repeat_n(b'a', MAX_FRAME_SIZE)
                    .chain(std::iter::once(0))
                    .collect(),
                expected: vec![b'a'; MAX_FRAME_SIZE],
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            // Read the entire delimited frame through the memory adapter
            let mut host_to_wire = Cursor::new(tt.input);
            let mut framing = FrameReader::new(
                Memory::new(&mut host_to_wire, &clock),
                Closer::new(&clock, || {}),
            );
            let frame = framing.next_frame_blob().unwrap();
            assert_eq!(frame, tt.expected, "test {i}");
        }
    }

    /// Checks that each oversized frame reports one error, even across several
    /// buffers, while its terminator is consumed and later frames and resets
    /// survive.
    ///
    /// A preceding frame also exercises buffer compaction.
    #[test]
    fn test_next_frame_oversized() {
        // Surround oversized frames with valid frames and resets
        let tester = test_clock();
        let clock = tester.clock();
        let mut input = b"before\0".to_vec();
        for size in [MAX_FRAME_SIZE + 1, 2 * MAX_FRAME_SIZE + 15] {
            input.extend(std::iter::repeat_n(b'a', size));
            input.extend_from_slice(b"\0after\0\0");
        }
        let mut framing = FrameReader::new(
            Memory::new(Cursor::new(input), &clock),
            Closer::new(&clock, || {}),
        );

        // Report each oversized frame once and preserve its successors
        assert_eq!(framing.next_frame_blob().unwrap(), b"before");
        for _ in 0..2 {
            assert!(matches!(
                framing.next_frame_blob(),
                Err(Error::FrameTooLarge(size)) if size == MAX_FRAME_SIZE + 1
            ));
            assert_eq!(framing.next_frame_blob().unwrap(), b"after");
            assert!(framing.next_packet(None).unwrap().is_none());
        }
        assert!(matches!(framing.next_frame_blob(), Err(Error::Terminated)));
    }

    /// Checks that read failures and EOF keep the discard state of an oversized
    /// frame, so the next call resumes discarding instead of serving its tail.
    ///
    /// Overflow must be reported before another read, even without a delimiter.
    #[test]
    fn test_next_frame_discard_resumes() {
        // Define interrupted discard cases on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();

        /// Reader handing out one mock result per read.
        struct Mock(
            /// Results still to hand out, in order.
            VecDeque<io::Result<Vec<u8>>>,
        );

        impl io::Read for Mock {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                match self.0.pop_front() {
                    Some(Ok(bytes)) => {
                        buf[..bytes.len()].copy_from_slice(&bytes);
                        Ok(bytes.len())
                    }
                    Some(Err(err)) => Err(err),
                    None => Ok(0),
                }
            }
        }

        let interrupted = || io::Error::from(io::ErrorKind::Interrupted);
        let timeout = || io::Error::from(io::ErrorKind::WouldBlock);

        /// Adapter results from the oversized prefix on, and the frames or read
        /// failures expected after the initial size error.
        struct TestCase {
            /// Adapter results, starting with the oversized prefix.
            reads: Vec<io::Result<Vec<u8>>>,
            /// Frame served per call after the size error, or `None` for a
            /// read failure.
            expected: Vec<Option<Vec<u8>>>,
        }
        let tests = [
            // An interrupted read resumes the discard of an oversized frame
            TestCase {
                reads: vec![
                    Ok(vec![b'a'; MAX_FRAME_SIZE + 1]),
                    Err(interrupted()),
                    Ok(b"aaa\0foo\0".to_vec()),
                ],
                expected: vec![Some(b"foo".to_vec())],
            },
            // A failed read returns its error. The next call resumes discarding.
            TestCase {
                reads: vec![
                    Ok(vec![b'a'; MAX_FRAME_SIZE + 1]),
                    Err(timeout()),
                    Ok(b"aaa\0foo\0".to_vec()),
                ],
                expected: vec![None, Some(b"foo".to_vec())],
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            // Report the oversized prefix, then serve each expected result
            let mut framing = FrameReader::new(
                Memory::new(Mock(tt.reads.into()), &clock),
                Closer::new(&clock, || {}),
            );
            assert!(matches!(
                framing.next_frame_blob(),
                Err(Error::FrameTooLarge(size)) if size == MAX_FRAME_SIZE + 1
            ));
            for (j, expected) in tt.expected.into_iter().enumerate() {
                let result = framing.next_frame_blob().map(<[u8]>::to_vec);
                match expected {
                    Some(frame) => assert_eq!(result.unwrap(), frame, "test {i} call {j}"),
                    None => assert!(
                        matches!(result, Err(Error::RecvFailed(_))),
                        "test {i} call {j}: {result:?}"
                    ),
                }
            }
        }

        // EOF while discarding does not make a later tail into a fresh frame
        let reads = vec![
            Ok(vec![b'a'; MAX_FRAME_SIZE + 1]),
            Ok(Vec::new()),
            Ok(b"tail\0foo\0".to_vec()),
        ];
        let mut framing = FrameReader::new(
            Memory::new(Mock(reads.into()), &clock),
            Closer::new(&clock, || {}),
        );
        assert!(matches!(
            framing.next_frame_blob(),
            Err(Error::FrameTooLarge(size)) if size == MAX_FRAME_SIZE + 1
        ));
        assert!(matches!(framing.next_frame_blob(), Err(Error::Terminated)));
        assert_eq!(framing.next_frame_blob().unwrap(), b"foo");
    }

    /// Checks raw frame output with and without the recovery prefix, up to a
    /// maximum-sized frame that fills the entire combined buffer.
    #[test]
    fn test_send_frame() {
        // Define raw output boundaries on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();

        /// Input and expected result for one framing boundary case.
        struct TestCase {
            /// Encoded frame to write, without its delimiter.
            input: &'static [u8],
            /// Bytes on the wire without the recovery prefix.
            expected: Vec<u8>,
        }
        let tests = [
            // Empty packet
            TestCase {
                input: b"",
                expected: b"\0".to_vec(),
            },
            // Simple packet
            TestCase {
                input: b"foo",
                expected: b"foo\0".to_vec(),
            },
            // A frame at the exact size limit is accepted
            TestCase {
                input: &[b'a'; MAX_FRAME_SIZE],
                expected: std::iter::repeat_n(b'a', MAX_FRAME_SIZE)
                    .chain(std::iter::once(0))
                    .collect(),
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            for resync in [false, true] {
                // Write each frame with and without a pending recovery prefix
                let mut wire_to_host = Vec::new();
                let mut framing = FrameWriter::new(
                    Memory::new(&mut wire_to_host, &clock),
                    Closer::new(&clock, || {}),
                );
                framing.resync = resync;
                framing
                    .send_frame_blob(tt.input, clock.now() + DEFAULT_WRITE_TIMEOUT)
                    .unwrap();

                // Expect the recovery zero ahead of the frame only when resyncing
                let mut expected = Vec::new();
                if resync {
                    expected.push(0);
                }
                expected.extend_from_slice(&tt.expected);
                assert_eq!(wire_to_host, expected, "test {i}, resync {resync}");
            }
        }
    }

    /// Checks that a successful flush returning after the deadline fails its
    /// frame, and the next send resynchronizes the adapter with a fresh budget.
    #[test]
    fn test_late_flush_resynchronizes() {
        /// Writer delaying one flush until its deadline has elapsed.
        ///
        /// It models a successful adapter call whose return was scheduled late.
        struct LateFlush {
            /// Clock governing the delayed flush.
            clock: Clock,
            /// Bytes accepted so far.
            bytes: Vec<u8>,
            /// Latest installed write deadline.
            deadline: Option<Instant>,
            /// Whether the next flush sleeps until the deadline.
            delay: bool,
        }

        impl Write for LateFlush {
            fn clock(&self) -> Clock {
                self.clock.clone()
            }

            fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
                self.deadline = Some(deadline);
                Ok(())
            }
        }

        impl io::Write for LateFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                if std::mem::take(&mut self.delay) {
                    let deadline = self.deadline.expect("deadline installed");
                    self.clock.sleep_until(deadline);
                }
                Ok(())
            }
        }

        // Park a flush until its frame deadline on the paused clock
        let mut tester = test_clock();
        let clock = tester.clock();
        let mut framing = FrameWriter::new(
            LateFlush {
                clock: clock.clone(),
                bytes: Vec::new(),
                deadline: None,
                delay: true,
            },
            Closer::new(&clock, || {}),
        );
        let deadline = clock.now() + Duration::from_millis(100);
        let result = std::thread::scope(|scope| {
            let writing = scope.spawn(|| framing.send_frame_blob(b"old", deadline));
            tester.wait_blocked(1);
            tester.advance_to(deadline);
            writing.join().unwrap()
        });
        assert!(
            matches!(result, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut)
        );
        assert_eq!(framing.writer.inner.bytes, b"old\0");

        // Resynchronize the next send with a fresh deadline
        framing
            .send_frame_blob(b"new", clock.now() + DEFAULT_WRITE_TIMEOUT)
            .unwrap();
        assert_eq!(framing.writer.inner.bytes, b"old\0\0new\0");
    }

    /// Checks that a writer panic leaves the recovery flag raised, so the
    /// framer's next send starts with a recovery delimiter.
    ///
    /// Catching the panic here lets the test inspect the next send's delimiter.
    /// Reusing a complete transport after a panic is not supported.
    #[test]
    fn test_send_panic() {
        // Prepare a writer that panics once on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();

        /// Writer panicking on its first write and collecting the ones after.
        struct Panicky {
            /// Whether the next write panics.
            armed: bool,
            /// Bytes accepted after the panic.
            written: Vec<u8>,
        }

        impl io::Write for Panicky {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if std::mem::take(&mut self.armed) {
                    panic!("injected panic");
                }
                self.written.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut framing = FrameWriter::new(
            Memory::new(
                Panicky {
                    armed: true,
                    written: Vec::new(),
                },
                &clock,
            ),
            Closer::new(&clock, || {}),
        );
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            framing.send_packet(&[1, 2, 3], clock.now() + DEFAULT_WRITE_TIMEOUT)
        }));
        assert!(result.is_err());

        // Require a recovery delimiter when the isolated framer is reused
        framing
            .send_packet(&[1, 2, 3], clock.now() + DEFAULT_WRITE_TIMEOUT)
            .unwrap();
        assert_eq!(
            framing.writer.inner.inner.written,
            [0x00, 0x04, 1, 2, 3, 0x00]
        );
    }
}

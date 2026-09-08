// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

//! COBS framer over a raw byte stream, a reading half and a writing half.
//! Frames are zero delimited, with any zero in the payload encoded away.
//!
//! The stream is assumed to carry no connection lifecycle, as USB bulk transfers
//! lack it by design. E.g A client may attach via WebUSB, crash or reconnect
//! without the server noticing. Session boundaries have to be signaled in band.
//!
//! Since an empty frame is not valid COBS, it is used to mark a session reset.
//! A client opens a session with two zeros, the first terminating whatever frame
//! may have been interrupted, the second being the reset. A server answers with
//! a single zero whenever it has no session for what it received.
//!
//! A failed send may have put part of its frame on the stream already. The
//! next send, a frame or a signal, starts with an extra delimiter terminating
//! that leftover. A failed flush counts as a failed send, as some transports
//! only report a lost transfer there.

use crate::transport::io::check_deadline;
use crate::transport::stream::{ReadHalf, WriteHalf};
use crate::transport::{Closer, Error, MAX_FRAME_SIZE, Read, Write};
use darkbio_cobs as cobs;
use std::ops::Range;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

/// Reading half of the framer, the frames coming in and the buffers receiving
/// and decoding them. It stands on its own, so a session can read on one
/// thread while writing on another.
pub(crate) struct FrameReader<R: Read> {
    reader: ReadHalf<R>, // Byte stream frames are read from, guarded by its close handle

    buffer: Vec<u8>, // Received bytes not yet consumed, partial or multiple frames
    filled: usize,   // Number of received bytes in buffer
    offset: usize,   // Start of the unconsumed data, i.e. of the next frame
    search: usize,   // End of the unconsumed data already scanned for a delimiter
    discard: bool,   // An oversized frame was reported; discard its remainder through the delimiter

    packet: Vec<u8>, // Last decoded packet, handed out as a view until the next read
}

impl<R: Read> FrameReader<R> {
    /// Creates the reading half of a framed transport around a low level reader.
    pub fn new(reader: R, close: Closer) -> Self {
        Self {
            reader: ReadHalf {
                inner: reader,
                closer: close,
            },
            buffer: vec![0u8; MAX_FRAME_SIZE + 1], // one extra slot for the frame delimiter
            filled: 0,
            offset: 0,
            search: 0,
            discard: false,
            packet: vec![0u8; MAX_FRAME_SIZE],
        }
    }

    /// Reads the next frame and COBS decodes it, returning the packet as a view
    /// valid until the next read. An empty frame is not COBS but a session reset
    /// signal and yields `None`; a genuinely empty packet decodes to an empty
    /// view. Complete buffered frames remain available after stream closure;
    /// needing another read observes EOF. An oversized frame returns
    /// [`Error::FrameTooLarge`] once, with later calls discarding its remainder.
    /// Setting the optional reconnect flag cancels further reads for that attempt;
    /// ordinary idle adapter timeouts are retried without losing buffered input.
    #[inline]
    pub fn next_packet(&mut self, canceled: Option<&AtomicBool>) -> Result<Option<&[u8]>, Error> {
        // Retrieve the next 0-bounded frame and pull out the data
        let frame = self.next_frame(canceled)?;

        // Empty frame is a session reset signal, it's not valid COBS
        if frame.start == frame.end {
            return Ok(None);
        }
        // Decode it with COBS. The framer split the stream at the first zero,
        // so the frame is guaranteed zero free and the cheaper decoder applies.
        let size = cobs::decode_nonzero(&self.buffer[frame.start..frame.end], &mut self.packet)
            .map_err(Error::FrameDecodingFailed)?;
        Ok(Some(&self.packet[..size]))
    }

    /// Reads the next zero delimited frame, returning its range within `buffer`
    /// so callers can parse it without copying. Crossing MAX_FRAME_SIZE reports
    /// an error immediately, before the frame's full length is known. Later
    /// calls discard the remainder through its delimiter without reporting the
    /// same frame again or treating that delimiter as a reset. Read failures
    /// preserve the discard state; interrupted reads are retried.
    #[inline]
    fn next_frame(&mut self, canceled: Option<&AtomicBool>) -> Result<Range<usize>, Error> {
        'outer: loop {
            // Search for the frame delimiter, starting from where we left off
            if let Some(found) = memchr::memchr(0, &self.buffer[self.search..self.filled]) {
                // Found the end of the frame, consume it from the buffer
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
                // We were in normal operation, return the consumed frame
                return Ok(Range { start, end });
            }
            // The searched region is delimiter free, don't rescan it later
            self.search = self.filled;

            // Frame delimiter not found, we only have fragments
            if !self.discard {
                if self.offset > 0 {
                    // We're in waiting mode, compact the buffer to maximise free space
                    let used = self.filled - self.offset;
                    self.buffer.copy_within(self.offset..self.filled, 0);
                    self.filled = used;
                    self.offset = 0;
                    self.search = used;
                }
            } else {
                // We're in discard mode, throw everything away
                self.filled = 0;
                self.offset = 0;
                self.search = 0
            }
            // A full delimiter-free buffer proves overflow. Report it before
            // reading any more, retaining only the need to drain its remainder.
            if self.filled == MAX_FRAME_SIZE + 1 {
                self.discard = true;
                self.filled = 0;
                self.offset = 0;
                self.search = 0;
                return Err(Error::FrameTooLarge(MAX_FRAME_SIZE + 1));
            }
            // Read more data to try and find the next frame marker
            match self.reader.read(&mut self.buffer[self.filled..], canceled) {
                Err(err) => return Err(Error::RecvFailed(err)), // Surface the adapter or configuration failure
                Ok(0) => return Err(Error::Terminated), // Transport was terminated, tear down
                Ok(n) => self.filled += n,              // Read some bytes, ingest them
            }
        }
    }

    /// Test and benchmark helper exposing `next_frame` with the raw frame as a
    /// slice.
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_frame_blob(&mut self) -> Result<&[u8], Error> {
        let frame = self.next_frame(None)?;
        Ok(&self.buffer[frame])
    }
}

/// Writing half of the framer, the frames going out and the buffer encoding
/// them. It stands on its own, so a session can write on one thread while
/// reading on another.
///
/// Every send takes an absolute deadline and optional cancellation flag.
/// Observing a set flag refuses further adapter calls; admitted calls may
/// finish normally. Deadline expiry also fails a frame whose flush returns late.
pub(crate) struct FrameWriter<W: Write> {
    writer: WriteHalf<W>, // Byte stream frames are written to, guarded by its close handle

    resync: bool, // Whether the last send failed, possibly leaving a frame unterminated
    frame: Vec<u8>, // Leading recovery zero, encoded frame, trailing delimiter
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

    /// Signals a session reset by writing two frame delimiters, the first one
    /// terminating any interrupted frame, the second forming the empty reset
    /// frame. The first covers a frame a previous client may have left behind,
    /// so a reset resyncs the stream by itself. Both bytes and flush share the
    /// supplied absolute deadline.
    pub fn send_reset(
        &mut self,
        deadline: Instant,
        canceled: Option<&AtomicBool>,
    ) -> Result<(), Error> {
        self.resync = false;

        // Piggyback on the frame sender which turn this into 2 zero-frames
        self.frame[1] = 0;
        self.send_frame(1, deadline, canceled)
    }

    /// Signals a dropped session by writing a single frame delimiter, forming
    /// an empty frame. After a failed send it goes out behind the delimiter
    /// terminating what that send left behind, so it is not swallowed as one.
    /// The resynchronization delimiter also uses the supplied absolute deadline.
    pub fn send_dropped(
        &mut self,
        deadline: Instant,
        canceled: Option<&AtomicBool>,
    ) -> Result<(), Error> {
        // Piggyback on the frame sender which turn this into 1 zero-frame
        self.send_frame(0, deadline, canceled)
    }

    /// COBS encodes a packet and sends it as a delimited frame. Packets whose
    /// encoding would exceed MAX_FRAME_SIZE are rejected. Encoding, any resync
    /// delimiter, all partial writes and flush share the supplied absolute deadline.
    #[inline]
    pub fn send_packet(
        &mut self,
        packet: &[u8],
        deadline: Instant,
        canceled: Option<&AtomicBool>,
    ) -> Result<(), Error> {
        // Encode the packet with COBS and send it as a frame
        let len = cobs::encode_buffer(packet.len());
        if len > MAX_FRAME_SIZE {
            return Err(Error::FrameTooLarge(len));
        }
        let size = cobs::encode(packet, &mut self.frame[1..=MAX_FRAME_SIZE])
            .expect("frame buffer holds any packet passing the size check");

        // Send the frame into the 0-bounded stream
        self.send_frame(size, deadline, canceled)
    }

    /// Writes and flushes `size` bytes starting at buffer index one, followed
    /// by a delimiter. After a failed send, the slice also includes the reserved
    /// leading zero to terminate the previous partial frame.
    /// The resync flag is raised while writing, so a panic leaves the next send
    /// responsible for terminating any partial frame.
    #[inline]
    fn send_frame(
        &mut self,
        size: usize,
        deadline: Instant,
        canceled: Option<&AtomicBool>,
    ) -> Result<(), Error> {
        // Index zero stays reserved for recovery; the frame begins at one.
        self.frame[size + 1] = 0;
        let start = if std::mem::replace(&mut self.resync, true) {
            0
        } else {
            1
        };
        let result = self
            .writer
            .write(&self.frame[start..size + 2], deadline, canceled);

        // Apply late completion at the whole-frame boundary. Standard writes
        // must report any accepted bytes, including when a call finishes late.
        let result = check_deadline(deadline).and(result);

        // If anything went wrong, set the resync marker back
        self.resync = result.is_err();
        result.map_err(Error::SendFailed)
    }

    /// Test and benchmark helper exposing `send_frame` with the raw frame taken
    /// from a slice. Panics on frames larger than the send buffer.
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
        canceled: Option<&AtomicBool>,
    ) -> Result<(), Error> {
        assert!(bytes.len() <= MAX_FRAME_SIZE, "frame fits the send buffer");
        self.frame[1..bytes.len() + 1].copy_from_slice(bytes);
        self.send_frame(bytes.len(), deadline, canceled)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::DEFAULT_WRITE_TIMEOUT;
    use crate::transport::testing::Memory;
    use std::collections::VecDeque;
    use std::io::{self, Cursor};
    use std::panic::{self, AssertUnwindSafe};
    use std::time::{Duration, Instant};

    // Closing leaves complete buffered frames readable, then reports EOF.
    #[test]
    fn test_close_drains_buffered_frames() {
        let closer = Closer::new(|| {});
        let mut reader =
            FrameReader::new(Memory::new(&[0x02, 1, 0, 0x02, 2, 0][..]), closer.clone());
        assert_eq!(reader.next_packet(None).unwrap(), Some(&[1][..]));
        closer.close();
        assert_eq!(reader.next_packet(None).unwrap(), Some(&[2][..]));
        assert!(matches!(reader.next_packet(None), Err(Error::Terminated)));
    }

    // Tests corner-cases when consuming a packet from the framed transport.
    #[test]
    fn test_next_packet() {
        testing::init_tracing();

        /// Input and expected result for one framing boundary case.
        struct TestCase {
            input: Vec<u8>,
            expected: Option<Vec<u8>>, // Decoded packet, none if the frame fails to decode
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
            // A COBS run can contain a maximum of 255 non-zero bytes, check that
            // the max length chunk decodes correctly.
            TestCase {
                input: std::iter::once(0xff)
                    .chain(1..=0xfe)
                    .chain(std::iter::once(0x00))
                    .collect(),
                expected: Some((1..=0xfe).collect()),
            },
            // A COBS run can contain a maximum of 255 non-zero bytes, check that
            // exceeding that into multiple chunks succeeds decoding.
            TestCase {
                input: std::iter::once(0xff)
                    .chain(1..=0xfe)
                    .chain([0x02, 0xff, 0x00])
                    .collect(),
                expected: Some((1..=0xff).collect()),
            },
            // A COBS code promising more bytes than the frame carries fails.
            TestCase {
                input: [0xff, 0x01, 0x00].to_vec(),
                expected: None,
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            let mut host_to_wire = Cursor::new(tt.input);

            let mut framing = FrameReader::new(Memory::new(&mut host_to_wire), Closer::new(|| {}));
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

    // Tests corner-cases when injecting a packet into a framed transport.
    #[test]
    fn test_send_packet() {
        testing::init_tracing();

        /// Input and expected result for one framing boundary case.
        struct TestCase {
            input: Vec<u8>,
            expected: Option<Vec<u8>>, // Bytes on the wire, none if the packet is refused
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
            // A COBS run can contain a maximum of 255 non-zero bytes, check that
            // the max length chunk encodes correctly.
            TestCase {
                input: (1..=0xfe).collect(),
                expected: Some(
                    std::iter::once(0xff)
                        .chain(1..=0xfe)
                        .chain(std::iter::once(0x00))
                        .collect(),
                ),
            },
            // A COBS run can contain a maximum of 255 non-zero bytes, check that
            // exceeding that into multiple chunks succeeds encoding.
            TestCase {
                input: (1..=0xff).collect(),
                expected: Some(
                    std::iter::once(0xff)
                        .chain(1..=0xfe)
                        .chain([0x02, 0xff, 0x00])
                        .collect(),
                ),
            },
            // A packet whose encoding would not fit a frame is refused up front.
            TestCase {
                input: vec![0x01; MAX_FRAME_SIZE],
                expected: None,
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            let mut wire_to_host = Cursor::new(Vec::<u8>::new());

            let mut framing = FrameWriter::new(Memory::new(&mut wire_to_host), Closer::new(|| {}));
            match tt.expected {
                Some(expected) => {
                    framing
                        .send_packet(&tt.input, Instant::now() + DEFAULT_WRITE_TIMEOUT, None)
                        .unwrap();

                    let written = &wire_to_host.get_ref()[..];
                    assert_eq!(written, expected, "test {i}");
                }
                None => {
                    let result = framing.send_packet(
                        &tt.input,
                        Instant::now() + DEFAULT_WRITE_TIMEOUT,
                        None,
                    );
                    assert!(
                        matches!(result, Err(Error::FrameTooLarge(_))),
                        "test {i}: {result:?}"
                    );
                    assert!(wire_to_host.get_ref().is_empty(), "test {i}");
                }
            }
        }
    }

    // Tests corner-cases when consuming a frame from the raw transport.
    #[test]
    fn test_next_frame() {
        testing::init_tracing();

        /// Raw input and the frame it must deliver, including the size boundary.
        struct TestCase {
            input: Vec<u8>,
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
            // Max packet size right below overflow should be accepted.
            TestCase {
                input: std::iter::repeat_n(b'a', MAX_FRAME_SIZE)
                    .chain(std::iter::once(0))
                    .collect(),
                expected: vec![b'a'; MAX_FRAME_SIZE],
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            let mut host_to_wire = Cursor::new(tt.input);

            let mut framing = FrameReader::new(Memory::new(&mut host_to_wire), Closer::new(|| {}));
            let frame = framing.next_frame_blob().unwrap();
            assert_eq!(frame, tt.expected, "test {i}");
        }
    }

    // Tests that each oversized frame reports one error, including when it spans
    // several buffers. Its terminator is consumed, while following frames and a
    // separate reset survive. A preceding frame also exercises buffer compaction.
    #[test]
    fn test_next_frame_oversized() {
        let mut input = b"before\0".to_vec();
        for size in [MAX_FRAME_SIZE + 1, 2 * MAX_FRAME_SIZE + 15] {
            input.extend(std::iter::repeat_n(b'a', size));
            input.extend_from_slice(b"\0after\0\0");
        }
        let mut framing = FrameReader::new(Memory::new(Cursor::new(input)), Closer::new(|| {}));
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

    // Tests reads failing midway through an oversized frame, which leave the
    // discard to resume on the next call, the frame's tail never served. Overflow
    // is reported before another adapter read, even if no delimiter ever arrives.
    #[test]
    fn test_next_frame_discard_resumes() {
        testing::init_tracing();

        /// Reader handing out one mock result per read.
        struct Mock(VecDeque<io::Result<Vec<u8>>>);

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

        /// Adapter results after the oversized prefix and the frames or read
        /// failures expected after the initial size error.
        struct TestCase {
            reads: Vec<io::Result<Vec<u8>>>,
            expected: Vec<Option<Vec<u8>>>, // Frame served per call, none for a failure
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
            // A failed read surfaces, the discard resuming on the next call
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
            let mut framing =
                FrameReader::new(Memory::new(Mock(tt.reads.into())), Closer::new(|| {}));
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

        // EOF while discarding does not make a later tail into a fresh frame.
        let reads = vec![
            Ok(vec![b'a'; MAX_FRAME_SIZE + 1]),
            Ok(Vec::new()),
            Ok(b"tail\0foo\0".to_vec()),
        ];
        let mut framing = FrameReader::new(Memory::new(Mock(reads.into())), Closer::new(|| {}));
        assert!(matches!(
            framing.next_frame_blob(),
            Err(Error::FrameTooLarge(size)) if size == MAX_FRAME_SIZE + 1
        ));
        assert!(matches!(framing.next_frame_blob(), Err(Error::Terminated)));
        assert_eq!(framing.next_frame_blob().unwrap(), b"foo");
    }

    // Tests raw frame boundaries with and without the reserved recovery prefix,
    // including a maximum-sized frame that fills the entire combined buffer.
    #[test]
    fn test_send_frame() {
        testing::init_tracing();

        /// Input and expected result for one framing boundary case.
        struct TestCase {
            input: &'static [u8],
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
            // Max packet size right below overflow should be accepted.
            TestCase {
                input: &[b'a'; MAX_FRAME_SIZE],
                expected: std::iter::repeat_n(b'a', MAX_FRAME_SIZE)
                    .chain(std::iter::once(0))
                    .collect(),
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            for resync in [false, true] {
                let mut wire_to_host = Vec::new();
                let mut framing =
                    FrameWriter::new(Memory::new(&mut wire_to_host), Closer::new(|| {}));
                framing.resync = resync;
                framing
                    .send_frame_blob(tt.input, Instant::now() + DEFAULT_WRITE_TIMEOUT, None)
                    .unwrap();

                let mut expected = Vec::new();
                if resync {
                    expected.push(0);
                }
                expected.extend_from_slice(&tt.expected);
                assert_eq!(wire_to_host, expected, "test {i}, resync {resync}");
            }
        }
    }

    // A successful flush that returns after the deadline still fails the frame.
    // The next send must use a fresh budget and resynchronize the same adapter.
    #[test]
    fn test_late_flush_resynchronizes() {
        /// Collects bytes and delays one flush until its deadline has elapsed,
        /// modeling a successful adapter call whose return was scheduled late.
        struct LateFlush {
            bytes: Vec<u8>,
            deadline: Option<Instant>,
            delay: bool,
        }

        impl Write for LateFlush {
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
                    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                }
                Ok(())
            }
        }

        let mut framing = FrameWriter::new(
            LateFlush {
                bytes: Vec::new(),
                deadline: None,
                delay: true,
            },
            Closer::new(|| {}),
        );
        let result =
            framing.send_frame_blob(b"old", Instant::now() + Duration::from_millis(100), None);
        assert!(
            matches!(result, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut)
        );
        assert_eq!(framing.writer.inner.bytes, b"old\0");

        framing
            .send_frame_blob(b"new", Instant::now() + DEFAULT_WRITE_TIMEOUT, None)
            .unwrap();
        assert_eq!(framing.writer.inner.bytes, b"old\0\0new\0");
    }

    // Tests that a writer panicking midway leaves the framer usable, the frame
    // buffer in place and the next send starting with the delimiter that
    // terminates whatever the panic left behind.
    #[test]
    fn test_send_panic() {
        testing::init_tracing();

        /// Writer panicking on its first write and collecting the ones after.
        struct Panicky {
            armed: bool,
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
            Memory::new(Panicky {
                armed: true,
                written: Vec::new(),
            }),
            Closer::new(|| {}),
        );
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            framing.send_packet(&[1, 2, 3], Instant::now() + DEFAULT_WRITE_TIMEOUT, None)
        }));
        assert!(result.is_err());

        framing
            .send_packet(&[1, 2, 3], Instant::now() + DEFAULT_WRITE_TIMEOUT, None)
            .unwrap();
        assert_eq!(
            framing.writer.inner.inner.written,
            [0x00, 0x04, 1, 2, 3, 0x00]
        );
    }
}

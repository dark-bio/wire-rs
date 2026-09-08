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

use crate::transport::stream::{ReadHalf, WriteHalf};
use crate::transport::{Closer, Error, MAX_FRAME_SIZE};
use darkbio_cobs as cobs;
use std::io::{self, Read, Write};
use std::ops::Range;
use tracing::warn;

/// Reading half of the framer, the frames coming in and the buffers receiving
/// and decoding them. It stands on its own, so a session can read on one
/// thread while writing on another.
pub(crate) struct FrameReader<R: Read> {
    reader: ReadHalf<R>, // Byte stream frames are read from, guarded by its close handle

    buffer: Vec<u8>, // Received bytes not yet consumed, partial or multiple frames
    filled: usize,   // Number of received bytes in buffer
    offset: usize,   // Start of the unconsumed data, i.e. of the next frame
    search: usize,   // End of the unconsumed data already scanned for a delimiter
    discard: usize,  // Bytes of an oversized frame thrown away so far, its delimiter still to come

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
            discard: 0,
            packet: vec![0u8; MAX_FRAME_SIZE],
        }
    }

    /// Reads the next frame and COBS decodes it, returning the packet as a view
    /// valid until the next read. An empty frame is not COBS but a session reset
    /// signal and yields `None`; a genuinely empty packet decodes to an empty
    /// view. Complete buffered frames remain available after stream closure;
    /// needing another read observes EOF.
    #[inline]
    pub fn next_packet(&mut self) -> Result<Option<&[u8]>, Error> {
        // Retrieve the next 0-bounded frame and pull out the data
        let frame = self.next_frame()?;

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
    /// so callers can parse it without copying. Frames exceeding MAX_FRAME_SIZE
    /// are discarded with a warning, resynchronizing on the next delimiter, a
    /// read failing midway through one leaving the discard to resume on the
    /// next call. A read interrupted by a signal is retried.
    #[inline]
    fn next_frame(&mut self) -> Result<Range<usize>, Error> {
        'outer: loop {
            // Search for the frame delimiter, starting from where we left off
            if let Some(found) = memchr::memchr(0, &self.buffer[self.search..self.filled]) {
                // Found the end of the frame, consume it from the buffer
                let start = self.offset;
                let end = self.search + found;

                self.offset = end + 1; // skip the zero marker
                self.search = end + 1; // skip the zero marker

                // If we were in discard mode, report, throw away and start over
                if self.discard > 0 {
                    warn!("discarded frame of {} bytes", self.discard + end - start);
                    self.discard = 0;
                    continue 'outer;
                }
                // We were in normal operation, return the consumed frame
                return Ok(Range { start, end });
            }
            // The searched region is delimiter free, don't rescan it later
            self.search = self.filled;

            // Frame delimiter not found, we only have fragments
            if self.discard == 0 {
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
                self.discard += self.filled;
                self.filled = 0;
                self.offset = 0;
                self.search = 0
            }
            // We've done everything we could, we need more data. If the buffer
            // is already full, we've exceeded our frame size, drop all.
            if self.filled == MAX_FRAME_SIZE + 1 {
                self.discard += MAX_FRAME_SIZE + 1;
                self.filled = 0;
                self.offset = 0;
                self.search = 0
            }
            // Read more data to try and find the next frame marker
            match self.reader.read(&mut self.buffer[self.filled..]) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue, // Signal cut the read short, retry
                Err(err) => return Err(Error::RecvFailed(err)), // Transport failed internally, cannot recover
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
        let frame = self.next_frame()?;
        Ok(&self.buffer[frame])
    }
}

/// Writing half of the framer, the frames going out and the buffer encoding
/// them. It stands on its own, so a session can write on one thread while
/// reading on another.
pub(crate) struct FrameWriter<W: Write> {
    writer: WriteHalf<W>, // Byte stream frames are written to, guarded by its close handle

    resync: bool, // Whether the last send failed, possibly leaving a frame unterminated
    frame: Vec<u8>, // Frame being sent, with a spare slot for the delimiter
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
            frame: vec![0u8; MAX_FRAME_SIZE + 1], // one extra slot for the frame delimiter
        }
    }

    /// Signals a session reset by writing two frame delimiters, the first one
    /// terminating any interrupted frame, the second forming the empty reset
    /// frame. The first covers a frame a previous client may have left behind,
    /// so a reset resyncs the stream by itself.
    pub fn send_reset(&mut self) -> Result<(), Error> {
        self.resync = false;

        // Piggyback on the frame sender which turn this into 2 zero-frames
        self.frame[0] = 0;
        self.send_frame(1)
    }

    /// Signals a dropped session by writing a single frame delimiter, forming
    /// an empty frame. After a failed send it goes out behind the delimiter
    /// terminating what that send left behind, so it is not swallowed as one.
    pub fn send_dropped(&mut self) -> Result<(), Error> {
        // Piggyback on the frame sender which turn this into 1 zero-frame
        self.send_frame(0)
    }

    /// COBS encodes a packet and sends it as a delimited frame. Packets whose
    /// encoding would exceed MAX_FRAME_SIZE are rejected.
    #[inline]
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        // Encode the packet with COBS and send it as a frame
        let len = cobs::encode_buffer(packet.len());
        if len > MAX_FRAME_SIZE {
            return Err(Error::FrameTooLarge(len));
        }
        let size = cobs::encode(packet, &mut self.frame)
            .expect("frame buffer holds any packet passing the size check");

        // Send the frame into the 0-bounded stream
        self.send_frame(size)
    }

    /// Writes and flushes the first `size` bytes of the frame buffer with a
    /// trailing delimiter, preceded by another delimiter if the last send failed.
    /// The resync flag is raised while writing, so a panic leaves the next send
    /// responsible for terminating any partial frame.
    #[inline]
    fn send_frame(&mut self, size: usize) -> Result<(), Error> {
        // Append the frame end marker
        self.frame[size] = 0;

        // Send the frame, potentially including an initial resync marker
        let result = (|| {
            if std::mem::replace(&mut self.resync, true) {
                self.writer.write_all(&[0x00])?;
            }
            self.writer.write_all(&self.frame[..size + 1])?;
            self.writer.flush()
        })();

        // If anything went wrong, set the resync marker back
        self.resync = result.is_err();
        result.map_err(Error::SendFailed)
    }

    /// Test and benchmark helper exposing `send_frame` with the raw frame taken
    /// from a slice. Panics on frames larger than the send buffer.
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = self.frame.len().min(bytes.len());
        self.frame[..len].copy_from_slice(&bytes[..len]);
        self.send_frame(bytes.len())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use std::collections::VecDeque;
    use std::io::{self, Cursor};
    use std::panic::{self, AssertUnwindSafe};

    // Closing leaves complete buffered frames readable, then reports EOF.
    #[test]
    fn test_close_drains_buffered_frames() {
        let closer = Closer::new(|| {});
        let mut reader = FrameReader::new(&[0x02, 1, 0, 0x02, 2, 0][..], closer.clone());
        assert_eq!(reader.next_packet().unwrap(), Some(&[1][..]));
        closer.close();
        assert_eq!(reader.next_packet().unwrap(), Some(&[2][..]));
        assert!(matches!(reader.next_packet(), Err(Error::Terminated)));
    }

    // Tests corner-cases when consuming a packet from the framed transport.
    #[test]
    fn test_next_packet() {
        testing::init_tracing();

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

            let mut framing = FrameReader::new(&mut host_to_wire, Closer::new(|| {}));
            match tt.expected {
                Some(expected) => {
                    let packet = framing
                        .next_packet()
                        .unwrap()
                        .expect("expected a COBS packet");
                    assert_eq!(packet, expected, "test {i}");
                }
                None => {
                    let result = framing.next_packet();
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

            let mut framing = FrameWriter::new(&mut wire_to_host, Closer::new(|| {}));
            match tt.expected {
                Some(expected) => {
                    framing.send_packet(&tt.input).unwrap();

                    let written = &wire_to_host.get_ref()[..];
                    assert_eq!(written, expected, "test {i}");
                }
                None => {
                    let result = framing.send_packet(&tt.input);
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
            // Overflown packet should be silently discarded and the next packet
            // read and returned.
            TestCase {
                input: std::iter::repeat_n(b'a', MAX_FRAME_SIZE + 1)
                    .chain(b"\0foo\0".iter().copied())
                    .collect(),
                expected: b"foo".to_vec(),
            },
            // Multi-frame overflow should not cause issues.
            TestCase {
                input: std::iter::repeat_n(b'a', 2 * MAX_FRAME_SIZE + 15)
                    .chain(b"\0foo\0".iter().copied())
                    .collect(),
                expected: b"foo".to_vec(),
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            let mut host_to_wire = Cursor::new(tt.input);

            let mut framing = FrameReader::new(&mut host_to_wire, Closer::new(|| {}));
            let frame = framing.next_frame_blob().unwrap();
            assert_eq!(frame, tt.expected, "test {i}");
        }
    }

    // Tests reads failing midway through an oversized frame, which leave the
    // discard to resume on the next call, the frame's tail never served.
    #[test]
    fn test_next_frame_discard_resumes() {
        testing::init_tracing();

        /// Reader handing out one mock result per read.
        struct Mock(VecDeque<io::Result<Vec<u8>>>);

        impl Read for Mock {
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
            let mut framing = FrameReader::new(Mock(tt.reads.into()), Closer::new(|| {}));
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
    }

    // Tests corner-cases when injecting a frame into the raw transport.
    #[test]
    fn test_send_frame() {
        testing::init_tracing();

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
            let mut wire_to_host = Cursor::new(Vec::<u8>::with_capacity(tt.input.len() + 1));

            let mut framing = FrameWriter::new(&mut wire_to_host, Closer::new(|| {}));
            framing.send_frame_blob(tt.input).unwrap();

            let written = &wire_to_host.get_ref()[..];
            assert_eq!(written, tt.expected, "test {i}");
        }
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

        impl Write for Panicky {
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
            Panicky {
                armed: true,
                written: Vec::new(),
            },
            Closer::new(|| {}),
        );
        let result = panic::catch_unwind(AssertUnwindSafe(|| framing.send_packet(&[1, 2, 3])));
        assert!(result.is_err());

        framing.send_packet(&[1, 2, 3]).unwrap();
        assert_eq!(framing.writer.inner.written, [0x00, 0x04, 1, 2, 3, 0x00]);
    }
}

// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

use crate::{Error, MAX_FRAME_SIZE};
use darkbio_cobs as cobs;
use std::io::{Read, Write};
use std::ops::Range;
use tracing::warn;

/// COBS framer over a raw byte stream. Frames are zero delimited, with any
/// zero in the payload encoded away.
///
/// The stream is assumed to carry no client lifecycle, as USB bulk transfers
/// lack it by design. E.g A host may attach via WebUSB, crash or reconnect
/// without the Ark noticing. Session boundaries have to be signaled in band.
///
/// Since an empty frame is not valid COBS, it is used to mark a session reset.
/// A host opens a session with two zeros, the first terminating whatever frame
/// may have been interrupted, the second being the reset. An Ark answers with
/// a single zero whenever it has no session for what it received.
pub(crate) struct Framing<R: Read, W: Write> {
    reader: R, // Byte stream frames are read from
    writer: W, // Byte stream frames are written to

    reader_buffer: Vec<u8>, // Received bytes not yet consumed, partial or multiple frames
    reader_filled: usize,   // Number of received bytes in reader_buffer
    reader_offset: usize,   // Start of the unconsumed data, i.e. of the next frame
    reader_search: usize,   // End of the unconsumed data already scanned for a delimiter

    pub decobs_buffer: Vec<u8>, // Last decoded packet, consumed by the session layer
    encobs_buffer: Vec<u8>,     // Frame being sent, with a spare slot for the delimiter
    pub encode_buffer: Vec<u8>, // Scratch for protobuf encoding a message before sealing
}

impl<R: Read, W: Write> Framing<R, W> {
    /// Creates a new framed transport around a low level reader and writer.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            reader_buffer: vec![0u8; MAX_FRAME_SIZE + 1], // one extra slot for the frame delimiter
            reader_offset: 0,
            reader_filled: 0,
            reader_search: 0,
            decobs_buffer: vec![0u8; MAX_FRAME_SIZE],
            encobs_buffer: vec![0u8; MAX_FRAME_SIZE + 1], // one extra slot for the frame delimiter
            encode_buffer: vec![0u8; MAX_FRAME_SIZE],
        }
    }

    /// Signals a session reset by writing two frame delimiters, the first one
    /// terminating any interrupted frame, the second forming the empty reset
    /// frame.
    pub fn send_reset(&mut self) -> Result<(), Error> {
        (|| {
            self.writer.write_all(&[0x00, 0x00])?;
            self.writer.flush()
        })()
        .map_err(Error::SendFailed)
    }

    /// Signals a dropped session by writing a single frame delimiter, forming
    /// an empty frame. Unlike a host reset, this one does not guard against an
    /// interrupted frame. The Ark only leaves one behind when a write failed,
    /// which leaves the transport broken for the signal too.
    pub fn send_dropped(&mut self) -> Result<(), Error> {
        (|| {
            self.writer.write_all(&[0x00])?;
            self.writer.flush()
        })()
        .map_err(Error::SendFailed)
    }

    /// Reads the next frame and COBS decodes it into `decobs_buffer`, returning
    /// the packet size. An empty frame is not COBS but a session reset signal
    /// and yields `None`; a genuinely empty packet decodes to `Some(0)`.
    #[inline]
    pub fn next_packet(&mut self) -> Result<Option<usize>, Error> {
        // Retrieve the next 0-bounded frame and pull out the data
        let frame = self.next_frame()?;

        // Empty frame is a session reset signal, it's not valid COBS
        if frame.start == frame.end {
            return Ok(None);
        }
        // Decode it with COBS. The framer split the stream at the first zero,
        // so the frame is guaranteed zero free and the cheaper decoder applies.
        cobs::decode_nonzero(
            &self.reader_buffer[frame.start..frame.end],
            &mut self.decobs_buffer,
        )
        .map(Some)
        .map_err(Error::FrameDecodingFailed)
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
        let size = cobs::encode(packet, &mut self.encobs_buffer)
            .expect("frame buffer holds any packet passing the size check");

        // Send the frame into the 0-bounded stream
        self.send_frame(size)
    }

    /// Reads the next zero delimited frame, returning its range within
    /// `reader_buffer` so callers can parse it without copying. Frames exceeding
    /// MAX_FRAME_SIZE are discarded with a warning, resynchronizing on the next
    /// delimiter.
    #[inline]
    fn next_frame(&mut self) -> Result<Range<usize>, Error> {
        // Track if we're in discard mode and how much we discarded until now
        let mut discard = 0usize;

        'outer: loop {
            // Search for the frame delimiter, starting from where we left off
            if let Some(found) = memchr::memchr(
                0,
                &self.reader_buffer[self.reader_search..self.reader_filled],
            ) {
                // Found the end of the frame, consume it from the buffer
                let start = self.reader_offset;
                let end = self.reader_search + found;

                self.reader_offset = end + 1; // skip the zero marker
                self.reader_search = end + 1; // skip the zero marker

                // If we were in discard mode, report, throw away and start over
                if discard > 0 {
                    warn!("discarded frame of {} bytes", discard + end - start);
                    discard = 0;
                    continue 'outer;
                }
                // We were in normal operation, return the consumed frame
                return Ok(Range { start, end });
            }
            // The searched region is delimiter free, don't rescan it later
            self.reader_search = self.reader_filled;

            // Frame delimiter not found, we only have fragments
            if discard == 0 {
                if self.reader_offset > 0 {
                    // We're in waiting mode, compact the buffer to maximise free space
                    let used = self.reader_filled - self.reader_offset;
                    self.reader_buffer
                        .copy_within(self.reader_offset..self.reader_filled, 0);
                    self.reader_filled = used;
                    self.reader_offset = 0;
                    self.reader_search = used;
                }
            } else {
                // We're in discard mode, throw everything away
                discard += self.reader_filled;
                self.reader_filled = 0;
                self.reader_offset = 0;
                self.reader_search = 0
            }
            // We've done everything we could, we need more data. If the buffer
            // is already full, we've exceeded our frame size, drop all.
            if self.reader_filled == MAX_FRAME_SIZE + 1 {
                discard += MAX_FRAME_SIZE + 1;
                self.reader_filled = 0;
                self.reader_offset = 0;
                self.reader_search = 0
            }
            // Read more data to try and find the next frame marker
            match self
                .reader
                .read(&mut self.reader_buffer[self.reader_filled..])
            {
                Err(err) => return Err(Error::RecvFailed(err)), // Transport failed internally, cannot recover
                Ok(0) => return Err(Error::Terminated), // Transport was terminated, tear down
                Ok(n) => self.reader_filled += n,       // Read some bytes, ingest them
            }
        }
    }

    /// Writes the first `size` bytes of `encobs_buffer` as a frame, placing the
    /// delimiter in the buffer's spare slot so the frame goes out in one write.
    #[inline]
    fn send_frame(&mut self, size: usize) -> Result<(), Error> {
        self.encobs_buffer[size] = 0;
        (|| {
            self.writer.write_all(&self.encobs_buffer[..size + 1])?;
            self.writer.flush()
        })()
        .map_err(Error::SendFailed)
    }

    /// Test and benchmark helper exposing `next_packet` with the decoded packet
    /// as a slice.
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_packet_blob(&mut self) -> Result<Option<&[u8]>, Error> {
        match self.next_packet() {
            Err(err) => Err(err),
            Ok(None) => Ok(None),
            Ok(Some(size)) => Ok(Some(&self.decobs_buffer[..size])),
        }
    }

    /// Test and benchmark helper exposing `next_frame` with the raw frame as a
    /// slice.
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_frame_blob(&mut self) -> Result<&[u8], Error> {
        let frame = self.next_frame()?;
        Ok(&self.reader_buffer[frame])
    }

    /// Test and benchmark helper exposing `send_frame` with the raw frame taken
    /// from a slice. Panics on frames larger than the send buffer.
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(&mut self, frame: &[u8]) -> Result<(), Error> {
        let len = self.encobs_buffer.len().min(frame.len());
        self.encobs_buffer[..len].copy_from_slice(&frame[..len]);
        self.send_frame(frame.len())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use std::io::{Cursor, empty, sink};

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

            let mut framing = Framing::new(&mut host_to_wire, sink());
            match tt.expected {
                Some(expected) => {
                    let packet = framing
                        .next_packet_blob()
                        .unwrap()
                        .expect("expected a COBS packet");
                    assert_eq!(packet, expected, "test {i}");
                }
                None => {
                    let result = framing.next_packet_blob();
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

            let mut framing = Framing::new(empty(), &mut wire_to_host);
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
                input: std::iter::repeat(b'a')
                    .take(MAX_FRAME_SIZE)
                    .chain(std::iter::once(0))
                    .collect(),
                expected: vec![b'a'; MAX_FRAME_SIZE],
            },
            // Overflown packet should be silently discarded and the next packet
            // read and returned.
            TestCase {
                input: std::iter::repeat(b'a')
                    .take(MAX_FRAME_SIZE + 1)
                    .chain(b"\0foo\0".iter().copied())
                    .collect(),
                expected: b"foo".to_vec(),
            },
            // Multi-frame overflow should not cause issues.
            TestCase {
                input: std::iter::repeat(b'a')
                    .take(2 * MAX_FRAME_SIZE + 15)
                    .chain(b"\0foo\0".iter().copied())
                    .collect(),
                expected: b"foo".to_vec(),
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            let mut host_to_wire = Cursor::new(tt.input);

            let mut framing = Framing::new(&mut host_to_wire, sink());
            let frame = framing.next_frame_blob().unwrap();
            assert_eq!(frame, tt.expected, "test {i}");
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
                expected: std::iter::repeat(b'a')
                    .take(MAX_FRAME_SIZE)
                    .chain(std::iter::once(0))
                    .collect(),
            },
        ];

        for (i, tt) in tests.into_iter().enumerate() {
            let mut wire_to_host = Cursor::new(Vec::<u8>::with_capacity(tt.input.len() + 1));

            let mut framing = Framing::new(empty(), &mut wire_to_host);
            framing.send_frame_blob(tt.input).unwrap();

            let written = &wire_to_host.get_ref()[..];
            assert_eq!(written, tt.expected, "test {i}");
        }
    }
}

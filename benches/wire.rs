// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Benchmarks of reading and writing frames and packets through a client's framer.

#![expect(
    clippy::disallowed_methods,
    reason = "benchmarks measure real elapsed time"
)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use darkbio_cobs as cobs;
use darkbio_wire::clock::Clock;
use darkbio_wire::transport::Client;
use darkbio_wire::transport::testing::Memory;
use rand::RngExt;
use std::io::{Cursor, empty, sink};

/// Size of the in-memory stream each benchmark reads or writes, 512 MiB.
///
/// Iterations beyond what the stream holds are not run, and the measured time
/// is scaled up to cover them.
const MAX_MEMORY_USAGE: usize = 512 * 1024 * 1024;

/// Measures reading delimited frames through a client's framer, without COBS
/// decoding them.
fn bench_frame_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_read");

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        // Generate one random frame without zero bytes, then its delimiter
        let mut data: Vec<u8> = rand::rng()
            .random_iter::<u8>()
            .filter(|&b| b != 0)
            .take(size)
            .collect();
        data.push(0);

        // Fill the input stream with copies of that frame
        let mut reader: Cursor<Vec<u8>> = Cursor::new(
            data.iter()
                .cloned()
                .cycle()
                .take(MAX_MEMORY_USAGE)
                .collect(),
        );

        // Time as many reads as the stream holds, scaled to the requested count
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize).min(MAX_MEMORY_USAGE / data.len()).max(1);

                reader.set_position(0);
                let mut wire = Client::new(darkbio_wire::transport::Stream::new(
                    Memory::new(&mut reader, &Clock::real()),
                    Memory::new(sink(), &Clock::real()),
                    || {},
                ));

                let start = std::time::Instant::now();
                for _ in 0..actual_iters {
                    wire.next_frame_blob().unwrap();
                }
                start.elapsed().mul_f64(iters as f64 / actual_iters as f64)
            });
        });
    }
    group.finish();
}

/// Measures writing already encoded frames through a client's framer, which
/// adds only the delimiter.
fn bench_frame_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_write");
    let mut drain = Cursor::new(Vec::with_capacity(MAX_MEMORY_USAGE));

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        // Generate one random frame without zero bytes
        let data: Vec<u8> = rand::rng()
            .random_iter::<u8>()
            .filter(|&b| b != 0)
            .take(size)
            .collect();
        let frame_size = data.len() + 1;

        // Time as many writes as the drain holds, scaled to the requested count
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize).min(MAX_MEMORY_USAGE / frame_size).max(1);

                drain.set_position(0);
                let mut wire = Client::new(darkbio_wire::transport::Stream::new(
                    Memory::new(empty(), &Clock::real()),
                    Memory::new(&mut drain, &Clock::real()),
                    || {},
                ));

                let start = std::time::Instant::now();
                for _ in 0..actual_iters {
                    wire.send_frame_blob(&data).unwrap();
                }
                start.elapsed().mul_f64(iters as f64 / actual_iters as f64)
            });
        });
    }
    group.finish();
}

/// Measures reading frames through a client's framer and COBS decoding them
/// into packets, without decryption.
fn bench_packet_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_read");

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        // Encode one random packet into a delimited frame
        let data: Vec<u8> = rand::rng().random_iter().take(size).collect();
        let mut encoded = vec![0u8; cobs::encode_buffer(size)];
        let len = cobs::encode(&data, &mut encoded).unwrap();
        encoded.truncate(len);
        encoded.push(0);

        // Fill the input stream with copies of that frame
        let mut reader: Cursor<Vec<u8>> = Cursor::new(
            encoded
                .iter()
                .cloned()
                .cycle()
                .take(MAX_MEMORY_USAGE)
                .collect(),
        );

        // Time as many reads as the stream holds, scaled to the requested count
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize)
                    .min(MAX_MEMORY_USAGE / encoded.len())
                    .max(1);

                reader.set_position(0);
                let mut wire = Client::new(darkbio_wire::transport::Stream::new(
                    Memory::new(&mut reader, &Clock::real()),
                    Memory::new(sink(), &Clock::real()),
                    || {},
                ));

                let start = std::time::Instant::now();
                for _ in 0..actual_iters {
                    wire.next_packet_blob().unwrap();
                }
                start.elapsed().mul_f64(iters as f64 / actual_iters as f64)
            });
        });
    }
    group.finish();
}

/// Measures COBS encoding packets and writing them through a client's framer,
/// without encryption.
fn bench_packet_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_write");
    let mut drain = Cursor::new(Vec::with_capacity(MAX_MEMORY_USAGE));

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        // Generate one random packet and bound its worst case frame size
        let data: Vec<u8> = rand::rng().random_iter().take(size).collect();
        let packet_size = cobs::encode_buffer(size) + 1;

        // Time as many writes as the drain holds, scaled to the requested count
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize).min(MAX_MEMORY_USAGE / packet_size).max(1);

                drain.set_position(0);
                let mut wire = Client::new(darkbio_wire::transport::Stream::new(
                    Memory::new(empty(), &Clock::real()),
                    Memory::new(&mut drain, &Clock::real()),
                    || {},
                ));

                let start = std::time::Instant::now();
                for _ in 0..actual_iters {
                    wire.send_packet_blob(&data).unwrap();
                }
                start.elapsed().mul_f64(iters as f64 / actual_iters as f64)
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_frame_read,
    bench_frame_write,
    bench_packet_read,
    bench_packet_write,
);

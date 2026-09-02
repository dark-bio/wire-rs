// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use darkbio_cobs as cobs;
use darkbio_wire::HostSide;
use rand::RngExt;
use std::io::{Cursor, empty, sink};

const MAX_MEMORY_USAGE: usize = 512 * 1024 * 1024;

// Benchmarks reading frames via the wire framer.
fn bench_frame_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_read");

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        let mut data: Vec<u8> = rand::rng()
            .random_iter::<u8>()
            .filter(|&b| b != 0)
            .take(size)
            .collect();
        data.push(0);

        let mut reader: Cursor<Vec<u8>> = Cursor::new(
            data.iter()
                .cloned()
                .cycle()
                .take(MAX_MEMORY_USAGE)
                .collect(),
        );

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize).min(MAX_MEMORY_USAGE / data.len()).max(1);

                reader.set_position(0);
                let mut wire = HostSide::new(&mut reader, sink());

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

// Benchmarks writing frames via the wire framer.
fn bench_frame_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_write");
    let mut drain = Cursor::new(Vec::with_capacity(MAX_MEMORY_USAGE));

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        let data: Vec<u8> = rand::rng()
            .random_iter::<u8>()
            .filter(|&b| b != 0)
            .take(size)
            .collect();
        let frame_size = data.len() + 1;

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize).min(MAX_MEMORY_USAGE / frame_size).max(1);

                drain.set_position(0);
                let mut wire = HostSide::new(empty(), &mut drain);

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

// Benchmarks reading packets via the wire framer.
fn bench_packet_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_read");

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        let data: Vec<u8> = rand::rng().random_iter().take(size).collect();
        let mut encoded = vec![0u8; cobs::encode_buffer(size)];
        let len = cobs::encode(&data, &mut encoded).unwrap();
        encoded.truncate(len);
        encoded.push(0);

        let mut reader: Cursor<Vec<u8>> = Cursor::new(
            encoded
                .iter()
                .cloned()
                .cycle()
                .take(MAX_MEMORY_USAGE)
                .collect(),
        );

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize)
                    .min(MAX_MEMORY_USAGE / encoded.len())
                    .max(1);

                reader.set_position(0);
                let mut wire = HostSide::new(&mut reader, sink());

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

// Benchmarks writing packets via the wire framer.
fn bench_packet_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_write");
    let mut drain = Cursor::new(Vec::with_capacity(MAX_MEMORY_USAGE));

    for size in [16, 256, 4096, 65536, 262144, 1048576] {
        let data: Vec<u8> = rand::rng().random_iter().take(size).collect();
        let packet_size = cobs::encode_buffer(size) + 1;

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iters| {
                let actual_iters = (iters as usize).min(MAX_MEMORY_USAGE / packet_size).max(1);

                drain.set_position(0);
                let mut wire = HostSide::new(empty(), &mut drain);

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

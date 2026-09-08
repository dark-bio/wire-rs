// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Deterministic randomness for vector generation and fuzzing.
//! With getrandom's custom backend selected, random draws, including crypto,
//! use a separate ChaCha20 stream on each thread. The recorder reseeds from
//! the scenario name; fuzzers reseed for each input. This makes random values
//! repeatable when the sequence of draws on each thread stays the same.
//! Thread scheduling and timing can still vary between runs.

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

thread_local! {
    /// This thread's random stream, initialized with an all-zero seed.
    static STREAM: RefCell<ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_seed([0; 32]));
}

/// Restarts this thread's stream with the SHA-256 hash of `name` as its seed.
pub fn reseed(name: &str) {
    let seed: [u8; 32] = Sha256::digest(name.as_bytes()).into();
    STREAM.with(|stream| *stream.borrow_mut() = ChaCha20Rng::from_seed(seed));
}

/// Fills getrandom's output buffer from this thread's stream.
///
/// # Safety
///
/// `dest` must be non-null and valid for writes of `len` bytes. The buffer must
/// not be accessed through another pointer for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    let buf = unsafe { std::slice::from_raw_parts_mut(dest, len) };
    STREAM.with(|stream| stream.borrow_mut().fill_bytes(buf));
    Ok(())
}

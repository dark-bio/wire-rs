// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Deterministic randomness for the vector builds and the fuzzers. With
//! getrandom's custom backend selected, every draw in the process, the
//! crypto's included, comes from a ChaCha20 stream per thread. The recorder
//! reseeds it from the scenario name, so a transcript regenerates unchanged
//! as long as the crypto draws the same way. The fuzzers reseed it per input,
//! so an input covers the same features on every execution and a corpus
//! minimizes to the same files every time.

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

thread_local! {
    /// Stream of the thread, from an all zero seed until reseeded.
    static STREAM: RefCell<ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_seed([0; 32]));
}

/// Restarts the thread's stream from the seed the name hashes into.
pub fn reseed(name: &str) {
    let seed: [u8; 32] = Sha256::digest(name.as_bytes()).into();
    STREAM.with(|stream| *stream.borrow_mut() = ChaCha20Rng::from_seed(seed));
}

/// The backend getrandom calls into, filling the buffer from the stream.
///
/// # Safety
///
/// The buffer must be valid for writes of the length.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    let buf = unsafe { std::slice::from_raw_parts_mut(dest, len) };
    STREAM.with(|stream| stream.borrow_mut().fill_bytes(buf));
    Ok(())
}

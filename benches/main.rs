// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Benchmark runner, printing the host environment before the benchmarks.

mod wire;

/// Prints the host's hardware, software and runtime details, so benchmarks run
/// on different machines can be compared.
fn print_system_infos() {
    use sysinfo::System;

    // Print the operating system details
    println!("Benchmark Environment:");
    println!(
        "  OS:        {} {}",
        System::name().unwrap_or_else(|| "Unknown".to_string()),
        System::os_version().unwrap_or_default()
    );
    println!(
        "  Kernel:    {}",
        System::kernel_version().unwrap_or_else(|| "Unknown".to_string())
    );
    println!("  Arch:      {}", std::env::consts::ARCH);

    // Print the hardware details
    let sys = System::new_all();
    let cpus = sys.cpus();
    if let Some(cpu) = cpus.first() {
        println!("  CPU:       {}", cpu.brand().trim());
    }
    println!("  Cores:     {}", cpus.len());
    println!(
        "  Memory:    {:.2} GB / {:.2} GB",
        sys.used_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
        sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0
    );

    // Print the Rust build details
    #[cfg(debug_assertions)]
    println!("  Build:     debug");
    #[cfg(not(debug_assertions))]
    println!("  Build:     release");

    println!("  Rustc:     {}", env!("RUSTC_VERSION"));
    println!();
}

/// Defines the benchmark `main` like `criterion_main!`, printing the host
/// environment first.
macro_rules! criterion_main_with_info {
    ( $( $group:path ),+ $(,)* ) => {
        /// Prints the host environment, then runs every benchmark group and
        /// the final summary.
        fn main() {
            print_system_infos();

            $(
                $group();
            )+

            criterion::Criterion::default()
                .configure_from_args()
                .final_summary();
        }
    }
}

criterion_main_with_info!(wire::benches);

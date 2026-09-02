// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

mod wire;

/// Prints a collection of system hardware, software and runtime infos so that
/// benchmarks originating from different people can be meaningfully compared.
fn print_system_infos() {
    use sysinfo::System;

    // Print operating system infos
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

    // Print hardware infos
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

    // Print Rust runtime infos
    #[cfg(debug_assertions)]
    println!("  Build:     debug");
    #[cfg(not(debug_assertions))]
    println!("  Build:     release");

    println!("  Rustc:     {}", env!("RUSTC_VERSION"));
    println!();
}

/// Clone of criterion_main!, but prints system infos first.
macro_rules! criterion_main_with_info {
    ( $( $group:path ),+ $(,)* ) => {
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

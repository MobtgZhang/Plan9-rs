//! Build script for the plan9-arch crate.
//!
//! Compiles architecture-specific assembly for the *target* architecture,
//! not the host architecture. `TARGET` is the cargo target triple.
//!
//! x86_64:
//!   - GDT segment-reload trampoline (`src/x86_64/reload_segments.S`)
//!   - IDT interrupt/exception stubs (`src/x86_64/idt_asm.S`)
//!   - ring-0 → ring-3 transition trampoline (`src/x86_64/switch_to_user.S`)
//!   - AP startup real-mode trampoline (`src/x86_64/ap_trampoline.S`)
//!
//! aarch64 / riscv64 / loongarch64 have no external assembly in the arch
//! crate — their context/CSR code lives in Rust `asm!` blocks.

use std::env;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_arch = "x86_64")]
fn build_x86_64(target: &str) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Segment-reload trampoline (used by gdt::reload_segments).
    cc::Build::new()
        .flag("-m64")
        .flag("-c")
        .file(manifest_dir.join("src/x86_64/reload_segments.S"))
        .target(target)
        .opt_level(0)
        .compile("arch_x86_64_asm");
    println!("cargo:rerun-if-changed=src/x86_64/reload_segments.S");

    // Interrupt/exception stubs used by the IDT. These are referenced
    // from arch::x86_64::idt via `extern "C"` and live here so the
    // kernel crate does not need its own build script for them.
    cc::Build::new()
        .flag("-m64")
        .flag("-c")
        .file(manifest_dir.join("src/x86_64/idt_asm.S"))
        .target(target)
        .opt_level(0)
        .compile("arch_x86_64_isr");
    println!("cargo:rerun-if-changed=src/x86_64/idt_asm.S");

    // Ring-0 → ring-3 transition trampoline used by
    // `kernel::entry::switch_to_user`.
    cc::Build::new()
        .flag("-m64")
        .flag("-c")
        .file(manifest_dir.join("src/x86_64/switch_to_user.S"))
        .target(target)
        .opt_level(0)
        .compile("arch_x86_64_switch");
    println!("cargo:rerun-if-changed=src/x86_64/switch_to_user.S");

    // AP startup trampoline: assembled 16-bit real-mode code, linked at
    // the fixed low-memory page the SIPI vector points at, and shipped as
    // a flat binary that the kernel copies into place during SMP bring-up.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let gcc = Command::new("gcc")
        .args(["-m16", "-c", "-o"])
        .arg(out_dir.join("ap_trampoline.o"))
        .arg(manifest_dir.join("src/x86_64/ap_trampoline.S"))
        .status()
        .expect("failed to run gcc for the AP trampoline");
    assert!(gcc.success(), "assembling ap_trampoline.S failed");
    let ld = Command::new("ld")
        .args(["-m", "elf_i386", "-Ttext=0x50000", "--oformat=binary", "-e", "ap_trampoline_start"])
        .arg(out_dir.join("ap_trampoline.o"))
        .arg("-o")
        .arg(out_dir.join("ap_trampoline.bin"))
        .status()
        .expect("failed to run ld for the AP trampoline");
    assert!(ld.success(), "linking ap_trampoline.bin failed");
    println!("cargo:rerun-if-changed=src/x86_64/ap_trampoline.S");

    println!("cargo:rerun-if-changed=build.rs");
}

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    if target == "x86_64-unknown-none" {
        #[cfg(target_arch = "x86_64")]
        build_x86_64(&target);
    }
    // All other targets need no external assembly objects.
}

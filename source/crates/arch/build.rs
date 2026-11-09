//! Build script for the plan9-arch crate.
//!
//! Compiles architecture-specific assembly (currently only the GDT
//! segment-reload trampoline on x86_64) so the arch crate can ship its
//! boot helpers without requiring the kernel crate to also bring along
//! a build script.

#[cfg(target_arch = "x86_64")]
fn build_x86_64() {
    use std::path::PathBuf;
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Segment-reload trampoline (used by gdt::reload_segments).
    cc::Build::new()
        .flag("-m64")
        .flag("-c")
        .file(manifest_dir.join("src/x86_64/reload_segments.S"))
        .target("x86_64-unknown-none")
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
        .target("x86_64-unknown-none")
        .opt_level(0)
        .compile("arch_x86_64_isr");
    println!("cargo:rerun-if-changed=src/x86_64/idt_asm.S");

    // Ring-0 → ring-3 transition trampoline used by
    // `kernel::entry::switch_to_user`.
    cc::Build::new()
        .flag("-m64")
        .flag("-c")
        .file(manifest_dir.join("src/x86_64/switch_to_user.S"))
        .target("x86_64-unknown-none")
        .opt_level(0)
        .compile("arch_x86_64_switch");
    println!("cargo:rerun-if-changed=src/x86_64/switch_to_user.S");

    // AP startup trampoline: assembled 16-bit real-mode code, linked at
    // the fixed low-memory page the SIPI vector points at, and shipped as
    // a flat binary that the kernel copies into place during SMP bring-up.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let gcc = std::process::Command::new("gcc")
        .args(["-m16", "-c", "-o"])
        .arg(out_dir.join("ap_trampoline.o"))
        .arg(manifest_dir.join("src/x86_64/ap_trampoline.S"))
        .status()
        .expect("failed to run gcc for the AP trampoline");
    assert!(gcc.success(), "assembling ap_trampoline.S failed");
    let ld = std::process::Command::new("ld")
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
    #[cfg(target_arch = "x86_64")]
    build_x86_64();
}

//! Build script for the Plan 9 kernel.
//!
//! Per-architecture boot assembly:
//!   * x86_64      — `src/arch/x86_64/boot.S` via the `cc` crate (system
//!                   assembler; GAS macros used by `multiboot2_constants.S`).
//!   * aarch64     — `src/arch/aarch64/boot.S` via `aarch64-linux-gnu-gcc`.
//!   * riscv64     — `src/arch/riscv64/boot.S` via `riscv64-linux-gnu-gcc`.
//!   * loongarch64 — `src/arch/loongarch64/boot.S` via
//!                   `loongarch64-linux-gnu-gcc`.
//!
//! The matching linker script (`kernel-<arch>.ld`) is passed with
//! `-T` on every target. Assembly objects are linked by passing the
//! compiled object file directly as a link argument.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap_or_default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let src_dir = manifest_dir.join("src");

    // The linker script is per-target (normalize riscv64gc → riscv64).
    let arch_name = target.split('-').next().unwrap_or("x86_64");
    let arch_name = arch_name.trim_end_matches("gc");
    let ld = manifest_dir.join(format!("kernel-{arch_name}.ld"));
    println!("cargo:rustc-link-arg=-T{}", ld.display());

    match target.as_str() {
        "x86_64-unknown-none" => {
            // `boot.S` includes `<arch/x86_64/multiboot2_constants.S>`, so the
            // search path must be the directory *above* `arch/x86_64/` — i.e.
            // the crate's `src/`.
            cc::Build::new()
                .include(src_dir.as_path())
                .flag("-m64")
                .flag("-c")
                .file(manifest_dir.join("src/arch/x86_64/boot.S"))
                .target("x86_64-unknown-none")
                .opt_level(0)
                .compile("kernel_asm");

            println!("cargo:rerun-if-changed=src/arch/x86_64/boot.S");
            println!("cargo:rerun-if-changed=src/arch/x86_64/multiboot2_constants.S");
        }
        "aarch64-unknown-none" => {
            assemble_cross(
                "aarch64-linux-gnu-gcc",
                &manifest_dir.join("src/arch/aarch64/boot.S"),
                &out_dir.join("boot_aarch64.o"),
            );
            println!("cargo:rerun-if-changed=src/arch/aarch64/boot.S");
        }
        "riscv64gc-unknown-none-elf" => {
            assemble_cross(
                "riscv64-linux-gnu-gcc",
                &manifest_dir.join("src/arch/riscv64/boot.S"),
                &out_dir.join("boot_riscv64.o"),
            );
            println!("cargo:rerun-if-changed=src/arch/riscv64/boot.S");
        }
        "loongarch64-unknown-none" => {
            assemble_cross(
                "loongarch64-linux-gnu-gcc",
                &manifest_dir.join("src/arch/loongarch64/boot.S"),
                &out_dir.join("boot_loongarch64.o"),
            );
            println!("cargo:rerun-if-changed=src/arch/loongarch64/boot.S");
        }
        other => {
            panic!("Plan 9 kernel: unsupported target '{other}'");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");

    // Link-argument hygiene shared by all targets (rust-lld is the default
    // linker for all four bare-metal targets).
    println!("cargo:rustc-link-arg=-znoexecstack");
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");
    // Force ELF type ET_EXEC (no PIE) so the loaders (GRUB, OpenSBI, QEMU)
    // can place the image without relocations.
    println!("cargo:rustc-link-arg=-no-pie");
}

/// Assemble `src` with a cross-binutils GCC driver into `obj` and pass the
/// object to the linker.
fn assemble_cross(compiler: &str, src: &PathBuf, obj: &PathBuf) {
    let status = Command::new(compiler)
        .args(["-c", "-fno-pic"])
        .arg(src)
        .arg("-o")
        .arg(obj)
        .status()
        .unwrap_or_else(|e| panic!("Plan 9 kernel: failed to spawn {compiler}: {e}"));
    if !status.success() {
        panic!("Plan 9 kernel: {compiler} failed assembling {}", src.display());
    }
    println!("cargo:rustc-link-arg={}", obj.display());
}

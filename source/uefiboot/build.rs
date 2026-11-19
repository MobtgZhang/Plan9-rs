//! Build script for the Plan 9 Rust UEFI boot loader.
//!
//! The loader is built two different ways:
//!
//!   * x86_64 / aarch64 — the official `*-unknown-uefi` rustc targets.
//!     Those target specs provide the PE/COFF entry glue (`_start` /
//!     `_start64`), so nothing special is needed here.
//!
//!   * riscv64 / loongarch64 — no official `*-unknown-uefi` target exists
//!     for them, so the loader is built as a plain bare-metal ELF and
//!     later wrapped into a PE32+ image by `build_tool`'s `wrap.rs`.
//!     Bare-metal `none` targets provide **no** entry glue at all, so
//!     this script supplies the two missing pieces:
//!
//!       1. a per-arch linker script that places the image at a fixed
//!          link address and defines the boot stack, and
//!       2. the `_start` symbol the linker looks for (emitted by the
//!          `global_asm!` stubs in `src/main.rs`).
//!
//! The linker script also matters for the PE wrapper: `wrap.rs` maps each
//! `PT_LOAD` segment to its physical address, so the image must be
//! position-dependent (ET_EXEC) and linked at a known address.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap_or_default();

    match target.as_str() {
        "riscv64gc-unknown-none-elf" => {
            emit(&manifest_dir, "uefiboot-riscv64.ld");
        }
        "loongarch64-unknown-none" => {
            emit(&manifest_dir, "uefiboot-loongarch64.ld");
        }
        // x86_64-unknown-uefi / aarch64-unknown-uefi: the official UEFI
        // target specs already provide the entry point and image layout.
        _ => {}
    }

    println!("cargo:rerun-if-changed=build.rs");
}

/// Pass the per-arch linker script and the link flags the bare-metal
/// loader needs (no PIE, no build-id, no dynamic linker).
fn emit(manifest_dir: &PathBuf, ld_name: &str) {
    let ld = manifest_dir.join(ld_name);
    println!("cargo:rustc-link-arg=-T{}", ld.display());
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");
    println!("cargo:rustc-link-arg=-znoexecstack");
    println!("cargo:rerun-if-changed={}", ld_name);
}

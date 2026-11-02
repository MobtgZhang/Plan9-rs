//! Build script for the Plan 9 kernel.
//!
//! Compiles the x86_64 assembly sources (`boot.S`, `idt_asm.S`) into a
//! single object file and tells the linker to pull it in. We use the
//! system assembler (`as`) via the `cc` crate because `rust-lld` does not
//! understand GAS macro syntax.

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `boot.S` includes `<arch/x86_64/multiboot2_constants.S>`, so the
    // search path must be the directory *above* `arch/x86_64/` — i.e. the
    // crate's `src/`.
    let src_dir = manifest_dir.join("src");

    // Compile the kernel assembly entry.  The IDT/exception stubs live in
    // the `plan9-arch` crate (idt_asm.S); compiling an identical copy here
    // would produce duplicate global symbols at link time.
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
    println!("cargo:rerun-if-changed=kernel-x86_64.ld");
    println!("cargo:rerun-if-changed=build.rs");

    let linker_script = manifest_dir.join("kernel-x86_64.ld");
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    println!("cargo:rustc-link-arg=-znoexecstack");
    // These args only work with the LLVM `lld` linker. For bare-metal
    // targets (x86_64-unknown-none) rust-lld is used by default, so we
    // can pass these unconditionally.
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");
    // Force ELF type ET_EXEC (no PIE) so GRUB Multiboot2 / Multiboot
    // can load the kernel without complaining about relocations.
    println!("cargo:rustc-link-arg=-no-pie");
}
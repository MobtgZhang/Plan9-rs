//! Binary entry point for `plan9_kernel`.
//!
//! The actual `_start` symbol is defined in `arch/x86_64/boot.S`. GRUB
//! transfers control directly to the assembly entry, which in turn calls
//! `plan9_kernel::entry::kstart()` once the boot stack and BSS are in
//! place.
//!
//! This file exists only because Cargo requires a `main.rs` for `[[bin]]`
//! targets. It intentionally contains no executable code and no `#[no_mangle]`
//! symbols — adding one would clash with the assembler-defined `_start` and
//! break the link.
//!
//! The `#[panic_handler]` lives in `entry.rs` because that module also owns
//! the early boot logic and the VGA text-mode `early_print`.

#![no_std]
#![no_main]

extern crate plan9_kernel;

//! Build script for the init binary: force ET_EXEC (no PIE) so GRUB
//! Multiboot2 modules don't refuse to load the file.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-arg=-no-pie");
}

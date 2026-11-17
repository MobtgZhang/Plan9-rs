//! Build script for the plan9-cmd binaries: force ET_EXEC (no PIE) so the
//! kernel's exec loader — which maps segments at USER_LOAD_BASE — accepts
//! them (same trick as the plan9-init build script).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-arg=-no-pie");
}

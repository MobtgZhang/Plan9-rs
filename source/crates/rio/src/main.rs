//! Plan 9 `rio` window system — user-space entry point.
//!
//! Currently compiled for the host triple (std target) so the window
//! table can be exercised in `cargo test` without needing the
//! kernel. The plan is to add a target build that uses
//! `plan9-libsys` once ring-3 syscalls are stable.

extern crate plan9_servers;

fn main() {
    // Tiny smoke test that the window table works from a host
    // binary. Real Plan 9 rio then enters an event loop reading
    // `/dev/mouse` and `/dev/kbd` events.
    let _a = plan9_servers::rio::new_window();
    let _b = plan9_servers::rio::new_window();
    println!("rio: {} windows open", plan9_servers::rio::windows().len());
}
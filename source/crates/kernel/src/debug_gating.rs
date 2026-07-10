//! Compile-time and runtime gating for the very chatty `put_bytes`
//! debug output.
//!
//! During bring-up the kernel logs every step through `put_bytes`.
//! Once boot is stable we want to silence the noise without ripping
//! out the calls — they're invaluable for post-mortem analysis when
//! something does go wrong.
//!
//! Two knobs are provided:
//!
//! * `KDEBUG_SERIAL` (compile time, default 1)
//!   - 0 → `put_bytes` is a no-op
//!   - 1 → emit unconditionally
//!   - 2 → emit only when the boot phase is < `DebugPhase::Quiet`
//!
//! * [`set_debug_phase`] (runtime)
//!   - called when entering user mode and again when the shell
//!     starts so the boot log stops being spammed to the console
//!   - the default phase is `Verbose`

use core::sync::atomic::{AtomicU8, Ordering};

/// What kind of boot phase we're in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DebugPhase {
    /// Pre-scheduler bring-up; print everything.
    Verbose = 0,
    /// User-mode init has started; only print warnings.
    Quiet = 1,
    /// Steady state; only print fatal panics.
    Silent = 2,
}

static PHASE: AtomicU8 = AtomicU8::new(DebugPhase::Verbose as u8);

/// Update the debug phase. Called by the kernel when it transitions
/// from ring 0 boot to ring 3 init, and again when the user shell
/// takes over the console.
pub fn set_debug_phase(p: DebugPhase) {
    PHASE.store(p as u8, Ordering::Release);
}

/// Returns true if the current phase permits debug output.
pub fn should_emit() -> bool {
    if cfg!(debug_assertions) {
        // dev profile: always emit so unit tests catch regressions.
        return true;
    }
    PHASE.load(Ordering::Acquire) == DebugPhase::Verbose as u8
}

/// Convenience: prefix tag so post-mortem readers can grep.
pub fn tag_for(phase: DebugPhase) -> &'static str {
    match phase {
        DebugPhase::Verbose => "[kdbg]",
        DebugPhase::Quiet => "[kwarn]",
        DebugPhase::Silent => "[kpanic]",
    }
}
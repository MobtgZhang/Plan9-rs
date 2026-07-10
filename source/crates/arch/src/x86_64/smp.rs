//! SMP (Symmetric Multi-Processing) primitives.
//!
//! Provides a small interface for the per-CPU storage primitives in
//! `common::sync` (notably `current_cpu()`). On a single-CPU bring-up
//! the implementation always returns 0. When the kernel boots APs via
//! `init_smp`, each AP writes its own slot index into the
//! `IA32_TSC_AUX` MSR so subsequent `rdtscp` reads yield that index.

/// Install this architecture's `current_cpu_id` into
/// `common::sync::CPU_ID_FN`. Must be called exactly once during
/// early arch init (before any `ILock` is taken).
pub fn install_cpu_id_provider() {
    // SAFETY: called exactly once before SMP brings up APs.
    unsafe {
        plan9_common::sync::set_cpu_id_provider(current_cpu_id);
    }
}

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_arch = "x86_64")]
static CURRENT_CPU_OVERRIDE: AtomicU32 = AtomicU32::new(0);

/// Return the logical id of the CPU executing this code.
///
/// On x86_64 we read `IA32_TSC_AUX` (set once per CPU by the SMP
/// bring-up sequence). `CURRENT_CPU_OVERRIDE` lets the BSP pretend to
/// be a different CPU id before per-CPU storage is initialised, which
/// is occasionally useful when debugging.
///
/// # Safety
/// Safe to call from any context. The MSR read is side-effect-free
/// for our purposes.
#[inline]
pub fn current_cpu_id() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let override_val = CURRENT_CPU_OVERRIDE.load(Ordering::Relaxed);
        if override_val != u32::MAX {
            return override_val as usize;
        }
        crate::x86_64::read_tsc_aux() as usize
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Single-CPU stub for other architectures.
        0
    }
}

/// Temporarily redirect `current_cpu_id()` to return `id`. Pass
/// `u32::MAX` to restore the MSR-based default.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
pub fn set_current_cpu_override(id: u32) {
    CURRENT_CPU_OVERRIDE.store(id, Ordering::Relaxed);
}

/// Initialise the SMP subsystem. The BSP writes 0 to `IA32_TSC_AUX`
/// and sets up the LAPIC; APs are brought up by `init_smp` once the
/// SMP trampoline is in place.
#[cfg(target_arch = "x86_64")]
pub fn init_smp_bsp() {
    use crate::x86_64;
    // Mark the BSP as CPU 0. Subsequent APs assign themselves
    // monotonically increasing ids in `init_smp_aps`.
    x86_64::write_tsc_aux(0);
}
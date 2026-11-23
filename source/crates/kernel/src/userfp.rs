use crate::proc::Proc;

#[cfg(target_arch = "riscv64")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
pub(crate) use plan9_arch::hal::context::FpuState as State;

#[cfg(target_arch = "loongarch64")]
#[repr(align(16))]
pub(crate) struct State {
    pub(crate) data: [u8; SIZE],
}

#[cfg(target_arch = "aarch64")]
pub(crate) const SIZE: usize = 528;
#[cfg(target_arch = "loongarch64")]
pub(crate) const SIZE: usize = 272;
#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
pub(crate) const SIZE: usize = plan9_arch::hal::context::FPU_STATE_SIZE;

#[cfg(target_arch = "loongarch64")]
extern "C" {
    static mut _user_fpregs: [u8; SIZE];
}

#[cfg(target_arch = "riscv64")]
static HAS_DOUBLE: AtomicBool = AtomicBool::new(false);

#[cfg(not(target_arch = "aarch64"))]
pub(crate) fn initial_state() -> State {
    #[allow(unused_mut)]
    let mut state = State { data: [0; SIZE] };
    #[cfg(target_arch = "x86_64")]
    {
        state.data[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        state.data[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    }
    state
}

#[cfg(not(target_arch = "aarch64"))]
pub(crate) unsafe fn capture() {
    if !available() {
        return;
    }
    if let Some(proc) = crate::proc::curproc_mut() {
        #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
        plan9_arch::hal::context::fpsave(&mut proc.user_fp);
        #[cfg(target_arch = "loongarch64")]
        (&raw const _user_fpregs).copy_to_nonoverlapping(&mut proc.user_fp.data, 1);
    }
}

pub(crate) unsafe fn resume(proc: &Proc) -> ! {
    let frame = proc.user_frame.as_ref().expect("missing user frame") as *const _ as u64;
    let root = proc.mmupdb.as_u64();
    #[cfg(not(target_arch = "aarch64"))]
    if available() {
        restore(&proc.user_fp);
    }
    plan9_arch::hal::switch_to_user::kernel_resume_user(frame, root)
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn restore(state: &State) {
    #[cfg(target_arch = "x86_64")]
    plan9_arch::hal::context::fprestore(state);
    #[cfg(target_arch = "riscv64")]
    plan9_arch::hal::context::fprestore(state);
    #[cfg(target_arch = "loongarch64")]
    (&raw mut _user_fpregs).copy_from_nonoverlapping(&state.data, 1);
}

pub(crate) unsafe fn init_boot() {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "mov {value}, cr0",
        "and {value}, -13",
        "or {value}, 2",
        "mov cr0, {value}",
        "mov {value}, cr4",
        "or {value}, 0x600",
        "mov cr4, {value}",
        value = out(reg) _,
        options(nostack),
    );
    #[cfg(target_arch = "riscv64")]
    HAS_DOUBLE.store(plan9_arch::hal::context::probe_double(), Ordering::Relaxed);
}

pub(crate) fn available() -> bool {
    #[cfg(target_arch = "riscv64")]
    return HAS_DOUBLE.load(Ordering::Relaxed);
    #[cfg(not(target_arch = "riscv64"))]
    true
}

#[cfg(target_arch = "riscv64")]
pub(crate) fn user_sstatus() -> u64 {
    if available() { plan9_arch::hal::switch_to_user::USER_SSTATUS_INIT } else { 0 }
}

pub(crate) fn reset(proc: &mut Proc) {
    #[cfg(not(target_arch = "aarch64"))]
    { proc.user_fp = initial_state(); }
    #[cfg(target_arch = "aarch64")]
    if let Some(frame) = proc.user_frame.as_mut() {
        *frame_bytes_mut(frame) = [0; SIZE];
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn frame_bytes(frame: &crate::proc::SavedUserFrame) -> &[u8; SIZE] {
    unsafe { &*core::ptr::addr_of!(frame.simd).cast() }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn frame_bytes_mut(frame: &mut crate::proc::SavedUserFrame) -> &mut [u8; SIZE] {
    unsafe { &mut *core::ptr::addr_of_mut!(frame.simd).cast() }
}

pub(crate) fn read(proc: &Proc) -> Option<&[u8; SIZE]> {
    if !available() {
        return None;
    }
    let frame = proc.user_frame.as_ref()?;
    #[cfg(target_arch = "aarch64")]
    return Some(frame_bytes(frame));
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = frame;
        Some(&proc.user_fp.data)
    }
}

pub(crate) fn write(proc: &mut Proc, offset: usize, input: &[u8]) -> Option<()> {
    let mut next = *read(proc)?;
    next.get_mut(offset..offset.checked_add(input.len())?)?.copy_from_slice(input);
    #[cfg(target_arch = "x86_64")]
    {
        let current = &proc.user_fp.data;
        let mask = u32::from_le_bytes(current[28..32].try_into().ok()?);
        let mask = if mask == 0 { 0xffbf } else { mask };
        let mxcsr = u32::from_le_bytes(next[24..28].try_into().ok()?);
        if mxcsr & !mask != 0 {
            return None;
        }
        next[28..32].copy_from_slice(&current[28..32]);
    }
    #[cfg(target_arch = "aarch64")]
    { *frame_bytes_mut(proc.user_frame.as_mut()?) = next; }
    #[cfg(not(target_arch = "aarch64"))]
    { proc.user_fp.data = next; }
    Some(())
}

//! GPU manager singleton.
//!
//! The manager holds the single live `DisplayEngine` instance for the kernel.
//! `init_from_bootinfo()` tries each backend in order (GOP → Bochs → virtio-gpu)
//! and stores the first successful one. The kernel console then uses it.

extern crate alloc;

use alloc::boxed::Box;
use crate::serial;
use super::{DisplayEngine, EngineKind, NullEngine};

/// The single live engine instance. Using `Option<Box<dyn DisplayEngine>>` in a
/// static avoids the DST fat-pointer `null_mut` problem.
static mut ENGINE: Option<Box<dyn DisplayEngine>> = None;

/// Whether the GPU subsystem has been successfully initialised.
pub fn is_initialised() -> bool {
    // SAFETY: read of static mut is safe because init runs once before any
    // concurrent access and we never drop the engine.
    unsafe { ENGINE.is_some() }
}

/// Initialise the GPU subsystem.
pub fn init_from_bootinfo(fb_config: Option<&crate::entry::FramebufferConfig>) {
    use super::gop::GopEngine;
    use super::bochs_vbe::BochsVbeEngine;
    use super::virtio_gpu::VirtioGpuEngine;

    serial::put_bytes(b"[gpu::manager] init_from_bootinfo\n");

    // Priority 1: GOP framebuffer from multiboot2 tag
    if let Some(cfg) = fb_config {
        serial::put_bytes(b"[gpu::manager] trying GOP...\n");
        if let Some(gop) = GopEngine::new(cfg) {
            serial::put_bytes(b"[gpu::manager] using GOP engine\n");
            store_engine(Box::new(gop));
            return;
        }
    }

    // Priority 2: QEMU Bochs VBE via PCI
    serial::put_bytes(b"[gpu::manager] trying Bochs VBE...\n");
    if let Some(bochs) = BochsVbeEngine::new() {
        serial::put_bytes(b"[gpu::manager] using Bochs VBE engine\n");
        store_engine(Box::new(bochs));
        return;
    }

    // Priority 3: QEMU virtio-gpu via PCI
    serial::put_bytes(b"[gpu::manager] trying virtio-gpu...\n");
    if let Some(vg) = VirtioGpuEngine::new() {
        serial::put_bytes(b"[gpu::manager] using virtio-gpu engine\n");
        store_engine(Box::new(vg));
        return;
    }

    // No GPU found — fall back to the null engine so drawing is safe.
    serial::put_bytes(b"[gpu::manager] no GPU found, using null engine\n");
    store_engine(Box::new(NullEngine));
}

fn store_engine(boxed: Box<dyn DisplayEngine>) {
    serial::put_bytes(b"[gpu::manager] engine: ");
    serial::put_bytes(boxed.name().as_bytes());
    serial::put_bytes(b"\n");

    let info = boxed.info();
    serial::put_bytes(b"[gpu::manager] fb: ");
    serial::put_hex_u32(info.width);
    serial::put_bytes(b"x");
    serial::put_hex_u32(info.height);
    serial::put_bytes(b" pitch=");
    serial::put_hex_u32(info.pitch);
    serial::put_bytes(b" bpp=");
    serial::put_hex_u32(info.format.bytes_per_pixel() as u32);
    serial::put_bytes(b" virt=");
    serial::put_hex_u64(info.virt_addr);
    serial::put_bytes(b"\n");

    // SAFETY: write to static mut is safe because:
    //  - This runs exactly once at boot, before any concurrent access.
    //  - The engine is never dropped (kernel lifetime).
    unsafe { ENGINE = Some(boxed); }
}

/// Borrow the engine immutably. Panics if not initialised.
pub fn with<F, R>(f: F) -> R
where
    F: FnOnce(&dyn DisplayEngine) -> R,
{
    // SAFETY: Same as above — the Option is only written once at boot.
    let engine = unsafe { ENGINE.as_ref().expect("gpu::manager: not initialised") };
    let inner: &dyn DisplayEngine = &**engine;
    f(inner)
}

/// Borrow the engine mutably. Panics if not initialised.
pub fn with_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut dyn DisplayEngine) -> R,
{
    // SAFETY: Same as above.
    let engine = unsafe { ENGINE.as_mut().expect("gpu::manager: not initialised") };
    f(&mut **engine)
}

/// Quick diagnostic: name and kind of the current engine.
pub fn current_engine_info() -> (&'static str, EngineKind) {
    if !is_initialised() {
        return ("uninitialised", EngineKind::None);
    }
    with(|e| (e.name(), e.kind()))
}

//! GPU manager singleton.
//!
//! The manager holds the single live `DisplayEngine` instance for the kernel.
//! `init_from_bootinfo()` tries each backend in order (GOP → Bochs → virtio-gpu)
//! and stores the first successful one. The kernel console then uses it.

extern crate alloc;

use alloc::boxed::Box;
use plan9_common::sync::Spinlock;
use crate::serial;
use super::{DisplayEngine, EngineKind, NullEngine};

static ENGINE: Spinlock<Option<Box<dyn DisplayEngine>>> = Spinlock::new(None);

/// Whether the GPU subsystem has been successfully initialised.
pub fn is_initialised() -> bool {
    ENGINE.lock().is_some()
}

/// Initialise the GPU subsystem.
pub fn init_from_bootinfo(fb_config: Option<&crate::entry::FramebufferConfig>) {
    use super::gop::GopEngine;
    #[cfg(target_arch = "x86_64")]
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

    // Priority 2: QEMU Bochs VBE via PCI (port-I/O dispi interface —
    // x86_64 only; the aarch64 virt board has no Bochs VGA and the port
    // access would fault).
    #[cfg(target_arch = "x86_64")]
    {
        serial::put_bytes(b"[gpu::manager] trying Bochs VBE...\n");
        if let Some(bochs) = BochsVbeEngine::new() {
            serial::put_bytes(b"[gpu::manager] using Bochs VBE engine\n");
            store_engine(Box::new(bochs));
            return;
        }
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

    *ENGINE.lock() = Some(boxed);
}

/// Borrow the engine immutably. Panics if not initialised.
pub fn with<F, R>(f: F) -> R
where
    F: FnOnce(&dyn DisplayEngine) -> R,
{
    let engine = ENGINE.lock();
    f(engine.as_deref().expect("gpu::manager: not initialised"))
}

/// Borrow the engine mutably. Panics if not initialised.
pub fn with_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut dyn DisplayEngine) -> R,
{
    let mut engine = ENGINE.lock();
    f(engine.as_deref_mut().expect("gpu::manager: not initialised"))
}

/// Quick diagnostic: name and kind of the current engine.
pub fn current_engine_info() -> (&'static str, EngineKind) {
    if !is_initialised() {
        return ("uninitialised", EngineKind::None);
    }
    with(|e| (e.name(), e.kind()))
}

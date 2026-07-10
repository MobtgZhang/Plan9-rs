//! Network stack data-plane interface.
//!
//! `netstack` exposes the small surface area that the kernel driver
//! layer uses to dispatch a received Ethernet frame or a newly
//! outgoing packet to the right protocol handler. The implementation
//! is intentionally trait-based so that:
//!
//! * The real stack (in `kernel::netstack`) plugs in during boot by
//!   providing an implementation of [`NetBackend`].
//! * Unit tests can substitute a mock backend that just records the
//!   packets it sees.
//! * The same interface is reused by the SMP trampoline so that
//!   per-CPU RX/TX queues can be wired without a second API.
//!
//! # Concurrency
//! All methods take `&self` and use interior mutability (spinlock).
//! The kernel side already serialises the IRQ path so the locking
//! here only protects the protocol-handler table itself.
//!
//! # Safety
//! All `tx_*` methods require that the caller owns the underlying
//! buffers and that they remain valid until the backend returns.

use alloc::vec::Vec;
use plan9_common::sync::Spinlock;

/// Link-layer frame delivered to / from the network stack.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Destination MAC address (6 bytes).
    pub dst: [u8; 6],
    /// Source MAC address (6 bytes).
    pub src: [u8; 6],
    /// EtherType (big-endian).
    pub ethertype: u16,
    /// Payload bytes (already stripped of the 14-byte Ethernet header).
    pub payload: Vec<u8>,
}

/// Protocol handlers invoked by [`NetBackend::dispatch_rx`] when a
/// frame arrives. The handler returns `true` if it consumed the
/// frame; otherwise the backend drops it.
pub type RxHandler = fn(&Frame) -> bool;

/// Single EtherType handler slot.
type EthHandlerSlot = (u16, RxHandler);

/// Backend that the kernel plugs into the network stack at boot.
pub trait NetBackend: Send + Sync {
    /// Inject a freshly received frame into the stack. The backend
    /// dispatches it to whichever protocol handler is registered for
    /// its EtherType.
    fn dispatch_rx(&self, frame: Frame);

    /// Send a frame out the wire. Returns `true` on success.
    fn tx(&self, frame: &Frame) -> bool;
}

/// In-memory backend used when no NIC driver is wired up yet.
///
/// The default kernel build has `install_default_backend` install
/// this so that user-space 9P servers can still mount the network
/// tree (`/net`) without panicking; packets are silently dropped.
pub struct LoopbackBackend {
    rx: Spinlock<Vec<EthHandlerSlot>>,
    tx_log: Spinlock<Vec<Frame>>,
}

impl LoopbackBackend {
    pub const fn new() -> Self {
        Self {
            rx: Spinlock::new(Vec::new()),
            tx_log: Spinlock::new(Vec::new()),
        }
    }

    /// Register a protocol handler for a specific EtherType.
    pub fn register_ethertype(&self, ethertype: u16, h: RxHandler) {
        // Simple linear search — there are at most a handful of
        // protocol handlers (ARP, IPv4, IPv6) so this is fine.
        let mut g = self.rx.lock();
        g.retain(|(et, _)| *et != ethertype);
        g.push((ethertype, h));
    }

    /// Number of frames sent through `tx` since boot. Useful as a
    /// smoke-test that the data plane is alive.
    pub fn tx_count(&self) -> usize {
        self.tx_log.lock().len()
    }
}

impl NetBackend for LoopbackBackend {
    fn dispatch_rx(&self, frame: Frame) {
        let handlers: Vec<EthHandlerSlot> = self.rx.lock().clone();
        for (et, h) in handlers.iter() {
            if *et == frame.ethertype && h(&frame) {
                return;
            }
        }
        // No handler found; silently drop. This matches the Plan 9
        // convention of `/net/ifc/...` filtering, which the kernel
        // performs in user space.
    }

    fn tx(&self, frame: &Frame) -> bool {
        self.tx_log.lock().push(frame.clone());
        true
    }
}

/// Global backend pointer installed during kernel init.
///
/// `None` means the data plane is not yet wired (e.g. before the PCI
/// scan finds a NIC). Drivers must check and either install their
/// own backend via [`set_backend`] or fall back to the default
/// loopback installed by [`install_default_backend`].
static BACKEND: Spinlock<Option<alloc::sync::Arc<dyn NetBackend>>> = Spinlock::new(None);

/// Install a backend. Replaces any previous backend.
pub fn set_backend(b: alloc::sync::Arc<dyn NetBackend>) {
    *BACKEND.lock() = Some(b);
}

/// Install the loopback backend if no backend has been registered.
pub fn install_default_backend() {
    let mut g = BACKEND.lock();
    if g.is_none() {
        *g = Some(alloc::sync::Arc::new(LoopbackBackend::new()));
    }
}

/// Send a frame if a backend is registered, otherwise drop it.
pub fn try_tx(frame: &Frame) -> bool {
    if let Some(b) = BACKEND.lock().as_ref() {
        b.tx(frame)
    } else {
        false
    }
}

/// Inject a frame into whichever backend is registered.
pub fn try_rx(frame: Frame) {
    if let Some(b) = BACKEND.lock().as_ref() {
        b.dispatch_rx(frame);
    }
}
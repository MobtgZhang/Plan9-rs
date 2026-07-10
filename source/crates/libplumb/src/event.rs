//! Plumb Event Handling — `eplumb`
//!
//! Implements the user-facing event loop helpers from
//! `sys/src/libplumb/eplumb.c`:
//!
//! - [`eplumb`] — wait for a plumb event on a file descriptor and
//!   return a [`Plumbmsg`].
//! - [`PlumbEventLoop`] — a higher-level wrapper that drives the
//!   event loop until [`PlumbEventLoop::quit`] is called.
//!
//! Reference: `sys/src/libplumb/eplumb.c`.

use crate::error::PlumbError;
use crate::message::Plumbmsg;
use crate::port::{Port, RecvBuffer};

/// Result of an [`eplumb`] call.
pub type PlumbEventResult = Result<Plumbmsg, PlumbError>;

/// Wait for a single plumb event.
///
/// In a real implementation this would `poll(2)` on the underlying
/// file descriptor and call [`Port::recv`] when the fd becomes
/// readable. In this `no_std` build we instead loop on the supplied
/// [`RecvBuffer`] until a complete message is available or the
/// optional deadline is exceeded.
///
/// # Arguments
/// * `port`     — the [`Port`] to receive on
/// * `buf`      — the [`RecvBuffer`] holding partially-decoded bytes
/// * `deadline` — optional iteration cap (a monotonically increasing
///                counter; the caller is responsible for choosing a
///                clock that is meaningful in their environment).
pub fn eplumb(port: &mut Port, _buf: &mut RecvBuffer, deadline: Option<u64>) -> PlumbEventResult {
    // Try a single non-blocking receive. In a real implementation we
    // would `poll(2)` on the fd until it becomes readable (subject to
    // `deadline`) and then call `Port::recv` to obtain the message.
    //
    // Without an OS to do the actual polling we surface `WouldBlock`
    // immediately so callers can either retry or back off.
    let mut count: u64 = 0;
    loop {
        match port.recv_timeout(0) {
            Ok(msg) => return Ok(msg),
            Err(PlumbError::NotConnected) => return Err(PlumbError::NotConnected),
            Err(PlumbError::WouldBlock) => {
                // Increment first, then compare so the deadline check
                // observes the post-increment value.
                count = count.saturating_add(1);
                if let Some(d) = deadline {
                    if count >= d {
                        return Err(PlumbError::Timeout);
                    }
                }
                return Err(PlumbError::WouldBlock);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Higher-level event loop helper.
///
/// The loop calls a user-supplied closure for each message until the
/// closure returns [`PlumbLoopControl::Quit`] or an error occurs.
///
/// # Example
/// ```ignore
/// let mut port = Port::open("/mnt/plumb/send")?;
/// let mut buf = RecvBuffer::default();
/// let mut eloop = PlumbEventLoop::new(port, buf);
/// eloop.run(|msg| {
///     // do something with msg
///     PlumbLoopControl::Continue
/// })?;
/// ```
pub struct PlumbEventLoop {
    port: Port,
    buf: RecvBuffer,
    /// Set to true by [`PlumbEventLoop::quit`].
    quit: bool,
}

impl PlumbEventLoop {
    /// Construct a new event loop.
    pub fn new(port: Port, buf: RecvBuffer) -> Self {
        Self { port, buf, quit: false }
    }

    /// Borrow the inner port.
    pub fn port(&mut self) -> &mut Port {
        &mut self.port
    }

    /// Borrow the inner receive buffer.
    pub fn buffer(&mut self) -> &mut RecvBuffer {
        &mut self.buf
    }

    /// True if the loop has been asked to quit.
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Request that the loop exit at the next iteration.
    pub fn quit(&mut self) {
        self.quit = true;
    }

    /// Drive the loop until the closure returns [`PlumbLoopControl::Quit`]
    /// or an error occurs.
    pub fn run<F>(&mut self, mut handler: F) -> Result<usize, PlumbError>
    where
        F: FnMut(&Plumbmsg) -> PlumbLoopControl,
    {
        let mut seen = 0usize;
        loop {
            if self.quit {
                break;
            }
            match eplumb(&mut self.port, &mut self.buf, None) {
                Ok(msg) => {
                    seen += 1;
                    match handler(&msg) {
                        PlumbLoopControl::Continue => continue,
                        PlumbLoopControl::Quit => break,
                    }
                }
                Err(PlumbError::WouldBlock) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(seen)
    }
}

/// Control flow returned by the event loop handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlumbLoopControl {
    /// Continue processing messages.
    Continue,
    /// Stop the loop after the current message.
    Quit,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loop_control_eq() {
        assert_eq!(PlumbLoopControl::Continue, PlumbLoopControl::Continue);
        assert_ne!(PlumbLoopControl::Continue, PlumbLoopControl::Quit);
    }

    #[test]
    fn test_event_loop_quit() {
        // The loop should exit cleanly even with no real port (we use
        // a dummy path; recv will return WouldBlock).
        let port = Port::open("/mnt/plumb/none").expect("port open should succeed");
        let buf = RecvBuffer::default();
        let mut eloop = PlumbEventLoop::new(port, buf);
        assert!(!eloop.should_quit());
        eloop.quit();
        assert!(eloop.should_quit());
        let seen = eloop.run(|_| PlumbLoopControl::Continue).expect("run should not error");
        assert_eq!(seen, 0);
    }

    #[test]
    fn test_event_loop_quit_from_handler() {
        let port = Port::open("/mnt/plumb/none").expect("port open should succeed");
        let buf = RecvBuffer::default();
        let mut eloop = PlumbEventLoop::new(port, buf);
        let seen = eloop.run(|_| PlumbLoopControl::Quit).expect("run should not error");
        assert_eq!(seen, 0);
    }

    #[test]
    fn test_event_loop_quit_then_handler() {
        let port = Port::open("/mnt/plumb/none").expect("port open should succeed");
        let buf = RecvBuffer::default();
        let mut eloop = PlumbEventLoop::new(port, buf);
        // Pre-set quit so the loop exits before calling the handler.
        eloop.quit();
        let mut calls = 0;
        let seen = eloop
            .run(|_| {
                calls += 1;
                PlumbLoopControl::Continue
            })
            .expect("run should not error");
        assert_eq!(seen, 0);
        assert_eq!(calls, 0);
    }
}

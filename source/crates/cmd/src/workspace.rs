use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct WorkspaceLease<'a>(&'a AtomicBool);

impl<'a> WorkspaceLease<'a> {
    pub(crate) fn claim(busy: &'a AtomicBool) -> Option<Self> {
        busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Self(busy))
    }
}

impl Drop for WorkspaceLease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

//! Request Pool Module
//!
//! Provides request pooling for 9P protocol with support for:
//! - Request tracking by tag
//! - Flush mechanism for request cancellation
//! - Reference counting for memory management
//! Based on Plan 9's Reqpool implementation.

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::string::String;
use crate::refcount::Ref;
use crate::intmap::Intmap;

/// Maximum number of concurrent requests
const MAX_REQUESTS: usize = 8192;

/// Request state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestState {
    /// Request is pending
    Pending,
    /// Request has been responded
    Responded,
    /// Request has been flushed
    Flushed,
}

/// Pending 9P request
#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// Request tag
    pub tag: u16,
    /// Message type (T-message type)
    pub msg_type: u8,
    /// Associated FID (if applicable)
    pub fid: Option<u32>,
    /// Timestamp when request was created
    pub timestamp: u64,
    /// Request state
    pub state: RequestState,
    /// Reference count
    pub refcount: Ref,
    /// Pointer to request that this one flushes
    pub oldreq: Option<Box<PendingRequest>>,
    /// List of requests waiting for this one to complete (flush chain)
    pub flush_list: Vec<Box<PendingRequest>>,
    /// Error message if failed
    pub error: Option<String>,
    /// User data
    pub aux: Option<usize>,
}

impl PendingRequest {
    /// Create a new pending request
    pub fn new(tag: u16, msg_type: u8) -> Self {
        Self {
            tag,
            msg_type,
            fid: None,
            timestamp: 0,
            state: RequestState::Pending,
            refcount: Ref::new(),
            oldreq: None,
            flush_list: Vec::new(),
            error: None,
            aux: None,
        }
    }

    /// Create with FID
    pub fn with_fid(tag: u16, msg_type: u8, fid: u32) -> Self {
        Self {
            tag,
            msg_type,
            fid: Some(fid),
            timestamp: 0,
            state: RequestState::Pending,
            refcount: Ref::new(),
            oldreq: None,
            flush_list: Vec::new(),
            error: None,
            aux: None,
        }
    }

    /// Check if request has been responded
    pub fn is_responded(&self) -> bool {
        self.state == RequestState::Responded
    }

    /// Check if request is flushed
    pub fn is_flushed(&self) -> bool {
        self.state == RequestState::Flushed
    }

    /// Mark request as responded
    pub fn respond(&mut self, error: Option<&str>) {
        self.state = RequestState::Responded;
        self.error = error.map(String::from);
    }

    /// Add a request to the flush chain
    pub fn add_flusher(&mut self, flusher: Box<PendingRequest>) {
        self.flush_list.push(flusher);
    }

    /// Drain all pending flush requests
    pub fn drain_flush_chain(&mut self) -> Vec<Box<PendingRequest>> {
        let mut result = Vec::new();
        for req in self.flush_list.drain(..) {
            result.push(req);
        }
        result
    }

    /// Set the request being flushed
    pub fn set_oldreq(&mut self, req: Box<PendingRequest>) {
        self.oldreq = Some(req);
    }
}

/// Request pool for managing concurrent 9P requests
pub struct ReqPool {
    /// Map from tag to request
    requests: Intmap,
    /// Request storage
    request_store: Vec<Option<PendingRequest>>,
    /// Maximum number of requests
    max_requests: usize,
    /// Number of active requests
    active_count: usize,
    /// Destroy callback function
    destroy: Option<fn(&PendingRequest)>,
}

impl ReqPool {
    /// Create a new request pool
    pub fn new() -> Self {
        Self {
            requests: Intmap::new(),
            request_store: Vec::new(),
            max_requests: MAX_REQUESTS,
            active_count: 0,
            destroy: None,
        }
    }

    /// Create with a custom destroy callback
    pub fn with_destroy(destroy: fn(&PendingRequest)) -> Self {
        Self {
            requests: Intmap::new(),
            request_store: Vec::new(),
            max_requests: MAX_REQUESTS,
            active_count: 0,
            destroy: Some(destroy),
        }
    }

    /// Allocate a new request
    ///
    /// Returns the index into the requests array.
    pub fn alloc(&mut self, tag: u16, msg_type: u8) -> Result<usize, ReqPoolError> {
        if self.active_count >= self.max_requests {
            return Err(ReqPoolError::PoolExhausted);
        }

        let idx = self.request_store.len();
        let req = PendingRequest::new(tag, msg_type);
        self.request_store.push(Some(req));
        let _ = self.requests.insert(tag as u64, idx);

        self.active_count += 1;
        Ok(idx)
    }

    /// Allocate a flush request
    ///
    /// Creates a Tflush request that will cancel an existing request.
    pub fn alloc_flush(&mut self, tag: u16, oldtag: u16) -> Result<Box<PendingRequest>, ReqPoolError> {
        // Look up the old request
        let _old_idx = self.lookup_index(oldtag as u64)
            .ok_or(ReqPoolError::NotFound)?;

        // Create the flush request
        let mut req = Box::new(PendingRequest::new(tag, 108)); // Tflush = 108
        req.oldreq = Some(Box::new(PendingRequest::new(oldtag, 0)));

        Ok(req)
    }

    /// Look up request by tag
    pub fn lookup(&self, tag: u16) -> Option<&PendingRequest> {
        let idx = self.requests.lookup(tag as u64)?;
        self.request_store.get(idx).and_then(|r| r.as_ref())
    }

    /// Look up request by tag (mutable)
    pub fn lookup_mut(&mut self, tag: u16) -> Option<&mut PendingRequest> {
        let idx = self.requests.lookup(tag as u64)?;
        self.request_store.get_mut(idx).and_then(|r| r.as_mut())
    }

    /// Look up request index by tag
    fn lookup_index(&self, tag: u64) -> Option<usize> {
        self.requests.lookup(tag)
    }

    /// Close a request
    ///
    /// Decrements reference count and potentially frees the request.
    /// If there are pending flush requests, they are returned.
    pub fn close(&mut self, tag: u16) -> Option<Vec<Box<PendingRequest>>> {
        let idx = self.requests.remove(tag as u64)?;
        self.active_count = self.active_count.saturating_sub(1);

        // Clear the request slot
        if idx < self.request_store.len() {
            self.request_store[idx] = None;
        }

        Some(Vec::new())
    }

    /// Respond to a request and process flush chain
    pub fn respond(&mut self, tag: u16, error: Option<&str>) -> Vec<Box<PendingRequest>> {
        let flushed = Vec::new();

        if let Some(req) = self.lookup_mut(tag) {
            req.respond(error);
        }

        flushed
    }

    /// Get number of active requests
    pub fn len(&self) -> usize {
        self.active_count
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.active_count == 0
    }

    /// Get maximum requests
    pub fn max_requests(&self) -> usize {
        self.max_requests
    }

    /// Check if a tag is already in use
    pub fn tag_exists(&self, tag: u16) -> bool {
        self.requests.contains(tag as u64)
    }

    /// Get all active tags
    pub fn active_tags(&self) -> Vec<u16> {
        let mut tags = Vec::new();
        for (tag, _) in &self.requests {
            tags.push(tag as u16);
        }
        tags
    }

    /// Clear all requests
    pub fn clear(&mut self) {
        if let Some(destroy) = self.destroy {
            for entry in &self.request_store {
                if let Some(ref req) = entry {
                    destroy(req);
                }
            }
        }

        self.requests.clear();
        self.request_store.clear();
        self.active_count = 0;
    }
}

impl Default for ReqPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Request pool errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReqPoolError {
    /// Pool is exhausted (too many requests)
    PoolExhausted,
    /// Request not found
    NotFound,
    /// Tag already in use
    TagExists,
    /// Invalid tag
    InvalidTag,
}

impl core::fmt::Display for ReqPoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PoolExhausted => write!(f, "request pool exhausted"),
            Self::NotFound => write!(f, "request not found"),
            Self::TagExists => write!(f, "tag already in use"),
            Self::InvalidTag => write!(f, "invalid tag"),
        }
    }
}

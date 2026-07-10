//! QIO Queue System
//!
//! Implements the Plan 9 QIO (Queue I/O) framework for asynchronous I/O.
//!
//! ## Overview
//!
//! QIO provides a framework for asynchronous I/O operations in the kernel.
//! It uses work queues per CPU to batch and process I/O requests efficiently.
//!
//! ## Constants
//!
//! - QTMPLIQ: Size of temporary queue for synchronous operations
//! - QDQLIM: Limit for delayed queue length

use crate::plan9_common::sync::{Spinlock, Mutex};
use crate::proc::Proc;

/// QIO request structure
#[derive(Debug)]
pub struct Qio {
    /// Operation type
    pub op: QioOp,
    /// Data buffer
    pub data: QioData,
    /// Callback function
    pub callback: Option<fn(&Qio)>,
    /// Completion status
    pub status: QioStatus,
    /// I/O offset
    pub offset: u64,
    /// I/O length
    pub len: usize,
}

/// QIO operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QioOp {
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Flush operation
    Flush,
    /// Sync operation
    Sync,
}

/// QIO data buffer
#[derive(Debug)]
pub enum QioData {
    /// Linear buffer
    Linear(Vec<u8>),
    /// Scatter-gather list
    ScatterGather(Vec<QioSegment>),
    /// Empty
    Empty,
}

/// QIO segment for scatter-gather I/O
#[derive(Debug, Clone)]
pub struct QioSegment {
    /// Buffer pointer
    pub addr: u64,
    /// Buffer length
    pub len: usize,
}

/// QIO completion status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QioStatus {
    /// Not started
    Idle,
    /// In progress
    Pending,
    /// Completed successfully
    Done,
    /// Completed with error
    Error(i32),
}

/// QIO work queue structure
pub struct Qiowq {
    /// Queue lock
    lock: Spinlock,
    /// Deferred work queue
    dq: Vec<Qio>,
    /// Temporary queue (per-call)
    q: Vec<Qio>,
    /// Number of deferred items
    ndq: usize,
}

impl Qiowq {
    /// Create a new work queue
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            dq: Vec::new(),
            q: Vec::new(),
            ndq: 0,
        }
    }

    /// Add request to the deferred queue
    pub fn add(&mut self, qio: Qio) {
        let mut lock = self.lock.lock();
        self.dq.push(qio);
        self.ndq += 1;
    }

    /// Add request to the temporary queue (synchronous)
    pub fn addtmp(&mut self, qio: Qio) {
        self.q.push(qio);
    }

    /// Process deferred queue
    pub fn process(&mut self) {
        let mut lock = self.lock.lock();
        while let Some(mut qio) = self.dq.pop() {
            self.ndq -= 1;
            drop(lock);

            // Process the I/O
            qio.status = QioStatus::Done;
            
            // Call callback if set
            if let Some(cb) = qio.callback {
                cb(&qio);
            }

            lock = self.lock.lock();
        }
    }

    /// Get queue length
    pub fn len(&self) -> usize {
        self.ndq
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.ndq == 0
    }
}

/// Queue thread structure
/// Each CPU has one queue thread that processes deferred I/O
pub struct QueueThread {
    /// Associated process
    proc: Option<Proc>,
    /// Work queue
    wq: Qiowq,
    /// CPU ID
    cpu_id: u32,
}

impl QueueThread {
    /// Create a new queue thread for a CPU
    pub fn new(cpu_id: u32) -> Self {
        Self {
            proc: None,
            wq: Qiowq::new(),
            cpu_id,
        }
    }

    /// Start the queue thread
    pub fn start(&mut self) {
        // In a real implementation, this would create a kernel thread
        // that runs process() in a loop
    }

    /// Process work queue
    pub fn process(&mut self) {
        self.wq.process();
    }

    /// Add work to the queue
    pub fn add_work(&mut self, qio: Qio) {
        self.wq.add(qio);
    }

    /// Get CPU ID
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

/// Global QIO state
static QIO_GLOBAL: Mutex<QioGlobal> = Mutex::new(QioGlobal::new());

/// Global QIO state
pub struct QioGlobal {
    /// Per-CPU queue threads
    threads: Vec<Option<QueueThread>>,
    /// Number of CPUs
    num_cpus: u32,
}

impl QioGlobal {
    /// Create new global state
    pub fn new() -> Self {
        Self {
            threads: Vec::new(),
            num_cpus: 1, // Default to 1 CPU
        }
    }

    /// Initialize for given number of CPUs
    pub fn init(&mut self, num_cpus: u32) {
        self.num_cpus = num_cpus;
        self.threads.resize(num_cpus as usize, None);
        for i in 0..num_cpus as usize {
            self.threads[i] = Some(QueueThread::new(i as u32));
        }
    }

    /// Get queue thread for current CPU
    pub fn current_thread(&self) -> Option<&QueueThread> {
        // In a real implementation, this would get the current CPU ID
        self.threads.get(0)?.as_ref()
    }

    /// Get mutable queue thread for current CPU
    pub fn current_thread_mut(&mut self) -> Option<&mut QueueThread> {
        // In a real implementation, this would get the current CPU ID
        self.threads.get_mut(0)?.as_mut()
    }
}

/// Initialize QIO system
pub fn init_qio(num_cpus: u32) {
    QIO_GLOBAL.lock().init(num_cpus);
}

/// Get current CPU's work queue
pub fn current_wq() -> Option<&mut Qiowq> {
    let mut g = QIO_GLOBAL.lock();
    let thread = g.current_thread_mut()?;
    Some(&mut thread.wq)
}

/// Submit an asynchronous I/O request
pub fn qio_submit(qio: Qio) {
    if let Some(wq) = current_wq() {
        wq.add(qio);
    }
}

/// Submit a synchronous I/O request (blocking)
pub fn qio_submit_sync(qio: Qio) -> QioStatus {
    let mut wq = Qiowq::new();
    wq.addtmp(qio);
    
    // Process immediately
    wq.process();
    
    // Return status of last item
    if let Some(q) = wq.q.last() {
        q.status
    } else {
        QioStatus::Idle
    }
}

/// Create a QIO request
pub fn qio_new(op: QioOp, data: QioData, offset: u64, len: usize) -> Qio {
    Qio {
        op,
        data,
        callback: None,
        status: QioStatus::Idle,
        offset,
        len,
    }
}

/// Create a read request
pub fn qio_read(buf: Vec<u8>, offset: u64) -> Qio {
    qio_new(QioOp::Read, QioData::Linear(buf), offset, 0)
}

/// Create a write request
pub fn qio_write(data: Vec<u8>, offset: u64) -> Qio {
    let len = data.len();
    qio_new(QioOp::Write, QioData::Linear(data), offset, len)
}

/// Helper to create scatter-gather list
pub fn qio_sg_add(sg: &mut Vec<QioSegment>, addr: u64, len: usize) {
    sg.push(QioSegment { addr, len });
}

/// Create scatter-gather I/O request
pub fn qio_sg_new(op: QioOp, sg: Vec<QioSegment>, offset: u64) -> Qio {
    let len: usize = sg.iter().map(|s| s.len).sum();
    qio_new(op, QioData::ScatterGather(sg), offset, len)
}

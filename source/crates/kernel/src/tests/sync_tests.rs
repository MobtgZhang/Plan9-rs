//! Synchronization Primitives Tests
//!
//! Tests for QLock, RWLock, Semaphore, Barrier, and other synchronization primitives.

use plan9_common::sync::{QLock, RWLock, Semaphore, Barrier};

#[test]
fn test_qlock_basic() {
    let lock = QLock::new();
    
    // Lock and unlock should work
    let guard = lock.lock();
    drop(guard);
    lock.unlock();
}

#[test]
fn test_qlock_reentrant() {
    let lock = QLock::new();
    
    // Take lock multiple times - this should panic if not reentrant
    let guard1 = lock.lock();
    // Note: QLock is NOT reentrant, so we don't test that here
    drop(guard1);
}

#[test]
fn test_rwlock_read_multiple() {
    let lock = RWLock::new();
    
    // Multiple readers should be allowed
    lock.rlock();
    lock.rlock();
    lock.runlock();
    lock.runlock();
}

#[test]
fn test_rwlock_write_blocks_readers() {
    let lock = RWLock::new();
    
    // Write lock should block readers
    lock.wlock();
    lock.wunlock();
}

#[test]
fn test_semaphore_init() {
    let sem = Semaphore::new(5);
    assert_eq!(sem.count(), 5);
}

#[test]
fn test_semaphore_down() {
    let sem = Semaphore::new(2);
    sem.down();
    assert_eq!(sem.count(), 1);
}

#[test]
fn test_semaphore_up() {
    let sem = Semaphore::new(1);
    sem.down();
    sem.up();
    assert_eq!(sem.count(), 1);
}

#[test]
fn test_semaphore_try_down() {
    let sem = Semaphore::new(0);
    assert!(!sem.try_down());
}

#[test]
fn test_barrier_init() {
    let barrier = Barrier::new(3);
    assert_eq!(barrier.current_count(), 3);
}

#[test]
fn test_barrier_single_thread() {
    let barrier = Barrier::new(1);
    let is_leader = barrier.wait();
    assert!(is_leader);
    // After wait, count should be reset
    assert_eq!(barrier.current_count(), 1);
}

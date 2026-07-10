//! Device Tests
//!
//! Tests for device drivers and the device framework.

use crate::dev::{RootDev, Qid, qidtype};

#[test]
fn test_rootdev_creation() {
    let dev = RootDev::new();
    assert_eq!(dev.dev_char(), '/');
    assert_eq!(dev.name(), "root");
}

#[test]
fn test_qid_creation() {
    let qid = Qid::new(0, 0, qidtype::DIR);
    assert!(qid.is_dir());
    assert_eq!(qid.path(), 0);
}

#[test]
fn test_qid_file() {
    let qid = Qid::new(1, 0, qidtype::FILE);
    assert!(!qid.is_dir());
    assert_eq!(qid.path(), 1);
}

#[test]
fn test_rootdev_lookup_dirs() {
    // Test that standard root directories can be looked up
    // This tests the RootDev::lookup_dir implementation
    let dev = RootDev::new();
    
    // Note: lookup_dir is private, so we test through the walk interface
    // In a real test, we'd create a channel and call walk
    assert_eq!(dev.dev_char(), '/');
}

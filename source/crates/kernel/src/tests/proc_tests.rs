//! Process Tests
//!
//! Tests for process management including state transitions.

use crate::proc::{State, Proc};

#[test]
fn test_process_state_default() {
    let state = State::default();
    assert_eq!(state, State::Ready);
}

#[test]
fn test_process_state_variants() {
    // Test that all state variants exist
    let _ = State::Ready;
    let _ = State::Wakeme(0);
    let _ = State::Moribund;
    let _ = State::Idle;
    let _ = State::Zombie;
}

#[test]
fn test_process_state_is_schedulable() {
    // Ready and Idle states are schedulable
    assert!(State::Ready.is_schedulable());
    assert!(State::Idle.is_schedulable());
    
    // Other states are not schedulable
    assert!(!State::Moribund.is_schedulable());
    assert!(!State::Zombie.is_schedulable());
}

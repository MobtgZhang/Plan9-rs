//! `units` — trivially honour Plan 9's `units` interface for the few
//! conversions this prototype knows: `units 1kb` style isn't wired to a
//! database; the command prints its supported table instead.

pub fn main(_argc: usize, _argv: *const *const u8) -> i32 {
    crate::outln("units: conversion table (subset)");
    crate::outln("  1 kb = 1024 bytes");
    crate::outln("  1 mb = 1024 kb");
    crate::outln("  1 gb = 1024 mb");
    crate::outln("  1 min = 60 sec");
    crate::outln("  1 hour = 60 min");
    crate::outln("  1 day = 24 hours");
    0
}

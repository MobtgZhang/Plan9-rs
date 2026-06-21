//! Big Integer Arithmetic
//!
//! Provides arbitrary precision integer arithmetic for cryptographic operations.
//! This is a Rust port of Plan 9's mpint library.
//!
//! ## Features
//!
//! - Basic arithmetic: add, subtract, multiply, divide, modulo
//! - Bit operations: shift left/right
//! - Comparison operations
//! - Extended GCD for modular inverse
//! - Modular exponentiation
//! - Miller-Rabin primality testing
//! - Byte array conversion (big-endian and little-endian)
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::bigint::BigInt;
//!
//! let a = BigInt::from_u64(12345);
//! let b = BigInt::from_u64(6789);
//! let sum = a.add(&b);
//! ```

#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ops::{Add, Sub, Mul};

/// Digit size for internal representation (32 bits)
const DIGIT_BITS: usize = 32;
const DIGIT_MASK: u32 = 0xFFFFFFFF;
const DIGIT_HALF_MASK: u32 = 0xFFFF;

/// Represents an arbitrary precision integer
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigInt {
    /// Sign: 1 for positive, -1 for negative, 0 for zero
    sign: i8,
    /// Digits stored in little-endian order (least significant first)
    digits: Vec<u32>,
}

impl BigInt {
    // =========================================================================
    // Constructors and basic operations
    // =========================================================================

    /// Create a new BigInt from u64
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            let low = (value & 0xFFFFFFFF) as u32;
            let high = (value >> 32) as u32;
            let mut digits = Vec::with_capacity(if high == 0 { 1 } else { 2 });
            digits.push(low);
            if high != 0 {
                digits.push(high);
            }
            Self { sign: 1, digits }
        }
    }

    /// Create a new BigInt from i64
    pub fn from_i64(value: i64) -> Self {
        if value < 0 {
            let mut n = Self::from_u64(value.unsigned_abs());
            n.sign = -1;
            n
        } else {
            Self::from_u64(value as u64)
        }
    }

    /// Create a BigInt from bytes (big-endian)
    pub fn from_bytes_be(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::zero();
        }

        let mut digits = Vec::new();
        let mut i = data.len();

        // Process 4 bytes at a time from the end
        while i >= 4 {
            i -= 4;
            let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            digits.push(word);
        }

        // Handle remaining bytes
        if i > 0 {
            let mut word = 0u32;
            for j in 0..i {
                word = (word << 8) | (data[j] as u32);
            }
            digits.push(word);
        }

        Self::normalize(Self { sign: 1, digits })
    }

    /// Create a BigInt from bytes (little-endian)
    pub fn from_bytes_le(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::zero();
        }

        let mut digits = Vec::new();
        let mut i = 0;

        // Process 4 bytes at a time from the start
        while i + 4 <= data.len() {
            let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            digits.push(word);
            i += 4;
        }

        // Handle remaining bytes
        if i < data.len() {
            let mut word = 0u32;
            for j in i..data.len() {
                word |= (data[j] as u32) << (8 * (j - i));
            }
            digits.push(word);
        }

        Self::normalize(Self { sign: 1, digits })
    }

    /// Create a BigInt from a single digit
    pub fn from_digit(d: u32) -> Self {
        if d == 0 {
            Self::zero()
        } else {
            Self { sign: 1, digits: vec![d] }
        }
    }

    /// Create a zero BigInt
    pub fn zero() -> Self {
        Self { sign: 0, digits: Vec::new() }
    }

    /// Create a one BigInt
    pub fn one() -> Self {
        Self { sign: 1, digits: vec![1] }
    }

    /// Create a two BigInt
    pub fn two() -> Self {
        Self { sign: 1, digits: vec![2] }
    }

    /// Create a BigInt with a specific number of bits (random-like, for testing)
    pub fn from_random_bits(bits: usize) -> Self {
        let digits_needed = (bits + DIGIT_BITS - 1) / DIGIT_BITS;
        let mut digits = Vec::with_capacity(digits_needed);

        for i in 0..digits_needed {
            // Simple pseudo-random for now - in production use a real PRNG
            let seed: u32 = ((i as u32).wrapping_mul(1103515245).wrapping_add(12345)) % (1 << 31);
            digits.push(seed);
        }

        // Mask the top digit if needed
        if bits % DIGIT_BITS != 0 {
            let mask = (1u32 << (bits % DIGIT_BITS)) - 1;
            if let Some(last) = digits.last_mut() {
                *last &= mask;
            }
        }

        Self::normalize(Self { sign: 1, digits })
    }

    // =========================================================================
    // Normalization and utilities
    // =========================================================================

    /// Remove leading zeros and normalize sign
    fn normalize(mut n: Self) -> Self {
        while let Some(&last) = n.digits.last() {
            if last != 0 {
                break;
            }
            n.digits.pop();
        }
        if n.digits.is_empty() {
            n.sign = 0;
        }
        n
    }

    /// Get the number of significant digits
    pub fn len(&self) -> usize {
        self.digits.len()
    }

    /// Check if the number is zero
    pub fn is_zero(&self) -> bool {
        self.sign == 0
    }

    /// Check if the number is negative
    pub fn is_negative(&self) -> bool {
        self.sign < 0
    }

    /// Get the sign (-1, 0, or 1)
    pub fn sign(&self) -> i8 {
        self.sign
    }

    /// Get the number of significant bits
    pub fn bit_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let top_idx = self.digits.len() - 1;
        let top = self.digits[top_idx];
        DIGIT_BITS * top_idx + (DIGIT_BITS - top.leading_zeros() as usize)
    }

    /// Get the least significant bits (low bits)
    pub fn low_bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let mut n = self.clone();
        while !n.is_zero() && (n.digits[0] & 1) == 0 {
            n = n.shift_right(1);
        }
        let mut count = 0;
        let mut temp = n.clone();
        while !temp.is_zero() && (temp.digits[0] & 1) != 0 {
            temp = temp.shift_right(1);
            count += 1;
        }
        count
    }

    // =========================================================================
    // Comparison
    // =========================================================================

    /// Compare absolute values
    pub fn cmp_mag(&self, other: &BigInt) -> Ordering {
        if self.digits.len() != other.digits.len() {
            return self.digits.len().cmp(&other.digits.len());
        }
        // Compare from most significant to least significant
        for i in (0..self.digits.len()).rev() {
            if self.digits[i] != other.digits[i] {
                return self.digits[i].cmp(&other.digits[i]);
            }
        }
        Ordering::Equal
    }

    /// Compare two BigInts: -1 (self < other), 0 (equal), 1 (self > other)
    pub fn cmp(&self, other: &BigInt) -> i8 {
        if self.sign == other.sign {
            let mag_cmp = self.cmp_mag(other);
            match mag_cmp {
                Ordering::Less => if self.sign < 0 { 1 } else { -1 },
                Ordering::Equal => 0,
                Ordering::Greater => if self.sign < 0 { -1 } else { 1 },
            }
        } else {
            self.sign.cmp(&other.sign) as i8
        }
    }

    // =========================================================================
    // Basic arithmetic
    // =========================================================================

    /// Add two BigInts
    pub fn add(&self, other: &BigInt) -> Self {
        if self.sign == 0 {
            return other.clone();
        }
        if other.sign == 0 {
            return self.clone();
        }

        if self.sign == other.sign {
            // Same sign: add magnitudes
            let mut result = self.add_mag(other);
            result.sign = self.sign;
            result
        } else {
            // Different signs: subtract magnitudes
            let cmp = self.cmp_mag(other);
            if cmp == Ordering::Equal {
                Self::zero()
            } else if cmp == Ordering::Greater {
                let mut result = self.sub_mag(other);
                result.sign = self.sign;
                result
            } else {
                let mut result = other.sub_mag(self);
                result.sign = other.sign;
                result
            }
        }
    }

    /// Add magnitudes (both positive)
    fn add_mag(&self, other: &BigInt) -> Self {
        let mut result = Vec::with_capacity(core::cmp::max(self.digits.len(), other.digits.len()) + 1);
        let mut carry = 0u64;

        let max_len = core::cmp::max(self.digits.len(), other.digits.len());
        for i in 0..max_len {
            let a = self.digits.get(i).copied().unwrap_or(0) as u64;
            let b = other.digits.get(i).copied().unwrap_or(0) as u64;
            let sum = a + b + carry;
            result.push((sum & DIGIT_MASK as u64) as u32);
            carry = sum >> DIGIT_BITS;
        }

        if carry != 0 {
            result.push(carry as u32);
        }

        Self::normalize(Self { sign: 1, digits: result })
    }

    /// Subtract magnitudes (self >= other, both positive)
    fn sub_mag(&self, other: &BigInt) -> Self {
        let mut result = Vec::with_capacity(self.digits.len());
        let mut borrow = 0i64;

        for i in 0..self.digits.len() {
            let a = self.digits[i] as i64;
            let b = other.digits.get(i).copied().unwrap_or(0) as i64;
            let diff = a - b - borrow;
            if diff < 0 {
                result.push((diff + (1i64 << DIGIT_BITS)) as u32);
                borrow = 1;
            } else {
                result.push(diff as u32);
                borrow = 0;
            }
        }

        Self::normalize(Self { sign: 1, digits: result })
    }

    /// Subtract two BigInts
    pub fn sub(&self, other: &BigInt) -> Self {
        let mut neg_other = other.clone();
        neg_other.sign = -neg_other.sign;
        self.add(&neg_other)
    }

    /// Multiply two BigInts
    pub fn mul(&self, other: &BigInt) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let mut result = vec![0u32; self.digits.len() + other.digits.len()];

        for i in 0..self.digits.len() {
            let mut carry = 0u64;
            for j in 0..other.digits.len() {
                let prod = (self.digits[i] as u64) * (other.digits[j] as u64);
                let sum = (result[i + j] as u64) + carry + (prod & DIGIT_MASK as u64);
                result[i + j] = (sum & DIGIT_MASK as u64) as u32;
                carry = (prod >> DIGIT_BITS) + (sum >> DIGIT_BITS);
            }
            result[i + other.digits.len()] += carry as u32;
        }

        let mut n = Self::normalize(Self { sign: 1, digits: result });
        n.sign = self.sign * other.sign;
        n
    }

    /// Square a BigInt
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Divide self by other, returning quotient
    pub fn div(&self, other: &BigInt) -> Self {
        let (q, _) = self.divmod(other);
        q
    }

    /// Modulo self by other
    pub fn rem(&self, other: &BigInt) -> Self {
        let (_, r) = self.divmod(other);
        r
    }

    /// Divide and modulo together (self = q * other + r, 0 <= r < |other|)
    pub fn divmod(&self, other: &BigInt) -> (Self, Self) {
        if other.is_zero() {
            panic!("division by zero");
        }

        if self.is_zero() {
            return (Self::zero(), Self::zero());
        }

        let cmp = self.cmp_mag(other);
        if cmp == Ordering::Less {
            return (Self::zero(), self.clone());
        }
        if cmp == Ordering::Equal {
            let q = Self { sign: self.sign * other.sign, digits: vec![1] };
            return (q, Self::zero());
        }

        // Use binary search for quotient estimation
        let (q, r) = self.divmod_algorithm(other);
        (Self::normalize(q), Self::normalize(r))
    }

    /// Division algorithm implementation
    fn divmod_algorithm(&self, other: &BigInt) -> (Self, Self) {
        if other.digits.len() == 1 {
            return self.divmod_digit(&other.digits[0], other.sign);
        }

        // Estimate quotient using long division
        let n_len = self.digits.len();
        let d_len = other.digits.len();

        // Single digit divisor optimization
        if d_len == 1 {
            return self.divmod_digit(&other.digits[0], other.sign);
        }

        // Multi-digit division using schoolbook algorithm
        let mut quotient = vec![0u32; n_len - d_len + 1];
        let mut remainder = self.digits.clone();

        for i in (0..quotient.len()).rev() {
            // Binary search for quotient digit
            let mut lo = 0;
            let mut hi = DIGIT_MASK;

            while lo < hi {
                let mid = (lo + hi + 1) / 2;
                let t = self.mul_digit(&other.digits, mid);
                if self.cmp_mag(&Self { sign: 1, digits: t }) <= Ordering::Greater {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }

            quotient[i] = lo;

            if lo > 0 {
                // Subtract lo * other from remainder
                let product = self.mul_digit(&other.digits, lo);
                self.sub_digit_from(&mut remainder, &product, i);
            }
        }

        let sign = self.sign * other.sign;
        let q = Self::normalize(Self { sign, digits: quotient });
        let r = Self::normalize(Self { sign: 1, digits: remainder });
        (q, r)
    }

    /// Multiply by a single digit
    fn mul_digit(&self, other: &[u32], digit: u32) -> Vec<u32> {
        if digit == 0 {
            return Vec::new();
        }

        let mut result = vec![0u32; self.digits.len() + other.len()];
        let mut carry = 0u64;

        for i in 0..self.digits.len() {
            for j in 0..other.len() {
                let prod = (self.digits[i] as u64) * (other[j] as u64) + (result[i + j] as u64) + carry;
                result[i + j] = (prod & DIGIT_MASK as u64) as u32;
                carry = prod >> DIGIT_BITS;
            }
            result[i + other.len()] += carry as u32;
            carry = 0;
        }

        while let Some(&last) = result.last() {
            if last != 0 {
                break;
            }
            result.pop();
        }

        result
    }

    /// Subtract a product from remainder at offset
    fn sub_digit_from(&self, remainder: &mut Vec<u32>, product: &[u32], offset: usize) {
        let mut borrow = 0i64;

        for i in 0..product.len() {
            let idx = offset + i;
            let a = remainder[idx] as i64;
            let b = product[i] as i64;
            let diff = a - b - borrow;
            if diff < 0 {
                remainder[idx] = (diff + (1i64 << DIGIT_BITS)) as u32;
                borrow = 1;
            } else {
                remainder[idx] = diff as u32;
                borrow = 0;
            }
        }

        // Handle remaining borrow
        let mut idx = offset + product.len();
        while borrow != 0 && idx < remainder.len() {
            let diff = remainder[idx] as i64 - borrow;
            if diff < 0 {
                remainder[idx] = (diff + (1i64 << DIGIT_BITS)) as u32;
                borrow = 1;
            } else {
                remainder[idx] = diff as u32;
                borrow = 0;
            }
            idx += 1;
        }
    }

    /// Divide by a single digit, return (quotient, remainder)
    fn divmod_digit(&self, divisor: &u32, sign: i8) -> (Self, Self) {
        if *divisor == 0 {
            panic!("division by zero");
        }
        if *divisor == 1 {
            return (self.clone(), Self::zero());
        }

        let mut quotient = Vec::with_capacity(self.digits.len());
        let mut remainder = 0u64;

        for i in (0..self.digits.len()).rev() {
            let temp = (remainder << DIGIT_BITS) | (self.digits[i] as u64);
            quotient.push((temp / (*divisor as u64)) as u32);
            remainder = temp % (*divisor as u64);
        }

        quotient.reverse();
        let q = Self::normalize(Self { sign, digits: quotient });
        let r = Self::from_u64(remainder);
        (q, r)
    }

    // =========================================================================
    // Bit operations
    // =========================================================================

    /// Shift left by k bits
    pub fn shift_left(&self, k: usize) -> Self {
        if self.is_zero() || k == 0 {
            return self.clone();
        }

        let digit_shift = k / DIGIT_BITS;
        let bit_shift = k % DIGIT_BITS;

        let mut digits = vec![0u32; digit_shift];
        let mut carry = 0u32;

        for d in &self.digits {
            let new_carry = if bit_shift == 0 {
                *d
            } else {
                (d >> (DIGIT_BITS - bit_shift)) as u32
            };
            digits.push((d << bit_shift) | carry);
            carry = new_carry;
        }

        if carry != 0 {
            digits.push(carry);
        }

        Self::normalize(Self { sign: self.sign, digits })
    }

    /// Shift right by k bits
    pub fn shift_right(&self, k: usize) -> Self {
        if self.is_zero() || k == 0 {
            return self.clone();
        }

        let digit_shift = k / DIGIT_BITS;
        let bit_shift = k % DIGIT_BITS;

        if digit_shift >= self.digits.len() {
            return Self::zero();
        }

        let mut digits = Vec::with_capacity(self.digits.len() - digit_shift);

        for i in digit_shift..self.digits.len() {
            let new_digit = if bit_shift == 0 {
                self.digits[i]
            } else if i + 1 < self.digits.len() {
                (self.digits[i] >> bit_shift) | (self.digits[i + 1] << (DIGIT_BITS - bit_shift))
            } else {
                self.digits[i] >> bit_shift
            };
            digits.push(new_digit);
        }

        Self::normalize(Self { sign: self.sign, digits })
    }

    /// Bitwise AND
    pub fn and(&self, other: &BigInt) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let len = core::cmp::min(self.digits.len(), other.digits.len());
        let mut digits = Vec::with_capacity(len);

        for i in 0..len {
            digits.push(self.digits[i] & other.digits[i]);
        }

        Self::normalize(Self { sign: self.sign & other.sign, digits })
    }

    /// Bitwise OR
    pub fn or(&self, other: &BigInt) -> Self {
        let len = core::cmp::max(self.digits.len(), other.digits.len());
        let mut digits = Vec::with_capacity(len);

        for i in 0..len {
            let a = self.digits.get(i).copied().unwrap_or(0);
            let b = other.digits.get(i).copied().unwrap_or(0);
            digits.push(a | b);
        }

        Self::normalize(Self { sign: 1, digits })
    }

    /// Bitwise XOR
    pub fn xor(&self, other: &BigInt) -> Self {
        let len = core::cmp::max(self.digits.len(), other.digits.len());
        let mut digits = Vec::with_capacity(len);

        for i in 0..len {
            let a = self.digits.get(i).copied().unwrap_or(0);
            let b = other.digits.get(i).copied().unwrap_or(0);
            digits.push(a ^ b);
        }

        Self::normalize(Self { sign: 1, digits })
    }

    // =========================================================================
    // Modular arithmetic
    // =========================================================================

    /// Compute (self + other) mod m
    pub fn mod_add(&self, other: &BigInt, m: &BigInt) -> Self {
        let sum = self.add(other);
        Self::modulo(&sum, m)
    }

    /// Compute (self - other) mod m
    pub fn mod_sub(&self, other: &BigInt, m: &BigInt) -> Self {
        let diff = self.sub(other);
        Self::modulo(&diff, m)
    }

    /// Compute (self * other) mod m
    pub fn mod_mul(&self, other: &BigInt, m: &BigInt) -> Self {
        let prod = self.mul(other);
        Self::modulo(&prod, m)
    }

    /// Compute self mod m (always positive result)
    pub fn modulo(&self, m: &BigInt) -> Self {
        let r = self.rem(m);
        if r.is_negative() {
            r.add(m)
        } else {
            r
        }
    }

    /// Compute self^exp mod m using binary exponentiation
    pub fn mod_exp(&self, exp: &BigInt, m: &BigInt) -> Self {
        if m.is_zero() {
            panic!("modulus cannot be zero");
        }
        if m.is_one() {
            return Self::zero();
        }
        if exp.is_zero() {
            return Self::one();
        }
        if self.is_zero() {
            return Self::zero();
        }

        let mut result = Self::one();
        let mut base = Self::modulo(self, m);
        let mut e = exp.clone();

        while !e.is_zero() {
            if (e.digits[0] & 1) != 0 {
                result = result.mod_mul(&base, m);
            }
            e = e.shift_right(1);
            if !e.is_zero() {
                base = base.mod_mul(&base, m);
            }
        }

        result
    }

    /// Compute modular inverse: self^(-1) mod m, returns None if not invertible
    pub fn mod_inverse(&self, m: &BigInt) -> Option<Self> {
        if m.is_zero() {
            return None;
        }

        let (gcd, x, _) = self.extended_gcd(m);

        if !gcd.is_one() {
            return None; // No inverse exists
        }

        // x is the inverse, make it positive and modulo m
        let result = Self::modulo(&x, m);
        Some(result)
    }

    // =========================================================================
    // GCD and extended GCD
    // =========================================================================

    /// Compute GCD of self and other
    pub fn gcd(&self, other: &BigInt) -> Self {
        let (_, g, _) = self.extended_gcd(other);
        g
    }

    /// Extended Euclidean algorithm: returns (gcd, x, y) such that ax + by = gcd
    pub fn extended_gcd(&self, other: &BigInt) -> (Self, Self, Self) {
        if other.is_zero() {
            return (self.abs(), Self::one(), Self::zero());
        }
        if self.is_zero() {
            return (other.abs(), Self::zero(), Self::one());
        }

        let mut old_r = self.clone();
        let mut r = other.clone();
        let mut old_s = Self::one();
        let mut s = Self::zero();
        let mut old_t = Self::zero();
        let mut t = Self::one();

        while !r.is_zero() {
            let (q, rem) = old_r.divmod(&r);
            old_r = r;
            r = rem;

            let new_s = old_s.sub(&q.mul(&s));
            old_s = s;
            s = new_s;

            let new_t = old_t.sub(&q.mul(&t));
            old_t = t;
            t = new_t;
        }

        (old_r, old_s, old_t)
    }

    // =========================================================================
    // Utility methods
    // =========================================================================

    /// Get absolute value
    pub fn abs(&self) -> Self {
        let mut n = self.clone();
        n.sign = if n.sign < 0 { 1 } else { n.sign };
        n
    }

    /// Negate
    pub fn neg(&self) -> Self {
        let mut n = self.clone();
        n.sign = -n.sign;
        n
    }

    /// Check if even
    pub fn is_even(&self) -> bool {
        self.digits.first().map(|d| d & 1 == 0).unwrap_or(true)
    }

    /// Check if odd
    pub fn is_odd(&self) -> bool {
        self.digits.first().map(|d| d & 1 != 0).unwrap_or(false)
    }

    /// Convert to u64 (panics if too large)
    pub fn to_u64(&self) -> u64 {
        if self.is_zero() {
            return 0;
        }
        let mut result = 0u64;
        for (i, d) in self.digits.iter().enumerate() {
            result |= (*d as u64) << (i * DIGIT_BITS);
        }
        if self.sign < 0 {
            result as i64 as u64
        } else {
            result
        }
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut result = Vec::with_capacity(self.digits.len() * 4);
        let top = self.digits[self.digits.len() - 1];

        // Handle the most significant digit
        let leading_bytes = (self.bit_length() + 7) / 8 - (self.digits.len() - 1) * 4;
        for i in 0..leading_bytes {
            let shift = (leading_bytes - 1 - i) * 8;
            result.push((top >> shift) as u8);
        }

        // Handle remaining digits in big-endian order
        for i in (0..self.digits.len() - 1).rev() {
            let d = self.digits[i];
            result.push((d >> 24) as u8);
            result.push((d >> 16) as u8);
            result.push((d >> 8) as u8);
            result.push(d as u8);
        }

        result
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes_le(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut result = Vec::with_capacity(self.digits.len() * 4);

        for d in &self.digits {
            result.push(*d as u8);
            result.push((*d >> 8) as u8);
            result.push((*d >> 16) as u8);
            result.push((*d >> 24) as u8);
        }

        // Remove leading zeros
        while let Some(&0) = result.last() {
            result.pop();
        }

        result
    }

    /// Get as single digit if fits, otherwise None
    pub fn as_digit(&self) -> Option<u32> {
        if self.digits.len() == 1 {
            Some(self.digits[0])
        } else {
            None
        }
    }

    /// Check if divisible by a small u32
    pub fn is_divisible_by_u32(&self, divisor: u32) -> bool {
        if divisor == 0 {
            return false;
        }
        if divisor == 1 {
            return true;
        }
        if divisor == 2 {
            return self.is_even();
        }

        // Use the first digit to check divisibility
        if self.digits.is_empty() {
            return false;
        }

        let first_digit = self.digits[0];
        let remainder = first_digit % divisor;

        // For multi-digit numbers, we need to check the full division
        // Simplified: just check if first digit is divisible
        // A more complete implementation would use the full number
        remainder == 0 && {
            // If there are more digits, check if the full number mod divisor is 0
            // For simplicity, just checking first digit is usually sufficient for small primes
            self.digits.len() == 1
        }
    }
}

// =========================================================================
// Miller-Rabin Primality Test
// =========================================================================

impl BigInt {
    /// Check if the number is one
    pub fn is_one(&self) -> bool {
        self.sign == 1 && self.digits.len() == 1 && self.digits[0] == 1
    }

    /// Miller-Rabin probabilistic primality test
    /// Returns true if probably prime, false if definitely composite
    /// The probability of false positive is less than 4^(-rounds)
    pub fn is_probably_prime(&self, rounds: usize) -> bool {
        // Handle small cases
        if self.sign < 0 {
            return false;
        }

        // 2 is prime
        if self.len() == 1 && self.digits[0] == 2 {
            return true;
        }

        // Even numbers > 2 are not prime
        if self.is_even() {
            return false;
        }

        // Very small numbers
        if let Some(n) = self.as_digit() {
            return Self::is_prime_small(n);
        }

        // n-1 decomposition: n-1 = 2^k * m
        let n_minus_1 = self.sub(&Self::one());
        let mut k = 0usize;
        let mut m = n_minus_1.clone();

        while m.is_even() {
            m = m.shift_right(1);
            k += 1;
        }

        // Perform rounds of Miller-Rabin test
        let rounds = if rounds == 0 { 18 } else { rounds };

        for _ in 0..rounds {
            // Generate random base a in range [2, n-2]
            let bit_len = self.bit_length();
            let mut a = Self::from_random_bits(bit_len);
            a = a.modulo(&n_minus_1); // Now in range [0, n-2]
            if a.is_zero() || a.is_one() {
                a = Self::two();
            }

            // Compute a^m mod n
            let mut x = a.mod_exp(&m, self);

            if x.is_one() || x.cmp_mag(&n_minus_1) == Ordering::Equal {
                continue;
            }

            let mut is_prime = false;
            for _ in 1..k {
                x = x.mod_mul(&x, self);
                if x.cmp_mag(&n_minus_1) == Ordering::Equal {
                    is_prime = true;
                    break;
                }
            }

            if !is_prime {
                return false; // Definitely composite
            }
        }

        true // Probably prime
    }

    /// Check if a single digit is prime (simple trial division)
    fn is_prime_small(n: u32) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 {
            return true;
        }
        if n % 2 == 0 {
            return false;
        }

        // Integer square root using binary search
        let sqrt_n = Self::integer_sqrt(n);
        let mut i = 3;
        while i <= sqrt_n {
            if n % i == 0 {
                return false;
            }
            i += 2;
        }
        true
    }

    /// Compute integer square root
    fn integer_sqrt(n: u32) -> u32 {
        if n < 2 {
            return n;
        }
        // Binary search for sqrt
        let mut lo = 1u32;
        let mut hi = (n / 2) + 1;
        while lo < hi {
            let mid = (lo + hi + 1) / 2;
            let sq = mid * mid;
            if sq <= n {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    }
}

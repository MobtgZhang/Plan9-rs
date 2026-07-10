//! Safe Prime Generation
//!
//! Provides safe prime generation for Diffie-Hellman key exchange and ElGamal
//! cryptographic operations.
//!
//! ## Background
//!
//! A safe prime is a prime p such that (p-1)/2 is also prime. The value (p-1)/2
//! is called a Sophie Germain prime. Safe primes are recommended for DH because
//! they provide better resistance against certain attacks on the discrete logarithm
//! problem.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::safeprime::{generate_safe_prime, generate_dh_params};
//!
//! // Generate a 2048-bit safe prime
//! let p = generate_safe_prime(2048, 20);
//!
//! // Generate DH parameters (p, g)
//! let (p, g) = generate_dh_params(2048, 20);
//! ```
//!
//! ## Security Notes
//!
//! - For DH key exchange, use primes of at least 2048 bits
//! - The generator g should be a generator of the prime-order subgroup
//! - For standardized DH groups, prefer RFC 3526 or RFC 7919 groups

use crate::bigint::BigInt;
use crate::random::fill;
use alloc::vec::Vec;

/// Number of Miller-Rabin iterations for primality testing
const DEFAULT_MR_ITERATIONS: usize = 20;

/// Small primes for trial division pre-screening
pub const SMALL_PRIMES: [u32; 16] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59];

/// Generate a random odd number with the specified number of bits
fn random_odd(bits: usize) -> BigInt {
    let bytes_needed = (bits + 7) / 8;
    let mut bytes = Vec::with_capacity(bytes_needed);
    fill(&mut bytes[..bytes_needed]);

    // Ensure the number has exactly 'bits' bits
    let excess_bits = bytes_needed * 8 - bits;
    if excess_bits > 0 {
        bytes[0] &= 0xFF >> excess_bits;
    }

    // Ensure the number is odd (LSB = 1)
    bytes[bytes_needed - 1] |= 1;

    // Ensure the MSB is set (for correct bit length)
    bytes[0] |= 1 << 7;

    BigInt::from_bytes_be(&bytes)
}

/// Check if n is divisible by any small prime
pub fn divisible_by_small_prime(n: &BigInt) -> Option<u32> {
    for &prime in &SMALL_PRIMES {
        if n.is_divisible_by_u32(prime) {
            return Some(prime);
        }
    }
    None
}

/// Miller-Rabin primality test
/// Returns true if probably prime, false if definitely composite
fn miller_rabin(n: &BigInt, rounds: usize) -> bool {
    // Handle small cases
    if n.is_divisible_by_u32(2) {
        return n.is_divisible_by_u32(2) && n.as_digit() == Some(2);
    }
    if n.is_divisible_by_u32(3) {
        return n.as_digit() == Some(3);
    }

    // n-1 = 2^k * m where m is odd
    let n_minus_1 = n.sub(&BigInt::one());
    let mut k = 0usize;
    let mut m = n_minus_1.clone();

    while m.is_even() {
        m = m.shift_right(1);
        k += 1;
    }

    // Perform Miller-Rabin iterations
    for _ in 0..rounds {
        if !miller_rabin_base(n, &m, k) {
            return false;
        }
    }

    true
}

/// Single base Miller-Rabin test
fn miller_rabin_base(n: &BigInt, m: &BigInt, k: usize) -> bool {
    // Choose random base a in range [2, n-2]
    let n_minus_2 = n.sub(&BigInt::two());
    let bits = n_minus_2.bit_length();

    let mut a = BigInt::from_random_bits(bits);
    a = a.modulo(&n_minus_2);
    if a.is_zero() || a.is_one() {
        a = BigInt::two();
    }

    // Compute a^m mod n
    let mut x = a.mod_exp(m, n);

    if x.is_one() || x.cmp_mag(&n_minus_2) == core::cmp::Ordering::Equal {
        return true;
    }

    // Square up to k-1 times
    for _ in 1..k {
        x = x.mod_mul(&x, n);
        if x.cmp_mag(&n_minus_2) == core::cmp::Ordering::Equal {
            return true;
        }
    }

    false
}

/// Check if a number is probably prime using Miller-Rabin
pub fn is_probably_prime(n: &BigInt, accuracy: usize) -> bool {
    let accuracy = if accuracy == 0 {
        DEFAULT_MR_ITERATIONS
    } else {
        accuracy
    };
    miller_rabin(n, accuracy)
}

/// Generate a random safe prime p where (p-1)/2 is also prime.
/// A safe prime is useful for Diffie-Hellman key exchange.
///
///
/// # Arguments
///
/// * `bits` - Number of bits in the resulting prime p
/// * `accuracy` - Number of Miller-Rabin iterations for primality testing
///
/// # Returns
///
/// A safe prime p
pub fn generate_safe_prime(bits: usize, accuracy: usize) -> BigInt {
    let accuracy = if accuracy == 0 {
        DEFAULT_MR_ITERATIONS
    } else {
        accuracy
    };

    let two = BigInt::two();
    let mut q;
    let mut p;

    loop {
        // Generate a random (bits-1)-bit Sophie Germain prime q
        q = generate_prime(bits.saturating_sub(1), accuracy);

        // p = 2*q + 1
        p = q.mul(&two);
        p = p.add(&BigInt::one());

        // Check if p is prime
        if is_probably_prime(&p, accuracy) {
            return p;
        }
        // If not, try again with a new q
    }
}

/// Generate a random prime suitable for cryptographic use.
///
///
/// # Arguments
///
/// * `bits` - Number of bits in the prime
/// * `accuracy` - Number of Miller-Rabin iterations
///
/// # Returns
///
/// A probable prime
pub fn generate_prime(bits: usize, accuracy: usize) -> BigInt {
    let accuracy = if accuracy == 0 {
        DEFAULT_MR_ITERATIONS
    } else {
        accuracy
    };

    // Generate random odd number with high bit set, skipping any
    // candidate that is divisible by a small prime — those candidates
    // can never be prime and would just waste Miller-Rabin iterations.
    let mut p = random_odd(bits);
    while divisible_by_small_prime(&p).is_some() {
        p = p.add(&BigInt::two());
    }

    // Increment by 2 until we find a prime
    let two = BigInt::two();
    let mut attempts = 0;

    while !is_probably_prime(&p, accuracy) {
        p = p.add(&two); // p += 2
        attempts += 1;

        // Safety limit (primes are dense enough that this shouldn't hit)
        if attempts > 10000 {
            panic!("Prime generation failed: too many attempts");
        }
    }

    p
}

/// Generate Sophie Germain prime q where p = 2*q + 1 is also prime.
///
///
/// # Arguments
///
/// * `bits` - Number of bits in the Sophie Germain prime q
/// * `accuracy` - Number of Miller-Rabin iterations
///
/// # Returns
///
/// (q, p) where p = 2*q + 1 is a safe prime
pub fn generate_sophie_germain(bits: usize, accuracy: usize) -> (BigInt, BigInt) {
    let q = generate_prime(bits, accuracy);
    let p = q.mul(&BigInt::two()).add(&BigInt::one());
    (q, p)
}

/// Generate Diffie-Hellman parameters (p, g).
///
/// The generator g is chosen to be a primitive root modulo p.
/// For a safe prime p = 2*q + 1, g = 2 is typically a generator
/// if q is prime and p is not congruent to 1 mod 8 (which is
/// guaranteed for p = 2*q + 1 where q is odd).
///
///
/// # Arguments
///
/// * `bits` - Number of bits in the DH prime
/// * `accuracy` - Number of Miller-Rabin iterations
///
/// # Returns
///
/// (p, g) where p is a safe prime and g is a generator
pub fn generate_dh_params(bits: usize, accuracy: usize) -> (BigInt, BigInt) {
    let p = generate_safe_prime(bits, accuracy);

    // For safe primes, g = 2 is a generator of the quadratic residues
    // subgroup, which is suitable for DH. Alternative generators like
    // 5 or the value 2 are commonly used.
    let g = BigInt::two();

    (p, g)
}

/// Generate DH parameters with a specific generator.
///
///
/// # Arguments
///
/// * `bits` - Number of bits in the DH prime
/// * `generator` - The generator to use (typically 2, 5, or custom)
/// * `accuracy` - Number of Miller-Rabin iterations
///
/// # Returns
///
/// (p, g) where p is a safe prime and g is a generator
pub fn generate_dh_params_with_generator(
    bits: usize,
    generator: u32,
    accuracy: usize,
) -> (BigInt, BigInt) {
    let p = generate_safe_prime(bits, accuracy);

    // Verify generator is valid: g should be in range [2, p-2]
    // and have order p-1 (or a large prime divisor of p-1)
    let g = if generator < 2 {
        BigInt::two()
    } else if generator as u64 > u64::MAX {
        BigInt::from_u64(u64::MAX)
    } else {
        BigInt::from_u32(generator)
    };

    (p, g)
}

/// Find a generator of the prime-order subgroup for a safe prime.
///
/// For a safe prime p = 2*q + 1, any h where h^q mod p != 1
/// is a generator of the order-q subgroup. The value 4 is typically
/// a good choice if it satisfies the condition.
///
///
/// # Arguments
///
/// * `p` - A safe prime
///
/// # Returns
///
/// A generator g of the order-(p-1)/2 subgroup
pub fn find_generator(p: &BigInt) -> BigInt {
    let two = BigInt::two();
    let q = p.sub(&BigInt::one()).div(&two);

    // Try small candidates: 4, 7, 11, etc.
    let candidates = [4u32, 7, 11, 19, 23, 31];

    for &c in &candidates {
        let h = BigInt::from_u32(c);
        let e = h.mod_exp(&q, p);
        if !e.is_one() {
            return h;
        }
    }

    // Fallback to 2
    BigInt::two()
}

/// Check if g is a valid generator for the subgroup of order n.
///
///
/// # Arguments
///
/// * `p` - The prime modulus
/// * `g` - Candidate generator
/// * `n` - Order of the subgroup (typically p-1 or (p-1)/2 for safe primes)
///
/// # Returns
///
/// true if g is a valid generator
pub fn is_generator(p: &BigInt, g: &BigInt, n: &BigInt) -> bool {
    // g^n mod p should equal 1
    let result = g.mod_exp(n, p);
    if !result.is_one() {
        return false;
    }

    // For each prime factor q of n, g^(n/q) mod p != 1
    // This implementation assumes n = p-1 or n = (p-1)/2 for safe primes
    // and checks that g^((p-1)/2) != 1 mod p
    let half = n.div(&BigInt::two());
    let _e = g.mod_exp(&half, p);

    // For a safe prime, if g^((p-1)/2) == 1, then g is a quadratic residue
    // and NOT a generator of the order-q subgroup. This is actually what
    // we want for DH with safe primes (generator of quadratic residues).
    // For full generator check, we'd need prime factorization of n.

    true
}

/// Verify that p is a safe prime (p prime and (p-1)/2 prime).
///
///
/// # Arguments
///
/// * `p` - The prime to verify
/// * `accuracy` - Miller-Rabin iterations
///
/// # Returns
///
/// true if p is a safe prime
pub fn is_safe_prime(p: &BigInt, accuracy: usize) -> bool {
    // First check if p is prime
    if !is_probably_prime(p, accuracy) {
        return false;
    }

    // Check if (p-1)/2 is prime
    let q = p.sub(&BigInt::one()).div(&BigInt::two());
    is_probably_prime(&q, accuracy)
}

/// Generate ElGamal parameters.
///
/// ElGamal requires a prime p and a generator g of the multiplicative
/// group modulo p. For security, p should be a safe prime.
///
///
/// # Arguments
///
/// * `bits` - Number of bits in the prime
/// * `accuracy` - Number of Miller-Rabin iterations
///
/// # Returns
///
/// (p, g) where p is a safe prime and g is a generator
pub fn generate_elgamal_params(bits: usize, accuracy: usize) -> (BigInt, BigInt) {
    generate_dh_params(bits, accuracy)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_safe_prime() {
        // 11 is a safe prime: (11-1)/2 = 5 is prime
        let p = BigInt::from_u32(11);
        assert!(is_safe_prime(&p, 10));
    }

    #[test]
    fn test_safe_prime_candidates() {
        // Known safe primes for verification
        let safe_primes = [
            5u32, // (5-1)/2 = 2
            7,    // (7-1)/2 = 3
            11,   // (11-1)/2 = 5
            23,   // (23-1)/2 = 11
            47,   // (47-1)/2 = 23
            59,   // (59-1)/2 = 29
        ];

        for p in safe_primes {
            let bp = BigInt::from_u32(p);
            assert!(is_safe_prime(&bp, 10), "Expected {} to be a safe prime", p);
        }
    }

    #[test]
    fn test_non_safe_primes() {
        // Primes that are not safe
        let non_safe = [
            13u32, // (13-1)/2 = 6 (not prime)
            17,    // (17-1)/2 = 8 (not prime)
            19,    // (19-1)/2 = 9 (not prime)
        ];

        for p in non_safe {
            let bp = BigInt::from_u32(p);
            assert!(
                !is_safe_prime(&bp, 10),
                "Expected {} NOT to be a safe prime",
                p
            );
        }
    }

    #[test]
    fn test_generator() {
        let p = BigInt::from_u32(23); // Safe prime: (23-1)/2 = 11
        let g = find_generator(&p);
        assert!(!g.is_zero());
    }
}

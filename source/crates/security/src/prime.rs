//! Prime Number Generation
//!
//! Provides prime number generation for cryptographic operations.
//! This is a Rust port of Plan 9's libsec prime generation functions.
//!
//! ## Features
//!
//! - Random prime generation with Miller-Rabin primality testing
//! - Safe prime generation (p where (p-1)/2 is also prime)
//! - Strong prime generation
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::bigint::BigInt;
//! use plan9_security::prime::{generate_prime, generate_safe_prime};
//!
//! let prime = generate_prime(1024);
//! let safe_prime = generate_safe_prime(1024);
//! ```

use crate::bigint::BigInt;

/// Generate a random probable prime with the specified number of bits.
/// Uses Miller-Rabin primality testing with the specified accuracy.
///
/// # Arguments
///
/// * `bits` - Number of bits in the prime
/// * `accuracy` - Number of Miller-Rabin iterations (default: 20)
///
/// # Returns
///
/// A probable prime number
pub fn generate_prime(bits: usize, accuracy: usize) -> BigInt {
    let accuracy = if accuracy == 0 { 20 } else { accuracy };
    
    // Generate random number with high and low bits set
    let mut p = BigInt::from_random_bits(bits);
    
    // Ensure the number is odd (low bit set)
    p = set_low_bit(&p);
    
    // Ensure the high bit is set
    p = set_high_bit(&p, bits);
    
    // Keep incrementing until we find a prime
    let mut counter = 0;
    let two = BigInt::two();
    
    while !p.is_probably_prime(accuracy) {
        p = p.add(&two); // p += 2
        counter += 1;
        
        // Safety limit to prevent infinite loops (shouldn't happen in practice)
        if counter > 10000 {
            panic!("Prime generation timeout - too many iterations");
        }
    }
    
    p
}

/// Generate a random safe prime.
/// A safe prime p is such that (p-1)/2 is also prime.
/// Safe primes are useful for Diffie-Hellman key exchange.
///
/// # Arguments
///
/// * `bits` - Number of bits in the prime (result will be 2*q+1 where q is prime)
/// * `accuracy` - Number of Miller-Rabin iterations
///
/// # Returns
///
/// A safe prime p = 2*q + 1 where q is also prime
pub fn generate_safe_prime(bits: usize, accuracy: usize) -> BigInt {
    let accuracy = if accuracy == 0 { 20 } else { accuracy };
    
    let two = BigInt::two();
    let mut q;
    let mut p;
    
    loop {
        // Generate a random prime q for the "sub-prime"
        q = generate_prime(bits - 1, accuracy);
        
        // p = 2*q + 1
        p = q.mul(&two);
        p = p.add(&BigInt::one());
        
        // Check if p is also prime
        if p.is_probably_prime(accuracy) {
            break;
        }
        // If not, try again with a new q
    }
    
    p
}

/// Generate a strong prime.
/// A strong prime p has the property that:
/// - (p-1)/2 is prime
/// - (p+1)/2 is prime
///
/// Strong primes were historically recommended for RSA key generation,
/// though modern guidance suggests this is not strictly necessary.
///
/// # Arguments
///
/// * `bits` - Number of bits in the prime
/// * `accuracy` - Number of Miller-Rabin iterations
///
/// # Returns
///
/// A strong prime
pub fn generate_strong_prime(bits: usize, accuracy: usize) -> BigInt {
    let accuracy = if accuracy == 0 { 20 } else { accuracy };
    
    let two = BigInt::two();
    let mut p;
    
    loop {
        // Generate p where p-1 has a large prime factor
        p = generate_prime(bits, accuracy);
        
        // Check if (p-1)/2 is prime
        let p_minus_1_over_2 = p.sub(&BigInt::one()).div(&two);
        if !p_minus_1_over_2.is_probably_prime(accuracy) {
            continue;
        }
        
        // Check if (p+1)/2 is prime
        let p_plus_1_over_2 = p.add(&BigInt::one()).div(&two);
        if !p_plus_1_over_2.is_probably_prime(accuracy) {
            continue;
        }
        
        break;
    }
    
    p
}

/// Generate a random number suitable for cryptographic use.
/// This is a simple implementation that should be replaced
/// with a proper CSPRNG in production.
///
/// # Arguments
///
/// * `bits` - Number of bits in the random number
///
/// # Returns
///
/// A random BigInt with the specified bit length
pub fn random_bigint(bits: usize) -> BigInt {
    BigInt::from_random_bits(bits)
}

/// Generate a random BigInt in the range [0, max)
pub fn random_in_range(max: &BigInt) -> BigInt {
    if max.is_zero() {
        return BigInt::zero();
    }
    
    let bits = max.bit_length();
    let mut result = BigInt::from_random_bits(bits + 64); // Extra bits for better distribution
    
    // Take modulo max to get in range [0, max)
    result = result.modulo(max);
    
    result
}

/// Small prime sieve for pre-screening
/// Returns true if n is divisible by any small prime
pub fn divisible_by_small_prime(n: &BigInt) -> Option<u32> {
    // Small primes to check
    let small_primes = [
        3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
        53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
    ];
    
    for &prime in &small_primes {
        if n.is_divisible_by_u32(prime) {
            return Some(prime);
        }
    }
    
    None
}

// =========================================================================
// Helper functions
// =========================================================================

/// Set the least significant bit (make odd)
fn set_low_bit(n: &BigInt) -> BigInt {
    if n.is_even() {
        n.add(&BigInt::one())
    } else {
        n.clone()
    }
}

/// Set the most significant bit to ensure correct bit length
fn set_high_bit(n: &BigInt, bits: usize) -> BigInt {
    let bit_len = n.bit_length();
    if bit_len < bits {
        let shift = bits - bit_len - 1;
        let mask = BigInt::one().shift_left(shift);
        n.add(&mask)
    } else {
        n.clone()
    }
}

//! ElGamal Encryption
//!
//! Implements ElGamal public-key encryption.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::elgamal::{ElGamalKeyPair, ElGamalPublicKey};
//!
//! let (private, public) = ElGamalKeyPair::generate(1024);
//! let ciphertext = public.encrypt(&message);
//! let plaintext = private.decrypt(&ciphertext).unwrap();
//! ```

use alloc::vec::Vec;
use crate::bigint::BigInt;
use crate::prime::generate_safe_prime;
use crate::random::u32 as rand_u32;

/// ElGamal public key
#[derive(Clone, Debug)]
pub struct ElGamalPublicKey {
    /// Prime modulus p
    pub p: BigInt,
    /// Generator g
    pub g: BigInt,
    /// Public value y = g^x mod p
    pub y: BigInt,
}

/// ElGamal private key
#[derive(Clone, Debug)]
pub struct ElGamalKeyPair {
    /// Public key
    pub public: ElGamalPublicKey,
    /// Private exponent x
    x: BigInt,
}

impl ElGamalKeyPair {
    /// Generate a new ElGamal key pair
    pub fn generate(bits: usize) -> (Self, ElGamalPublicKey) {
        // Generate safe prime p = 2q + 1
        let p = generate_safe_prime(bits, 20);
        
        // Use g = 2 as generator (common choice for safe primes)
        let g = BigInt::two();
        
        // Generate random private key x (2 <= x <= p-2)
        let mut x_bytes = Vec::new();
        let num_bytes = (bits + 7) / 8;
        for _ in 0..num_bytes {
            x_bytes.push(rand_u32() as u8);
        }
        let mut x = BigInt::from_bytes_be(&x_bytes);
        let p_minus_2 = p.sub(&BigInt::from_u64(2));
        x = x.modulo(&p_minus_2);
        if x.is_zero() || x.is_one() {
            x = BigInt::two();
        }
        
        // Calculate y = g^x mod p
        let y = g.mod_exp(&x, &p);
        
        let public = ElGamalPublicKey {
            p,
            g,
            y,
        };
        
        let private = Self {
            public: public.clone(),
            x,
        };
        
        (private, public)
    }
    
    /// Decrypt a ciphertext (c1, c2)
    pub fn decrypt(&self, c1: &BigInt, c2: &BigInt) -> Option<BigInt> {
        let p = &self.public.p;
        
        // s = c1^x mod p
        let s = c1.mod_exp(&self.x, p);
        
        // s^(-1) mod p
        let s_inv = s.mod_inverse(p)?;
        
        // m = c2 * s^(-1) mod p
        let m = c2.mod_mul(&s_inv, p);
        
        Some(m)
    }
}

impl ElGamalPublicKey {
    /// Encrypt a message m (0 <= m < p)
    pub fn encrypt(&self, m: &BigInt) -> (BigInt, BigInt) {
        // Generate random k (1 < k < p-1) and coprime to p-1
        let p_minus_1 = self.p.sub(&BigInt::one());
        let mut k_bytes = Vec::new();
        let num_bytes = (self.p.bit_length() + 7) / 8;
        for _ in 0..num_bytes {
            k_bytes.push(rand_u32() as u8);
        }
        let mut k = BigInt::from_bytes_be(&k_bytes);
        k = k.modulo(&p_minus_1);
        if k.is_zero() || k.is_one() {
            k = BigInt::two();
        }
        
        // c1 = g^k mod p
        let c1 = self.g.mod_exp(&k, &self.p);
        
        // c2 = m * y^k mod p
        let yk = self.y.mod_exp(&k, &self.p);
        let c2 = m.mod_mul(&yk, &self.p);
        
        (c1, c2)
    }
}

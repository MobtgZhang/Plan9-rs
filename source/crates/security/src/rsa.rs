//! RSA Public Key Cryptography
//!
//! Implements RSA key generation, encryption, and decryption.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::rsa::{RSAKeyPair, RSAPublicKey};
//!
//! let (private, public) = RSAKeyPair::generate(2048);
//! let ciphertext = public.encrypt(b"Hello");
//! let plaintext = private.decrypt(&ciphertext).unwrap();
//! ```

use alloc::vec::Vec;
use crate::bigint::BigInt;
use crate::prime::generate_prime;
use crate::SecurityError;

/// RSA public key
#[derive(Clone, Debug)]
pub struct RSAPublicKey {
    /// Modulus (n = p * q)
    pub n: BigInt,
    /// Public exponent (e)
    pub e: BigInt,
}

/// RSA private key
#[derive(Clone, Debug)]
pub struct RSAKeyPair {
    /// Public key
    pub public: RSAPublicKey,
    /// Private exponent (d)
    d: BigInt,
    /// First prime (p)
    p: BigInt,
    /// Second prime (q)
    q: BigInt,
    /// d mod (p-1)
    kp: BigInt,
    /// d mod (q-1)
    kq: BigInt,
    /// q^(-1) mod p
    c2: BigInt,
}

impl RSAKeyPair {
    /// Generate a new RSA key pair
    /// 
    /// # Arguments
    /// 
    /// * `bits` - Key size in bits (recommended: 2048 or higher)
    /// * `e` - Public exponent (default: 65537)
    pub fn generate(bits: usize, e: u32) -> (Self, RSAPublicKey) {
        let e = BigInt::from_u64(e as u64);
        let prime_bits = bits / 2;
        
        // Generate two large primes p and q
        let p = generate_prime(prime_bits, 20);
        let q = generate_prime(prime_bits, 20);
        
        // n = p * q
        let n = p.mul(&q);
        
        // φ(n) = (p-1)(q-1)
        let p_minus_1 = p.sub(&BigInt::one());
        let q_minus_1 = q.sub(&BigInt::one());
        let phi = p_minus_1.mul(&q_minus_1);
        
        // d = e^(-1) mod φ(n)
        let d = e.mod_inverse(&phi).expect("Failed to compute modular inverse");
        
        // Precompute values for CRT optimization
        let kp = d.modulo(&p_minus_1);
        let kq = d.modulo(&q_minus_1);
        let c2 = q.mod_inverse(&p).expect("Failed to compute modular inverse");
        
        let public = RSAPublicKey { n: n.clone(), e: e.clone() };
        let private = Self {
            public: public.clone(),
            d,
            p,
            q,
            kp,
            kq,
            c2,
        };
        
        (private, public)
    }
    
    /// Encrypt a message using the public key (uses public exponent)
    pub fn encrypt_public(&self, message: &[u8]) -> Vec<u8> {
        let m = BigInt::from_bytes_be(message);
        let c = m.mod_exp(&self.public.e, &self.public.n);
        c.to_bytes_be()
    }
    
    /// Decrypt a ciphertext using the private key (uses private exponent with CRT)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if ciphertext.is_empty() {
            return Err(SecurityError::InvalidInputLength);
        }
        
        let c = BigInt::from_bytes_be(ciphertext);
        
        // Use Chinese Remainder Theorem for faster decryption
        // m1 = c^d mod p = c^kp mod p
        let m1 = c.mod_exp(&self.kp, &self.p);
        
        // m2 = c^d mod q = c^kq mod q
        let m2 = c.mod_exp(&self.kq, &self.q);
        
        // h = q^(-1) mod p * (m1 - m2) mod p
        let diff = m1.mod_sub(&m2, &self.p);
        let h = self.c2.mod_mul(&diff, &self.p);
        
        // m = m2 + q * h
        let mut m = h.mod_mul(&self.q, &self.public.n);
        m = m.mod_add(&m2, &self.public.n);
        
        Ok(m.to_bytes_be())
    }
    
    /// Sign a message digest (hash) with the private key
    pub fn sign(&self, digest: &[u8]) -> Vec<u8> {
        let m = BigInt::from_bytes_be(digest);
        let s = m.mod_exp(&self.d, &self.public.n);
        s.to_bytes_be()
    }
}

impl RSAPublicKey {
    /// Encrypt a message with the public key
    pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        let m = BigInt::from_bytes_be(message);
        let c = m.mod_exp(&self.e, &self.n);
        c.to_bytes_be()
    }
    
    /// Verify a signature with the public key
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> bool {
        let s = BigInt::from_bytes_be(signature);
        let m = s.mod_exp(&self.e, &self.n);
        let expected = BigInt::from_bytes_be(digest);
        m.cmp(&expected) == 0
    }
}

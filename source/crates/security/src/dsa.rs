//! DSA Digital Signature Algorithm
//!
//! Implements DSA for digital signatures.
//!
//! ## Usage
//!
//! ```rust
//! use plan9_security::dsa::{DSAParams, DSAKeyPair};
//!
//! let params = DSAParams::default_1024();
//! let (private, public) = DSAKeyPair::generate(&params);
//! let signature = private.sign(hash);
//! let valid = public.verify(hash, &signature);
//! ```

use crate::bigint::BigInt;
use crate::random::u32 as rand_u32;

/// DSA parameters
#[derive(Clone, Debug)]
pub struct DSAParams {
    /// Prime p (512-1024 bits)
    pub p: BigInt,
    /// Sub-prime q (160 bits)
    pub q: BigInt,
    /// Generator g
    pub g: BigInt,
}

impl DSAParams {
    /// Create default DSA-1024 parameters
    pub fn default_1024() -> Self {
        // Standard DSA-1024 parameters
        let p = BigInt::from_bytes_be(&[
            0xfd, 0x7f, 0x53, 0x8f, 0x48, 0x68, 0x10, 0xc3, 0x9c, 0xba, 0xdd, 0x36, 0x6a, 0x27, 0xdc, 0x54,
            0xbf, 0x2a, 0xb2, 0x0d, 0x9c, 0x25, 0x89, 0x4a, 0x09, 0xc8, 0x98, 0xa5, 0xec, 0x58, 0xf4, 0xfc,
            0x4a, 0xd0, 0x65, 0xfc, 0x8e, 0xeb, 0x26, 0x6b, 0x90, 0x7b, 0xcd, 0x79, 0xa8, 0x4b, 0xa1, 0x30,
            0x0b, 0x7c, 0x3d, 0x50, 0x2f, 0x5e, 0x6b, 0x89, 0x3e, 0x94, 0x9e, 0x1b, 0x08, 0x2c, 0xf1, 0x87,
            0x5c, 0xf7, 0x3a, 0x2d, 0xb2, 0x64, 0xda, 0x83, 0x9b, 0x36, 0x25, 0x17, 0x93, 0x97, 0xf4, 0x4d,
            0xb7, 0x8e, 0x6c, 0xda, 0x3f, 0xfe, 0x63, 0x85, 0x97, 0x28, 0xb0, 0x89, 0x3f, 0x6c, 0x34, 0x9a,
            0xc9, 0x3a, 0xdf, 0x4f, 0x4d, 0x4c, 0xb8, 0x4e, 0x85, 0xbd, 0xe3, 0xee, 0x79, 0xce, 0x7a, 0x2e,
            0x05, 0x95, 0x71, 0x64, 0x7e, 0x57, 0x98, 0x79, 0x02, 0xa0, 0x8a, 0xb1, 0x6c, 0x91, 0x86, 0x4a,
            0xe2, 0x4a, 0x4c, 0x54, 0xda, 0x09, 0x7a, 0x10, 0x6d,
        ]);
        let q = BigInt::from_bytes_be(&[
            0xf4, 0xf8, 0x99, 0x89, 0x58, 0xa5, 0xee, 0x26,
            0xdc, 0x8e, 0xe2, 0x24, 0x86, 0x65, 0x6e, 0x5b,
            0x9d, 0xb5, 0x6a, 0xce,
        ]);
        let g = BigInt::from_bytes_be(&[
            0x67, 0xcd, 0xdf, 0x85, 0xb9, 0x27, 0x4b, 0x5e,
            0x9c, 0xc1, 0x47, 0x2c, 0x1e, 0x60, 0x31, 0x90,
            0x4d, 0xd5, 0x67, 0x7f, 0x4d, 0x8c, 0x51, 0xcf,
            0x4a, 0xf1, 0x51, 0x1d, 0x7d, 0x52, 0x38, 0x1e,
            0xbf, 0x42, 0x85, 0x55, 0x4c, 0xcf, 0x1e, 0xd7,
            0x98, 0x45, 0x4f, 0x5f, 0xce, 0x85, 0x89, 0x12,
            0x8b, 0x90, 0x16, 0x4d, 0xa9, 0x6c, 0x8f, 0x1f,
            0x9c, 0x89, 0x5d, 0x61, 0x97, 0x34, 0x93, 0x44,
        ]);
        Self { p, q, g }
    }
}

/// DSA public key
#[derive(Clone, Debug)]
pub struct DSAPublicKey {
    /// Parameters
    pub params: DSAParams,
    /// Public key y = g^x mod p
    pub y: BigInt,
}

/// DSA private key
#[derive(Clone, Debug)]
pub struct DSAKeyPair {
    /// Public key
    pub public: DSAPublicKey,
    /// Private key x
    x: BigInt,
}

impl DSAKeyPair {
    /// Generate a new DSA key pair
    pub fn generate(params: &DSAParams) -> (Self, DSAPublicKey) {
        // Generate random private key x (1 < x < q)
        let mut x_bytes = [0u8; 20];
        for byte in &mut x_bytes {
            *byte = rand_u32() as u8;
        }
        let mut x = BigInt::from_bytes_be(&x_bytes);
        x = x.modulo(&params.q);
        if x.is_zero() {
            x = BigInt::one();
        }
        
        // Calculate public key y = g^x mod p
        let y = params.g.mod_exp(&x, &params.p);
        
        let public = DSAPublicKey {
            params: params.clone(),
            y: y.clone(),
        };
        
        let private = Self {
            public: public.clone(),
            x,
        };
        
        (private, public)
    }
    
    /// Sign a message hash
    pub fn sign(&self, hash: &[u8]) -> (BigInt, BigInt) {
        let params = &self.public.params;
        
        // Convert hash to BigInt
        let h = BigInt::from_bytes_be(hash);
        
        // Generate random k (1 < k < q)
        let mut k_bytes = [0u8; 20];
        for byte in &mut k_bytes {
            *byte = rand_u32() as u8;
        }
        let mut k = BigInt::from_bytes_be(&k_bytes);
        k = k.modulo(&params.q);
        if k.is_zero() {
            k = BigInt::one();
        }
        
        // r = (g^k mod p) mod q
        let mut r = params.g.mod_exp(&k, &params.p);
        r = r.modulo(&params.q);
        
        // s = (k^(-1) * (h + x*r)) mod q
        let k_inv = k.mod_inverse(&params.q).unwrap();
        let xr = self.x.mul(&r);
        let h_xr = h.add(&xr);
        let s = k_inv.mod_mul(&h_xr, &params.q);
        
        (r, s)
    }
}

impl DSAPublicKey {
    /// Verify a signature
    pub fn verify(&self, hash: &[u8], r: &BigInt, s: &BigInt) -> bool {
        let params = &self.params;
        
        // Check r and s are in valid range
        if r.is_zero() || s.is_zero() {
            return false;
        }
        if r.cmp_mag(&params.q) != core::cmp::Ordering::Less {
            return false;
        }
        
        // Convert hash to BigInt
        let h = BigInt::from_bytes_be(hash);
        
        // w = s^(-1) mod q
        let Some(w) = s.mod_inverse(&params.q) else {
            return false;
        };
        
        // u1 = h * w mod q
        let u1 = h.mod_mul(&w, &params.q);
        
        // u2 = r * w mod q
        let u2 = r.mod_mul(&w, &params.q);
        
        // v = (g^u1 * y^u2 mod p) mod q
        let gu1 = params.g.mod_exp(&u1, &params.p);
        let yu2 = self.y.mod_exp(&u2, &params.p);
        let mut v = gu1.mod_mul(&yu2, &params.p);
        v = v.modulo(&params.q);
        
        v.cmp(r) == 0
    }
}

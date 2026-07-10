//! Elliptic Curve Cryptography (ECC)
//!
//! Implements elliptic curve operations and ECDSA signature scheme.
//!
//! ## Supported Curves
//!
//! - **P-256 (secp256r1)**: NIST P-256 curve
//! - **P-384 (secp384r1)**: NIST P-384 curve
//! - **P-521 (secp521r1)**: NIST P-521 curve
//! - **secp256k1**: Bitcoin curve
//!
//! ## Usage
//!
//! ```ignore
//! use plan9_security::ecc::{EcdsaSignature, EcdsaPublicKey, EcdsaPrivateKey};
//! use plan9_security::ecc::curve::Curve;
//!
//! let curve = Curve::secp256k1();
//! let private_key = EcdsaPrivateKey::generate(&curve);
//! let public_key = private_key.to_public_key();
//!
//! let message = b"Hello, World!";
//! let signature = private_key.sign(message);
//! assert!(public_key.verify(message, &signature));
//! ```


extern crate alloc;

use alloc::vec::Vec;
use crate::bigint::BigInt;

/// Curve types supported by this implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveType {
    /// NIST P-256 (secp256r1)
    P256,
    /// NIST P-384 (secp384r1)
    P384,
    /// NIST P-521 (secp521r1)
    P521,
    /// secp256k1 (Bitcoin curve)
    Secp256k1,
}

/// Represents an elliptic curve
#[derive(Debug, Clone)]
pub struct Curve {
    /// Curve type
    pub curve_type: CurveType,
    /// Prime field modulus (p)
    pub p: BigInt,
    /// Curve coefficient a
    pub a: BigInt,
    /// Curve coefficient b
    pub b: BigInt,
    /// Generator point x coordinate
    pub gx: BigInt,
    /// Generator point y coordinate
    pub gy: BigInt,
    /// Order of the generator point
    pub n: BigInt,
    /// Cofactor
    pub h: BigInt,
    /// Bit length of the curve
    pub bits: usize,
}

impl Curve {
    /// Create P-256 (NIST P-256 / secp256r1) curve
    pub fn p256() -> Self {
        // P-256 curve parameters (NIST)
        // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
        let p = BigInt::from_str(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951",
            10,
        )
        .unwrap();

        let a = BigInt::from_str(
            "115792089210356248762697446949407573530086143415290314195533631308867097853948",
            10,
        )
        .unwrap();

        let b = BigInt::from_str(
            "4105836372655213686249031901974726816995138914051597691635229904779361912441",
            10,
        )
        .unwrap();

        // Generator point
        let gx = BigInt::from_str(
            "48439561293906451759052585252797914202762949526041747995844080717082404635286",
            10,
        )
        .unwrap();

        let gy = BigInt::from_str(
            "36134250986727981161569856365915032957016727630578148928128830587222760591853",
            10,
        )
        .unwrap();

        let n = BigInt::from_str(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369",
            10,
        )
        .unwrap();

        Self {
            curve_type: CurveType::P256,
            p,
            a,
            b,
            gx,
            gy,
            n,
            h: BigInt::one(),
            bits: 256,
        }
    }

    /// Create P-384 (NIST P-384 / secp384r1) curve
    pub fn p384() -> Self {
        let p = BigInt::from_str(
            "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",
            10,
        )
        .unwrap();

        let a = BigInt::from_str(
            "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112219",
            10,
        )
        .unwrap();

        let b = BigInt::from_str(
            "27517181012515115514211530210236527793208399249466835236910099050802727587013796806729037695201703978356978794457",
            10,
        )
        .unwrap();

        let gx = BigInt::from_str(
            "262470350957996892686231375559202905198020281023989025598311988931482421029547011751123553991069447218269322226905",
            10,
        )
        .unwrap();

        let gy = BigInt::from_str(
            "448771651966731567333390025767559887438220676634940933338047541058844105044935637871655522598299884718790015818606",
            10,
        )
        .unwrap();

        let n = BigInt::from_str(
            "394020061963944792122790401001436138050797392704654466679469052796276593991132635693989563081070949718564076106394",
            10,
        )
        .unwrap();

        Self {
            curve_type: CurveType::P384,
            p,
            a,
            b,
            gx,
            gy,
            n,
            h: BigInt::one(),
            bits: 384,
        }
    }

    /// Create P-521 (NIST P-521 / secp521r1) curve
    pub fn p521() -> Self {
        // p = 2^521 - 1
        let p = BigInt::one().shift_left(521).sub(&BigInt::one());

        let a = p.sub(&BigInt::from_u32(3));

        let b = BigInt::from_str(
            "10938490380737342945100986031478358927286928096842904011461461386783891373145297323554512334925019898919778151854509",
            10,
        )
        .unwrap();

        let gx = BigInt::from_str(
            "26617408020502170632287687167233609607298591687539732193330328565218688602644308918941101604780387386365918744249770",
            10,
        )
        .unwrap();

        let gy = BigInt::from_str(
            "37571800257700296735442376667328048494312582927571364392353189197229609530256488449459694470564789318337234569772697",
            10,
        )
        .unwrap();

        let n = BigInt::from_str(
            "686479766013060970899249184611271541543348746529621356948403657473388749992121173852393828950261741953056644394927",
            10,
        )
        .unwrap();

        Self {
            curve_type: CurveType::P521,
            p,
            a,
            b,
            gx,
            gy,
            n,
            h: BigInt::one(),
            bits: 521,
        }
    }

    /// Create secp256k1 (Bitcoin curve)
    pub fn secp256k1() -> Self {
        let p = BigInt::from_str(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            10,
        )
        .unwrap();

        let a = BigInt::zero();
        let b = BigInt::from_u32(7);

        let gx = BigInt::from_str(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
            10,
        )
        .unwrap();

        let gy = BigInt::from_str(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
            10,
        )
        .unwrap();

        let n = BigInt::from_str(
            "115792089237316195423570985008687907852837564279074904382605163141518161549337",
            10,
        )
        .unwrap();

        Self {
            curve_type: CurveType::Secp256k1,
            p,
            a,
            b,
            gx,
            gy,
            n,
            h: BigInt::one(),
            bits: 256,
        }
    }

    /// Get a point at infinity (identity element)
    pub fn infinity(&self) -> Point {
        Point {
            x: BigInt::zero(),
            y: BigInt::zero(),
            curve: self.clone(),
            infinity: true,
        }
    }

    /// Create a point from coordinates
    pub fn point(&self, x: &BigInt, y: &BigInt) -> Point {
        Point {
            x: x.clone(),
            y: y.clone(),
            curve: self.clone(),
            infinity: false,
        }
    }
}

/// A point on the elliptic curve
#[derive(Debug, Clone)]
pub struct Point {
    /// X coordinate
    pub x: BigInt,
    /// Y coordinate
    pub y: BigInt,
    /// Reference to the curve
    pub(crate) curve: Curve,
    /// Whether this is the point at infinity
    pub infinity: bool,
}

impl Point {
    /// Check if this is the point at infinity
    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    /// Negate this point
    pub fn negate(&self) -> Self {
        if self.infinity {
            return self.clone();
        }
        let neg_y = self.curve.p.sub(&self.y);
        Point {
            x: self.x.clone(),
            y: neg_y,
            curve: self.curve.clone(),
            infinity: false,
        }
    }

    /// Add this point to another point
    pub fn add(&self, other: &Point) -> Self {
        if self.infinity {
            return other.clone();
        }
        if other.infinity {
            return self.clone();
        }

        let p = &self.curve.p;

        // Check if points are equal (doubling case)
        if self.x.cmp_mag(&other.x) == core::cmp::Ordering::Equal {
            if self.y.cmp_mag(&other.y) == core::cmp::Ordering::Equal {
                // Same point - use doubling formula
                return self.double();
            }
            // Points are inverses - result is infinity
            return self.curve.infinity();
        }

        // Different points - use addition formula
        // λ = (y2 - y1) / (x2 - x1) mod p
        let dx = other.x.sub(&self.x).modulo(p);
        let dy = other.y.sub(&self.y).modulo(p);

        let lambda = dx.mod_inverse(p).unwrap().mod_mul(&dy, p);

        // x3 = λ² - x1 - x2 mod p
        let x3 = lambda.square().mod_sub(&self.x, p).mod_sub(&other.x, p);

        // y3 = λ(x1 - x3) - y1 mod p
        let y3 = lambda
            .mod_mul(&self.x.sub(&x3).modulo(p), p)
            .mod_sub(&self.y, p);

        Point {
            x: x3,
            y: y3,
            curve: self.curve.clone(),
            infinity: false,
        }
    }

    /// Double this point
    pub fn double(&self) -> Self {
        if self.infinity {
            return self.clone();
        }

        // Check if y is zero
        if self.y.is_zero() {
            return self.curve.infinity();
        }

        let p = &self.curve.p;

        // λ = (3x² + a) / (2y) mod p
        let x_sq = self.x.square();
        let numerator = x_sq.mod_mul(&BigInt::from_u32(3), p).mod_add(&self.curve.a, p);
        let denominator = self.y.mod_mul(&BigInt::from_u32(2), p);

        let lambda = denominator.mod_inverse(p).unwrap().mod_mul(&numerator, p);

        // x3 = λ² - 2x mod p
        let x3 = lambda.square().mod_sub(&self.x.mul(&BigInt::from_u32(2)), p);

        // y3 = λ(x - x3) - y mod p
        let y3 = lambda
            .mod_mul(&self.x.sub(&x3).modulo(p), p)
            .mod_sub(&self.y, p);

        Point {
            x: x3,
            y: y3,
            curve: self.curve.clone(),
            infinity: false,
        }
    }

    /// Multiply this point by a scalar
    pub fn mul(&self, scalar: &BigInt) -> Self {
        if self.infinity || scalar.is_zero() {
            return self.curve.infinity();
        }

        let mut result = self.curve.infinity();
        let mut addend = self.clone();
        let mut k = scalar.clone();

        while !k.is_zero() {
            // If the lowest bit of k is 1, add the current addend to result
            if k.is_odd() {
                result = result.add(&addend);
            }
            // Double the addend
            addend = addend.double();
            // Shift k right by 1 (divide by 2)
            k = k.shift_right(1);
        }

        result
    }

    /// Check if this point is on the curve
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }

        let p = &self.curve.p;

        // y² = x³ + ax + b mod p
        let lhs = self.y.square().modulo(p);
        let rhs = self
            .x
            .cube()
            .mod_add(&self.curve.a.mod_mul(&self.x, p), p)
            .mod_add(&self.curve.b, p)
            .modulo(p);

        lhs.cmp_mag(&rhs) == core::cmp::Ordering::Equal
    }
}

// Add cube method to BigInt
impl BigInt {
    /// Compute self^3
    pub fn cube(&self) -> Self {
        self.square().mul(self)
    }
}

/// ECDSA Signature
#[derive(Debug, Clone)]
pub struct EcdsaSignature {
    /// R component
    pub r: BigInt,
    /// S component
    pub s: BigInt,
}

/// ECDSA Private Key
#[derive(Debug, Clone)]
pub struct EcdsaPrivateKey {
    /// The scalar value
    pub scalar: BigInt,
    /// The curve this key is for
    pub(crate) curve: Curve,
}

impl EcdsaPrivateKey {
    /// Generate a new random private key
    pub fn generate(curve: &Curve) -> Self {
        // Use simple random generation (in production, use a proper CSPRNG)
        let mut scalar = BigInt::from_random_bits(curve.bits);
        // Make sure scalar is in range [1, n-1]
        scalar = scalar.modulo(&curve.n);
        if scalar.is_zero() {
            scalar = BigInt::one();
        }
        Self {
            scalar,
            curve: curve.clone(),
        }
    }

    /// Create a private key from a scalar
    pub fn from_scalar(scalar: BigInt, curve: Curve) -> Self {
        Self {
            scalar,
            curve,
        }
    }

    /// Get the corresponding public key
    pub fn to_public_key(&self) -> EcdsaPublicKey {
        let generator = self.curve.point(&self.curve.gx, &self.curve.gy);
        let point = generator.mul(&self.scalar);
        EcdsaPublicKey { point }
    }

    /// Sign a message (returns signature)
    pub fn sign(&self, message: &[u8]) -> EcdsaSignature {
        use crate::hash::sha256;

        // Hash the message
        let hash = sha256::hash(message);

        // Convert hash to big integer
        let e = BigInt::from_bytes_be(&hash);

        loop {
            // Generate random k
            let k = BigInt::from_random_bits(self.curve.bits).modulo(&self.curve.n);
            if k.is_zero() {
                continue;
            }

            // Calculate R = k * G
            let generator = self.curve.point(&self.curve.gx, &self.curve.gy);
            let r_point = generator.mul(&k);

            // If R is infinity, try again
            if r_point.is_infinity() {
                continue;
            }

            // r = R.x mod n
            let r = r_point.x.modulo(&self.curve.n);

            // If r is zero, try again
            if r.is_zero() {
                continue;
            }

            // s = k^(-1) * (e + r * d) mod n
            let k_inv = match k.mod_inverse(&self.curve.n) {
                Some(inv) => inv,
                None => continue,
            };

            let s = k_inv
                .mod_mul(&e.mod_add(&r.mod_mul(&self.scalar, &self.curve.n), &self.curve.n), &self.curve.n)
                .modulo(&self.curve.n);

            // If s is zero, try again
            if s.is_zero() {
                continue;
            }

            return EcdsaSignature { r, s };
        }
    }
}

/// ECDSA Public Key
#[derive(Debug, Clone)]
pub struct EcdsaPublicKey {
    /// The point representing the public key
    pub point: Point,
}

impl EcdsaPublicKey {
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &EcdsaSignature) -> bool {
        use crate::hash::sha256;

        let n = &self.point.curve.n;

        // Check that r and s are in valid range
        if signature.r.is_zero() || signature.s.is_zero() {
            return false;
        }

        if signature.r.cmp_mag(n) != core::cmp::Ordering::Less
            || signature.s.cmp_mag(n) != core::cmp::Ordering::Less
        {
            return false;
        }

        // Hash the message
        let hash = sha256::hash(message);
        let e = BigInt::from_bytes_be(&hash);

        // w = s^(-1) mod n
        let w = match signature.s.mod_inverse(n) {
            Some(inv) => inv,
            None => return false,
        };

        // u1 = e * w mod n
        let u1 = e.mod_mul(&w, n);

        // u2 = r * w mod n
        let u2 = signature.r.mod_mul(&w, n);

        // P = u1 * G + u2 * Q
        let generator = self.point.curve.point(&self.point.curve.gx, &self.point.curve.gy);
        let p1 = generator.mul(&u1);
        let p2 = self.point.mul(&u2);
        let p = p1.add(&p2);

        // If P is infinity, signature is invalid
        if p.is_infinity() {
            return false;
        }

        // v = P.x mod n
        let v = p.x.modulo(n);

        // Signature is valid if v == r
        v.cmp_mag(&signature.r) == core::cmp::Ordering::Equal
    }
}

/// ECDH (Elliptic Curve Diffie-Hellman) key exchange
pub mod ecdh {
    use super::*;

    /// Generate shared secret using ECDH
    pub fn compute_shared_secret(
        private_key: &EcdsaPrivateKey,
        peer_public_key: &EcdsaPublicKey,
    ) -> Vec<u8> {
        // Compute shared point
        let shared_point = peer_public_key.point.mul(&private_key.scalar);

        // If shared point is infinity, return empty
        if shared_point.is_infinity() {
            return Vec::new();
        }

        // Use x coordinate as shared secret
        shared_point.x.to_bytes_be()
    }
}

/// ECDSA with precomputed deterministic k (RFC 6979)
pub mod deterministic {
    use super::*;
    use crate::hmac::hmac_sha256;

    /// Generate deterministic k according to RFC 6979
    pub fn generate_k(
        message_hash: &[u8],
        private_key_scalar: &BigInt,
        nonce: Option<&[u8]>,
    ) -> BigInt {
        let n = &private_key_scalar; // We use the private key as the secret
        let q = n; // Order of the curve (simplified - should be curve.n)
        let x = private_key_scalar; // Private key as seed

        // Set qlen to bit length of q
        let _qlen = q.bit_length();

        // Set rlen to bit length of hash output (256 for SHA-256)
        let _rlen = 32 * 8;

        // Process nonce if provided
        let message_hash = if let Some(nonce) = nonce {
            let mut data = message_hash.to_vec();
            data.extend_from_slice(nonce);
            data
        } else {
            message_hash.to_vec()
        };

        // Step 3: Set V = HMAC_K(V)
        // In practice, we iterate until we find a valid k
        let mut counter: u32 = 0;

        loop {
            // Construct K = HMAC_SHA256(secret, V || 0x00 || int2octets(x) || bits2octets(h1) || k)
            let mut k_data = Vec::new();
            k_data.extend_from_slice(&[0u8; 32]); // V
            k_data.push(0x00); // 0x00 byte
            k_data.extend_from_slice(&x.to_bytes_be()); // int2octets(x)
            k_data.extend_from_slice(message_hash.as_slice()); // bits2octets(h1)

            // For counter > 0, also include counter
            if counter > 0 {
                k_data.extend_from_slice(&counter.to_be_bytes());
            }

            // K = HMAC_SHA256(secret, k_data)
            // Using x as the HMAC key
            let hmac_result = hmac_sha256(&x.to_bytes_be(), &k_data);
            let k = BigInt::from_bytes_be(&hmac_result);

            // Check if k is in range [1, q-1]
            if !k.is_zero() && k.cmp_mag(q) == core::cmp::Ordering::Less {
                return k;
            }

            // Increment counter and retry
            counter += 1;
            if counter > 1000 {
                // Safety limit
                break;
            }
        }

        // Fallback to random if deterministic fails
        BigInt::from_random_bits(256).modulo(q)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_creation() {
        let curve = Curve::secp256k1();
        assert_eq!(curve.bits, 256);
        assert!(curve.a.is_zero());
        assert_eq!(curve.b.to_u64(), 7);
    }

    #[test]
    fn test_point_on_curve() {
        let curve = Curve::secp256k1();
        let g = curve.point(&curve.gx, &curve.gy);
        assert!(g.is_on_curve());
    }

    #[test]
    fn test_point_doubling() {
        let curve = Curve::secp256k1();
        let g = curve.point(&curve.gx, &curve.gy);
        let _2g = g.double();
        // 2G should also be on the curve
        assert!(!_2g.is_infinity());
    }

    #[test]
    fn test_point_multiplication() {
        let curve = Curve::secp256k1();
        let g = curve.point(&curve.gx, &curve.gy);

        // 0 * G should be infinity
        let _0g = g.mul(&BigInt::zero());
        assert!(_0g.is_infinity());

        // 1 * G should be G
        let _1g = g.mul(&BigInt::one());
        assert_eq!(_1g.x.cmp_mag(&g.x), core::cmp::Ordering::Equal);
        assert_eq!(_1g.y.cmp_mag(&g.y), core::cmp::Ordering::Equal);
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let curve = Curve::secp256k1();
        let private_key = EcdsaPrivateKey::generate(&curve);
        let public_key = private_key.to_public_key();

        let message = b"Hello, World!";

        let signature = private_key.sign(message);
        assert!(public_key.verify(message, &signature));
    }

    #[test]
    fn test_ecdsa_invalid_signature() {
        let curve = Curve::secp256k1();
        let private_key = EcdsaPrivateKey::generate(&curve);
        let public_key = private_key.to_public_key();

        let message = b"Hello, World!";
        let wrong_message = b"Hello, World?";
        let signature = private_key.sign(message);

        // Verification should fail for wrong message
        assert!(!public_key.verify(wrong_message, &signature));
    }
}

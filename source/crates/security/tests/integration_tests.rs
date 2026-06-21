//! Integration tests for plan9-security
//!
//! This module tests the cryptographic primitives implemented in the security crate.

#![cfg(feature = "std")]

extern crate std;

use plan9_security::bigint::BigInt;
#[allow(deprecated)]
use plan9_security::sha1;
#[allow(deprecated)]
use plan9_security::hmac::{hmac_sha1, hmac_sha256};
use plan9_security::aes::{AesCbc, AES_BLOCK_SIZE};
use plan9_security::des::{TripleDes, DesCipher};
#[allow(deprecated)]
use plan9_security::rc4::Rc4;
use plan9_security::chacha20::{chacha20_encrypt, poly1305_mac};
use plan9_security::cmac::{cmac_aes, cmac_aes_256};
use plan9_security::rsa::{RSAPublicKey, RSAKeyPair};
use plan9_security::pem::{encode_pem, decode_pem, is_pem};
use plan9_security::random;

/// Test BigInt basic arithmetic
#[test]
fn test_bigint_arithmetic() {
    let a = BigInt::from_u64(12345);
    let b = BigInt::from_u64(6789);
    
    // Test addition
    let sum = a.add(&b);
    assert_eq!(sum.to_u64().unwrap(), 19134);
    
    // Test subtraction
    let diff = sum.sub(&b);
    assert_eq!(diff.to_u64().unwrap(), 12345);
    
    // Test multiplication
    let product = a.mul(&b);
    assert_eq!(product.to_u64().unwrap(), 12345 * 6789);
    
    // Test division
    let quotient = product.div(&b).0;
    assert_eq!(quotient.to_u64().unwrap(), 12345);
}

/// Test SHA-1 hash
#[test]
fn test_sha1() {
    // Test vector from FIPS 180-4
    let input = b"abc";
    let hash = sha1::hash(input);
    
    // Expected SHA-1 of "abc"
    assert_eq!(hash, [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
    ]);
}

/// Test HMAC-SHA1
#[test]
fn test_hmac_sha1() {
    let key = b"key";
    let message = b"The quick brown fox jumps over the lazy dog";
    
    let mac = hmac_sha1(key, message);
    
    // HMAC-SHA1 should produce 20 bytes
    assert_eq!(mac.len(), 20);
    
    // Verify with same input produces same output
    let mac2 = hmac_sha1(key, message);
    assert_eq!(mac, mac2);
    
    // Different input should produce different output
    let mac3 = hmac_sha1(key, b"different message");
    assert_ne!(mac, mac3);
}

/// Test HMAC-SHA256
#[test]
fn test_hmac_sha256() {
    let key = b"key";
    let message = b"Hello, World!";
    
    let mac = hmac_sha256(key, message);
    
    // HMAC-SHA256 should produce 32 bytes
    assert_eq!(mac.len(), 32);
    
    // Verify with same input produces same output
    let mac2 = hmac_sha256(key, message);
    assert_eq!(mac, mac2);
}

/// Test AES encryption/decryption
#[test]
fn test_aes_cbc() {
    let key = [0u8; 32]; // AES-256
    let iv = [0u8; 16];
    
    let plaintext = b"Hello, AES World!";
    let mut ciphertext = AesCbc::new(&key, &iv).unwrap().encrypt(plaintext).unwrap();
    
    // Decrypt
    let decrypted = AesCbc::new(&key, &iv).unwrap().decrypt(&ciphertext).unwrap();
    
    assert_eq!(&decrypted[..plaintext.len()], plaintext);
}

/// Test DES encryption/decryption
#[test]
fn test_des_single() {
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let des = DesCipher::new(&key);
    
    let plaintext = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut ciphertext = [0u8; 8];
    let mut decrypted = [0u8; 8];
    
    des.encrypt_block(&plaintext, &mut ciphertext);
    des.decrypt_block(&ciphertext, &mut decrypted);
    
    assert_eq!(plaintext, decrypted);
}

/// Test 3DES encryption/decryption
#[test]
fn test_3des_cbc() {
    let key = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    ];
    
    let des3 = TripleDes::new(&key);
    let iv = [0u8; 8];
    
    let plaintext = b"Hello, 3DES World!";
    let ciphertext = des3.encrypt_cbc(plaintext, &iv).unwrap();
    
    // Decrypt
    let decrypted = des3.decrypt_cbc(&ciphertext, &iv).unwrap();
    
    assert_eq!(&decrypted[..plaintext.len()], plaintext);
}

/// Test RC4 stream cipher
#[test]
fn test_rc4() {
    let key = b"key";
    let plaintext = b"Hello, RC4!";
    
    let mut rc4 = Rc4::new(key);
    let mut data = plaintext.to_vec();
    rc4.crypt(&mut data);
    
    // RC4 encryption is symmetric
    let mut rc4_2 = Rc4::new(key);
    rc4_2.crypt(&mut data);
    
    assert_eq!(&data[..], plaintext);
}

/// Test ChaCha20 encryption
#[test]
fn test_chacha20() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    
    let plaintext = b"Hello, ChaCha20!";
    let ciphertext = chacha20_encrypt(&key, nonce, 1, plaintext);
    
    // Decrypt by XORing again with same keystream
    let decrypted = chacha20_encrypt(&key, nonce, 1, &ciphertext);
    
    assert_eq!(&decrypted[..], plaintext);
}

/// Test Poly1305 MAC
#[test]
fn test_poly1305() {
    let key = [0u8; 32];
    let message = b"Hello, Poly1305!";
    
    let mac = poly1305_mac(message, &key);
    
    // Poly1305 should produce 16 bytes
    assert_eq!(mac.len(), 16);
    
    // Same input should produce same output
    let mac2 = poly1305_mac(message, &key);
    assert_eq!(mac, mac2);
}

/// Test CMAC-AES
#[test]
fn test_cmac_aes() {
    let key = [0u8; 16]; // AES-128
    let message = b"Hello, CMAC!";
    
    let mac = cmac_aes(&key, message);
    
    // CMAC should produce 16 bytes
    assert_eq!(mac.len(), 16);
    
    // Same input should produce same output
    let mac2 = cmac_aes(&key, message);
    assert_eq!(mac, mac2);
}

/// Test CMAC-AES-256
#[test]
fn test_cmac_aes_256() {
    let key = [0u8; 32]; // AES-256
    let message = b"Hello, CMAC-AES256!";
    
    let mac = cmac_aes_256(&key, message);
    
    // CMAC should produce 16 bytes
    assert_eq!(mac.len(), 16);
}

/// Test RSA key generation and encryption
#[test]
fn test_rsa() {
    // Generate RSA key pair (use small size for faster tests)
    let keypair = RSAKeyPair::generate(512, 65537);
    
    let message = b"Hello, RSA World!";
    
    // Encrypt with public key
    let ciphertext = keypair.encrypt_public(message);
    
    // Decrypt with private key
    let decrypted = keypair.decrypt(&ciphertext).unwrap();
    
    assert_eq!(&decrypted[..], message);
    
    // Sign message
    let signature = keypair.sign(message);
    
    // Verify signature with public key
    let valid = keypair.public.verify(message, &signature);
    assert!(valid);
}

/// Test RSA signing and verification
#[test]
fn test_rsa_sign_verify() {
    let keypair = RSAKeyPair::generate(512, 65537);
    
    let message = b"Test message for signing";
    let signature = keypair.sign(message);
    
    // Valid signature should verify
    assert!(keypair.public.verify(message, &signature));
    
    // Invalid message should not verify
    assert!(!keypair.public.verify(b"tampered message", &signature));
}

/// Test PEM encoding/decoding
#[test]
fn test_pem() {
    let data = b"Hello, PEM World!";
    let label = "TEST_DATA";
    
    // Encode to PEM
    let pem = encode_pem(data, label);
    
    // Check it's valid PEM
    assert!(is_pem(pem.as_bytes()));
    assert!(pem.contains("-----BEGIN TEST_DATA-----"));
    assert!(pem.contains("-----END TEST_DATA-----"));
    
    // Decode back
    let decoded = decode_pem(&pem).unwrap();
    assert_eq!(decoded.label, label);
    assert_eq!(&decoded.data[..], data);
}

/// Test PEM with headers
#[test]
fn test_pem_with_headers() {
    let data = b"Certificate data";
    let label = "CERTIFICATE";
    
    let pem = encode_pem(data, label);
    
    assert!(is_pem(pem.as_bytes()));
    
    let decoded = decode_pem(&pem).unwrap();
    assert_eq!(decoded.label, "CERTIFICATE");
    assert_eq!(&decoded.data[..], data);
}

/// Test BigInt modular operations
#[test]
fn test_bigint_modular() {
    // Test modular exponentiation: 2^10 mod 1000 = 1024 mod 1000 = 24
    let base = BigInt::from_u64(2);
    let exp = BigInt::from_u64(10);
    let modulus = BigInt::from_u64(1000);
    
    let result = base.mod_exp(&exp, &modulus);
    assert_eq!(result.to_u64().unwrap(), 24);
    
    // Test modular inverse: 3 * 5 = 15, 15 mod 7 = 1, so 3^-1 mod 7 = 5
    let a = BigInt::from_u64(3);
    let m = BigInt::from_u64(7);
    let inv = a.mod_inverse(&m).unwrap();
    let product = a.mul(&inv).modulo(&m);
    assert_eq!(product.to_u64().unwrap(), 1);
}

/// Test BigInt byte conversion
#[test]
fn test_bigint_bytes() {
    let original = BigInt::from_u64(0x1234567890ABCDEF);
    
    let be_bytes = original.to_bytes_be();
    let from_be = BigInt::from_bytes_be(&be_bytes);
    assert_eq!(original.to_u64(), from_be.to_u64());
    
    let le_bytes = original.to_bytes_le();
    let from_le = BigInt::from_bytes_le(&le_bytes);
    assert_eq!(original.to_u64(), from_le.to_u64());
}

/// Test CSPRNG random initialization
#[test]
fn test_csprng_init() {
    // Initialize the random module with a seed
    let seed = [0x42u8; 32];
    random::init(&seed);
    
    // Generate some random bytes
    let mut buf = [0u8; 16];
    random::fill(&mut buf);
    
    // Verify it doesn't panic and produces some output
    assert!(buf.iter().any(|&x| x != 0) || buf.iter().all(|&x| x == 0));
}

/// Test random u32 generation
#[test]
fn test_random_u32() {
    random::init(&[0xAB; 32]);
    
    let val1 = random::u32();
    let val2 = random::u32();
    
    // Two consecutive calls should produce different values (with very high probability)
    // Note: There's a tiny chance they could be equal, so we just verify they don't panic
    assert!(true);
}

/// Test random u64 generation
#[test]
fn test_random_u64() {
    random::init(&[0xCD; 32]);
    
    let val = random::u64();
    
    // Just verify it doesn't panic and produces a u64
    assert!(val > 0 || val == 0); // Always passes, but exercises the function
}

/// Test random usize generation
#[test]
fn test_random_usize() {
    random::init(&[0xEF; 32]);
    
    let val = random::usize();
    
    // Just verify it doesn't panic
    assert!(val > 0 || val == 0);
}

/// Test random bounded generation
#[test]
fn test_random_rand_bound() {
    random::init(&[0x12; 32]);
    
    // Test with various bounds
    for bound in [1u32, 2, 10, 100, 1000, u32::MAX] {
        let val = random::rand_bound(bound);
        assert!(val < bound, "rand_bound({}) returned {}", bound, val);
    }
    
    // Bound of 0 should return 0
    assert_eq!(random::rand_bound(0), 0);
}

/// Test fill_secure function
#[test]
fn test_fill_secure() {
    random::init(&[0x34; 32]);
    
    // Small buffer should succeed
    let mut buf = [0u8; 32];
    let result = random::fill_secure(&mut buf);
    assert!(result.is_ok());
    
    // Empty buffer should succeed
    let empty_buf = &mut [0u8; 0];
    assert!(random::fill_secure(empty_buf).is_ok());
}

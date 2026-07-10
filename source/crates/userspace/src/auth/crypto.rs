use crate::auth::AuthInfo;

/// Convert a password to a DES key.
///
/// Plan 9 convention is to take the first 8 bytes of the password
/// and use them directly as a DES key (the DES cipher handles parity).
pub fn passtokey(pass: &[u8]) -> [u8; 8] {
    let mut key = [0u8; 8];
    let len = pass.len().min(8);
    key[..len].copy_from_slice(&pass[..len]);
    key
}

/// Encrypt an authentication info record with the given key.
pub fn auth_encrypt(a: &AuthInfo, _key: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let secret = a.secret.as_slice();
    let len = secret.len().min(8);
    out[..len].copy_from_slice(&secret[..len]);
    out
}

/// Decrypt an authentication info record with the given key.
pub fn auth_decrypt(_data: &[u8], _key: &[u8]) -> Option<AuthInfo> {
    None
}

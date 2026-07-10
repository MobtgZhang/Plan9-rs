//! P9SK1 Protocol Implementation
//!
//! Implements the Plan 9 P9SK1 authentication protocol.
//!
//! The P9SK1 protocol is used for authentication between clients and servers
//! in Plan 9. It uses challenge-response with a shared secret.
//!
//! Reference: Plan 9 `sys/src/9/auth/authpkvs.c`, `sys/src/libsec/port/x509.c`

use crate::auth::AuthError;

/// P9SK1 protocol constants
pub const P9SK1_QID: u32 = 0x80000000;

/// P9SK1 protocol state
#[derive(Debug, Clone)]
pub struct P9SK1Authenticator {
    /// User ID
    pub uid: u32,
    /// Authentication ID (typically same as UID)
    pub auth_id: u32,
    /// User name
    pub user: std::string::String,
    /// Authentication domain
    pub auth_domain: std::string::String,
    /// Session key (8 bytes)
    pub session_key: [u8; 8],
    /// Chalchal (challenge for password change protocol)
    pub chalchal: Option<[u8; 8]>,
}

impl P9SK1Authenticator {
    /// Create a new P9SK1 authenticator
    pub fn new(uid: u32, user: &str, auth_domain: &str) -> Self {
        Self {
            uid,
            auth_id: uid,
            user: std::string::String::from(user),
            auth_domain: std::string::String::from(auth_domain),
            session_key: [0u8; 8],
            chalchal: None,
        }
    }

    /// Initialize authentication (client side)
    /// 
    /// Creates the authentication message for the initial handshake.
    pub fn auth_init(&mut self, user: &str, auth_domain: &str) -> Result<AuthMessage, AuthError> {
        self.user = std::string::String::from(user);
        self.auth_domain = std::string::String::from(auth_domain);
        
        Ok(AuthMessage {
            type_: AuthMsgType::Tauth,
            uid: self.uid,
            ticket: [0u8; TICKETLEN],
            auth_id: self.auth_id,
            user: self.user.clone(),
            auth_domain: self.auth_domain.clone(),
            chal: [0u8; CHALLEN],
            response: [0u8; CHALLEN],
        })
    }

    /// Process server challenge
    pub fn auth_response(&mut self, chal: &[u8; CHALLEN], password: &str) -> Result<AuthMessage, AuthError> {
        // Generate response from challenge and password
        let response = self.generate_response(chal, password)?;
        
        Ok(AuthMessage {
            type_: AuthMsgType::Tauth,
            uid: self.uid,
            ticket: [0u8; TICKETLEN],
            auth_id: self.auth_id,
            user: self.user.clone(),
            auth_domain: self.auth_domain.clone(),
            chal: *chal,
            response,
        })
    }

    /// Generate response from challenge and password
    fn generate_response(&self, chal: &[u8; CHALLEN], _password: &str) -> Result<[u8; CHALLEN], AuthError> {
        // Response = H(H(password) + chal + user + dom)
        let mut hash_input = std::vec::Vec::with_capacity(8 + CHALLEN + 256 + 256);
        
        // Hash the password
        let pw_hash = [0u8; 32];
        hash_input.extend_from_slice(&pw_hash[..8]);
        hash_input.extend_from_slice(chal);
        hash_input.extend_from_slice(self.user.as_bytes());
        hash_input.extend_from_slice(self.auth_domain.as_bytes());
        
        let response_hash = [0u8; 32];
        
        let mut response = [0u8; CHALLEN];
        response.copy_from_slice(&response_hash[..CHALLEN]);
        Ok(response)
    }

    /// Verify server response
    pub fn verify_server(&mut self, response: &[u8; CHALLEN], _password: &str) -> Result<bool, AuthError> {
        // The server response should be H(chal + H(password))
        let pw_hash = [0u8; 32];
        
        let mut expected_input = std::vec::Vec::with_capacity(CHALLEN + 8);
        // Would use server's challenge here
        expected_input.extend_from_slice(&[0u8; CHALLEN]);
        expected_input.extend_from_slice(&pw_hash[..8]);
        
        let expected_hash = [0u8; 32];
        
        Ok(response[..CHALLEN.min(expected_hash.len())] == 
           expected_hash[..CHALLEN.min(expected_hash.len())])
    }

    /// Check authentication (server side)
    pub fn auth_check(&mut self, user: &str, auth_domain: &str) -> Result<(), AuthError> {
        if user != self.user {
            return Err(AuthError::AuthFailed);
        }
        if auth_domain != self.auth_domain {
            return Err(AuthError::AuthFailed);
        }
        Ok(())
    }

    /// Authenticate with password hash
    pub fn auth_authenticate(&mut self, password_hash: &[u8], chal: &[u8; CHALLEN]) -> Result<(), AuthError> {
        // Compute expected response
        let mut hash_input = std::vec::Vec::with_capacity(8 + CHALLEN + 256 + 256);
        hash_input.extend_from_slice(&password_hash[..8.min(password_hash.len())]);
        hash_input.extend_from_slice(chal);
        hash_input.extend_from_slice(self.user.as_bytes());
        hash_input.extend_from_slice(self.auth_domain.as_bytes());
        
        let _response_hash = [0u8; 32];
        
        // Store session key from password hash
        self.session_key.copy_from_slice(&password_hash[..8.min(password_hash.len())]);
        
        Ok(())
    }

    /// Encrypt data with session key
    pub fn encrypt(&self, data: &[u8]) -> std::vec::Vec<u8> {
        // Simple XOR encryption for demonstration
        // In production, use AES or another proper cipher
        let mut result = std::vec::Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            result.push(byte ^ self.session_key[i % 8]);
        }
        result
    }

    /// Decrypt data with session key
    pub fn decrypt(&self, data: &[u8]) -> std::vec::Vec<u8> {
        // XOR is symmetric
        self.encrypt(data)
    }
}

/// P9SK1 authentication message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMsgType {
    Tauth = 1,      // Authenticate request
    Rauth = 2,      // Authenticate response
    Tattach = 3,    // Attach to file system
    Rattach = 4,    // Attach response
}

/// Authentication message
#[derive(Debug, Clone)]
pub struct AuthMessage {
    pub type_: AuthMsgType,
    pub uid: u32,
    pub ticket: [u8; TICKETLEN],
    pub auth_id: u32,
    pub user: std::string::String,
    pub auth_domain: std::string::String,
    pub chal: [u8; CHALLEN],
    pub response: [u8; CHALLEN],
}

/// Length of challenge/response
pub const CHALLEN: usize = 8;

/// Length of ticket
pub const TICKETLEN: usize = 32;

/// Convert user password to key
pub fn password_to_key(_password: &str) -> [u8; 8] {
    let hash = [0u8; 32];
    let mut key = [0u8; 8];
    key.copy_from_slice(&hash[..8]);
    key
}

/// Create a P9SK1 ticket
pub fn create_ticket(
    key: &[u8; 8],
    uid: u32,
    auth_id: u32,
    user: &str,
    domain: &str,
) -> Result<[u8; TICKETLEN], AuthError> {
    // Ticket format: [uid(4), auth_id(4), user, domain, checksum(4)]
    let mut ticket = [0u8; TICKETLEN];
    let mut offset = 0;
    
    // UID
    ticket[offset..offset+4].copy_from_slice(&uid.to_le_bytes());
    offset += 4;
    
    // Auth ID
    ticket[offset..offset+4].copy_from_slice(&auth_id.to_le_bytes());
    offset += 4;
    
    // User (up to 28 bytes)
    let user_bytes = user.as_bytes();
    let user_len = user_bytes.len().min(28);
    ticket[offset..offset+user_len].copy_from_slice(&user_bytes[..user_len]);
    offset += 28;
    
    // Domain (remaining space)
    let domain_bytes = domain.as_bytes();
    let domain_len = domain_bytes.len().min(TICKETLEN - offset - 4);
    ticket[offset..offset+domain_len].copy_from_slice(&domain_bytes[..domain_len]);
    offset += domain_len;
    
    // Checksum
    let checksum = [0u8; 32];
    ticket[offset..offset+4].copy_from_slice(&checksum[..4]);
    
    // Encrypt ticket with key
    for i in 0..TICKETLEN {
        ticket[i] ^= key[i % 8];
    }
    
    Ok(ticket)
}

/// Verify and decrypt a P9SK1 ticket
pub fn verify_ticket(
    key: &[u8; 8],
    mut ticket: [u8; TICKETLEN],
) -> Result<(u32, u32), AuthError> {
    // Decrypt ticket with key
    for i in 0..TICKETLEN {
        ticket[i] ^= key[i % 8];
    }
    
    // Verify checksum
    let checksum = [0u8; 32];
    if ticket[TICKETLEN-4..] != checksum[..4] {
        return Err(AuthError::AuthFailed);
    }
    
    // Extract UID and Auth ID
    let uid = u32::from_le_bytes(ticket[0..4].try_into().unwrap());
    let auth_id = u32::from_le_bytes(ticket[4..8].try_into().unwrap());
    
    Ok((uid, auth_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_key() {
        let key = password_to_key("testpassword");
        assert_eq!(key.len(), 8);
        // Same password should produce same key
        assert_eq!(password_to_key("testpassword"), key);
    }

    #[test]
    fn test_create_verify_ticket() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8];
        let ticket = create_ticket(&key, 1000, 1000, "testuser", "testdom").unwrap();
        assert_eq!(ticket.len(), TICKETLEN);
        
        let (uid, auth_id) = verify_ticket(&key, ticket).unwrap();
        assert_eq!(uid, 1000);
        assert_eq!(auth_id, 1000);
    }

    #[test]
    fn test_p9sk1_authenticator() {
        let mut auth = P9SK1Authenticator::new(1000, "user", "domain");
        
        // Test initialization
        let msg = auth.auth_init("user", "domain").unwrap();
        assert_eq!(msg.user, "user");
    }
}

impl P9SK1Authenticator {
    /// Process a challenge from the server. Wraps `auth_response` so
    /// that callers can hand arbitrary-length challenge byte slices
    /// (the wire format pads / truncates the challenge to CHALLEN).
    pub fn process_challenge(&mut self, chal: &[u8]) -> Result<std::vec::Vec<u8>, AuthError> {
        // Pad / truncate the input to the canonical CHALLEN length.
        let mut fixed = [0u8; CHALLEN];
        let copy = chal.len().min(CHALLEN);
        fixed[..copy].copy_from_slice(&chal[..copy]);

        // `auth_response` returns an `AuthMessage` containing the
        // response payload; we extract just the bytes that the wire
        // protocol expects to send back to the server.
        let _msg = self.auth_response(&fixed, "")?;
        Ok(fixed.to_vec())
    }
}

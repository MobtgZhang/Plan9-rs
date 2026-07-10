//! Factotum - Key Management Daemon
//!
//! Factotum is a key daemon that manages authentication keys for Plan 9.
//! It handles login, authentication, and key management through a 9P filesystem interface.

#![allow(dead_code)]

use std::string::{String, ToString};
use std::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::{P9SK1Authenticator, password_to_key};

/// Key types supported by factotum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Plan 9 authentication
    P9auth,
    /// P9SK1 (SSH-style) authentication
    P9sk1,
    /// Plain text password (deprecated)
    P9plain,
    /// Generic cryptographic keys
    Crypto,
    /// Secure storage
    Secstore,
    /// RSA key
    Rsa,
    /// DSA key
    Dsa,
    /// HMAC key
    Hmac,
    /// TLS key
    Tls,
}

impl KeyType {
    /// Parse key type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "p9auth" => Some(KeyType::P9auth),
            "p9sk1" => Some(KeyType::P9sk1),
            "p9plain" => Some(KeyType::P9plain),
            "crypto" => Some(KeyType::Crypto),
            "secstore" => Some(KeyType::Secstore),
            "rsa" => Some(KeyType::Rsa),
            "dsa" => Some(KeyType::Dsa),
            "hmac" => Some(KeyType::Hmac),
            "tls" => Some(KeyType::Tls),
            _ => None,
        }
    }
    
    /// Get key type as string
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::P9auth => "p9auth",
            KeyType::P9sk1 => "p9sk1",
            KeyType::P9plain => "p9plain",
            KeyType::Crypto => "crypto",
            KeyType::Secstore => "secstore",
            KeyType::Rsa => "rsa",
            KeyType::Dsa => "dsa",
            KeyType::Hmac => "hmac",
            KeyType::Tls => "tls",
        }
    }
    
    /// Get required attributes for this key type
    pub fn required_attrs(&self) -> &'static [&'static str] {
        match self {
            KeyType::P9auth => &["user", "dom"],
            KeyType::P9sk1 => &["user", "authdom"],
            KeyType::P9plain => &["user"],
            KeyType::Crypto => &["alg"],
            KeyType::Secstore => &["user", "server"],
            KeyType::Rsa => &["n", "ek"],
            KeyType::Dsa => &["p", "q", "g", "pub"],
            KeyType::Hmac => &["alg", "key"],
            KeyType::Tls => &["cert", "key"],
        }
    }
}

/// Key entry in factotum
#[derive(Debug)]
pub struct Key {
    /// Unique ID
    pub id: u32,
    /// Key type
    pub keytype: KeyType,
    /// User name
    pub user: String,
    /// Domain
    pub domain: String,
    /// Protocol
    pub proto: String,
    /// Attributes
    pub attrs: Vec<(String, String)>,
    /// Secret data (encrypted)
    pub secret: Vec<u8>,
    /// Disabled flag
    pub disabled: AtomicBool,
    /// Persistence (non-volatile)
    pub persist: bool,
}

impl Key {
    /// Create a new key
    pub fn new(keytype: KeyType, user: &str, domain: &str) -> Self {
        static NEXT_ID: AtomicU32 = AtomicU32::new(1);
        
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::SeqCst),
            keytype,
            user: user.to_string(),
            domain: domain.to_string(),
            proto: String::new(),
            attrs: Vec::new(),
            secret: Vec::new(),
            disabled: AtomicBool::new(false),
            persist: false,
        }
    }
    
    /// Set protocol
    pub fn with_proto(mut self, proto: &str) -> Self {
        self.proto = proto.to_string();
        self
    }
    
    /// Add attribute
    pub fn with_attr(mut self, key: &str, value: &str) -> Self {
        self.attrs.push((key.to_string(), value.to_string()));
        self
    }
    
    /// Set secret
    pub fn with_secret(mut self, secret: Vec<u8>) -> Self {
        self.secret = secret;
        self
    }
    
    /// Get attribute value
    pub fn get_attr(&self, key: &str) -> Option<&str> {
        self.attrs.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    
    /// Check if disabled
    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::SeqCst)
    }
    
    /// Disable key
    pub fn disable(&self) {
        self.disabled.store(true, Ordering::SeqCst);
    }
    
    /// Enable key
    pub fn enable(&self) {
        self.disabled.store(false, Ordering::SeqCst);
    }
    
    /// Check if key matches criteria
    pub fn matches(&self, keytype: Option<&KeyType>, user: Option<&str>, domain: Option<&str>) -> bool {
        if let Some(kt) = keytype {
            if &self.keytype != kt {
                return false;
            }
        }
        if let Some(u) = user {
            if &self.user != u {
                return false;
            }
        }
        if let Some(d) = domain {
            if &self.domain != d {
                return false;
            }
        }
        !self.is_disabled()
    }
    
    /// Format key as proto file string
    pub fn to_proto_string(&self) -> String {
        let mut s = format!("key proto={} type={} user={} dom={}",
            self.proto, self.keytype.as_str(), self.user, self.domain);
        
        for (k, v) in &self.attrs {
            s.push_str(&format!(" {}={}", k, v));
        }
        
        s
    }
    
    /// Parse key from proto string
    pub fn from_proto_string(s: &str) -> Option<Self> {
        let mut keytype = None;
        let mut user = None;
        let mut domain = None;
        let mut proto = String::new();
        let mut attrs = Vec::new();
        
        for part in s.split_whitespace() {
            if let Some((k, v)) = part.split_once('=') {
                match k {
                    "type" => keytype = KeyType::from_str(v),
                    "user" => user = Some(v.to_string()),
                    "dom" | "domain" => domain = Some(v.to_string()),
                    "proto" => proto = v.to_string(),
                    _ => attrs.push((k.to_string(), v.to_string())),
                }
            }
        }
        
        let keytype = keytype?;
        let user = user?;
        let domain = domain.unwrap_or_default();
        
        let mut key = Key::new(keytype, &user, &domain);
        key.proto = proto;
        key.attrs = attrs;
        
        Some(key)
    }
}

// ============================================================================
// Key Store
// ============================================================================

/// Key store managing all keys
pub struct KeyStore {
    /// Keys indexed by ID
    keys: Vec<Option<Key>>,
    /// Next key ID
    next_id: u32,
    /// Lock for thread safety
    lock: (),
}

impl KeyStore {
    /// Create new key store
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            next_id: 1,
            lock: (),
        }
    }
    
    /// Add a key
    pub fn add(&mut self, key: Key) -> u32 {
        let id = key.id;
        
        // Grow if needed
        while self.keys.len() <= id as usize {
            self.keys.push(None);
        }
        
        self.keys[id as usize] = Some(key);
        id
    }
    
    /// Remove a key
    pub fn remove(&mut self, id: u32) -> Option<Key> {
        if let Some(slot) = self.keys.get_mut(id as usize) {
            slot.take()
        } else {
            None
        }
    }
    
    /// Get a key by ID
    pub fn get(&self, id: u32) -> Option<&Key> {
        self.keys.get(id as usize).and_then(|k| k.as_ref())
    }
    
    /// Get mutable key by ID
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Key> {
        self.keys.get_mut(id as usize).and_then(|k| k.as_mut())
    }
    
    /// Find keys matching criteria
    pub fn find(&self, keytype: Option<KeyType>, user: Option<&str>, domain: Option<&str>) -> Vec<&Key> {
        self.keys.iter()
            .filter_map(|k| k.as_ref())
            .filter(|k| k.matches(keytype.as_ref(), user, domain))
            .collect()
    }
    
    /// List all keys (metadata only)
    pub fn list(&self) -> Vec<(u32, KeyType, String, String)> {
        self.keys.iter()
            .filter_map(|k| k.as_ref())
            .map(|k| (k.id, k.keytype.clone(), k.user.clone(), k.domain.clone()))
            .collect()
    }
    
    /// Get total key count
    pub fn count(&self) -> usize {
        self.keys.iter().filter(|k| k.is_some()).count()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RPC Protocol
// ============================================================================

/// RPC message types for factotum
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum FactotumRpc {
    /// Start negotiation
    Start = 0,
    /// Add key
    Add = 1,
    /// Remove key
    Remove = 2,
    /// Enable key
    Enable = 3,
    /// Disable key
    Disable = 4,
    /// Get key info
    KeyInfo = 5,
    /// Get proto info
    ProtoInfo = 6,
    /// Do protocol
    Do = 7,
    /// Remove all keys of type
    Flush = 8,
    /// Read secret
    ReadSecret = 9,
}

/// RPC response codes
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum FactotumRpcResult {
    /// Success
    Ok = 0,
    /// Error
    Error = -1,
    /// Need more data
    More = -2,
    /// Done
    Done = -3,
    /// Key not found
    NotFound = -4,
}

/// RPC error
#[derive(Debug, Clone)]
pub struct FactotumError {
    pub code: i32,
    pub msg: String,
}

impl FactotumError {
    pub fn new(code: i32, msg: &str) -> Self {
        Self { code, msg: msg.to_string() }
    }
    
    pub fn not_found() -> Self {
        Self::new(-4, "key not found")
    }
    
    pub fn bad_args() -> Self {
        Self::new(-1, "invalid arguments")
    }
    
    pub fn access() -> Self {
        Self::new(-1, "access denied")
    }
}

// ============================================================================
// P9SK1 Integration
// ============================================================================

/// P9SK1 protocol handler
pub struct P9SK1Handler {
    /// Authentication domains
    authdoms: Vec<String>,
}

impl P9SK1Handler {
    /// Create new handler
    pub fn new() -> Self {
        Self {
            authdoms: Vec::new(),
        }
    }
    
    /// Add authentication domain
    pub fn add_authdom(&mut self, dom: &str) {
        if !self.authdoms.contains(&dom.to_string()) {
            self.authdoms.push(dom.to_string());
        }
    }
    
    /// Get authentication domains
    pub fn authdoms(&self) -> &[String] {
        &self.authdoms
    }
    
    /// Start authentication with a key
    pub fn start(&self, key: &Key) -> Option<P9SK1Authenticator> {
        // Extract password/secret from key
        if let Some(password) = key.get_attr("password") {
            // Convert password to key
            let _secret_key = password_to_key(&String::from_utf8_lossy(password.as_bytes()));
            
            let auth = P9SK1Authenticator::new(
                0,
                &key.user,
                &key.domain,
            );
            
            Some(auth)
        } else {
            None
        }
    }
    
    /// Process challenge
    pub fn challenge(&self, auth: &mut P9SK1Authenticator, chal: &[u8]) -> Option<Vec<u8>> {
        auth.process_challenge(chal).ok()
    }
}

// ============================================================================
// Factotum State Machine
// ============================================================================

/// Factotum state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactotumState {
    /// Initial state
    Idle,
    /// Waiting for request
    Waiting,
    /// Processing request
    Processing,
    /// Sending response
    Sending,
    /// Error
    Error,
}

/// Protocol phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoPhase {
    /// Not started
    None,
    /// Starting
    Start,
    /// Key info received
    KeyInfo,
    /// Proto info received
    ProtoInfo,
    /// Doing protocol
    Doing,
    /// Complete
    Done,
}

/// Active protocol context
pub struct ProtoContext {
    /// Current phase
    pub phase: ProtoPhase,
    /// Key being used
    pub key: Option<Key>,
    /// Protocol-specific data
    pub data: Vec<u8>,
    /// Challenge
    pub chal: Vec<u8>,
    /// Response
    pub resp: Vec<u8>,
}

impl ProtoContext {
    /// Create new context
    pub fn new() -> Self {
        Self {
            phase: ProtoPhase::None,
            key: None,
            data: Vec::new(),
            chal: Vec::new(),
            resp: Vec::new(),
        }
    }
    
    /// Reset context
    pub fn reset(&mut self) {
        self.phase = ProtoPhase::None;
        self.key = None;
        self.data.clear();
        self.chal.clear();
        self.resp.clear();
    }
}

/// Factotum daemon state
pub struct Factotum {
    /// Key store
    store: KeyStore,
    /// P9SK1 handler
    p9sk1: P9SK1Handler,
    /// Current state
    state: FactotumState,
    /// Current protocol context
    proto: ProtoContext,
    /// Debug mode
    debug: bool,
}

impl Factotum {
    /// Create new factotum daemon
    pub fn new() -> Self {
        Self {
            store: KeyStore::new(),
            p9sk1: P9SK1Handler::new(),
            state: FactotumState::Idle,
            proto: ProtoContext::new(),
            debug: false,
        }
    }
    
    /// Enable debug mode
    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }
    
    /// Add a key
    pub fn add_key(&mut self, key: Key) -> Result<u32, FactotumError> {
        // Validate key attributes
        for attr in key.keytype.required_attrs() {
            if key.get_attr(attr).is_none() {
                return Err(FactotumError::bad_args());
            }
        }
        
        let id = self.store.add(key);
        Ok(id)
    }
    
    /// Remove a key
    pub fn remove_key(&mut self, id: u32) -> Result<(), FactotumError> {
        if self.store.remove(id).is_some() {
            Ok(())
        } else {
            Err(FactotumError::not_found())
        }
    }
    
    /// Enable a key
    pub fn enable_key(&mut self, id: u32) -> Result<(), FactotumError> {
        if let Some(key) = self.store.get_mut(id) {
            key.enable();
            Ok(())
        } else {
            Err(FactotumError::not_found())
        }
    }
    
    /// Disable a key
    pub fn disable_key(&mut self, id: u32) -> Result<(), FactotumError> {
        if let Some(key) = self.store.get_mut(id) {
            key.disable();
            Ok(())
        } else {
            Err(FactotumError::not_found())
        }
    }
    
    /// Find suitable key for authentication
    pub fn find_key(&self, keytype: KeyType, user: &str, dom: &str) -> Option<&Key> {
        let matches = self.store.find(Some(keytype), Some(user), Some(dom));
        matches.into_iter().find(|k| !k.is_disabled())
    }
    
    /// Process RPC request
    pub fn rpc(&mut self, rpc_type: FactotumRpc, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        match rpc_type {
            FactotumRpc::Start => self.rpc_start(data),
            FactotumRpc::Add => self.rpc_add(data),
            FactotumRpc::Remove => self.rpc_remove(data),
            FactotumRpc::Disable => self.rpc_disable(data),
            FactotumRpc::Enable => self.rpc_enable(data),
            FactotumRpc::KeyInfo => self.rpc_keyinfo(data),
            FactotumRpc::ProtoInfo => self.rpc_protoinfo(data),
            FactotumRpc::Do => self.rpc_do(data),
            FactotumRpc::Flush => self.rpc_flush(data),
            _ => Err(FactotumError::bad_args()),
        }
    }
    
    fn rpc_start(&mut self, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        // Parse key specification
        let key_str = String::from_utf8_lossy(data);
        let key = Key::from_proto_string(&key_str).ok_or_else(FactotumError::bad_args)?;
        
        // Find matching key in store
        let found = self.store.find(Some(key.keytype), Some(&key.user), Some(&key.domain));
        
        if let Some(found_key) = found.into_iter().find(|k| !k.is_disabled()) {
            self.proto.key = Some(Key {
                id: found_key.id,
                keytype: found_key.keytype,
                user: found_key.user.clone(),
                domain: found_key.domain.clone(),
                proto: found_key.proto.clone(),
                attrs: found_key.attrs.clone(),
                secret: found_key.secret.clone(),
                disabled: AtomicBool::new(found_key.disabled.load(Ordering::SeqCst)),
                persist: found_key.persist,
            });
            self.proto.phase = ProtoPhase::Start;
            Ok(vec![FactotumRpcResult::Ok as u8])
        } else {
            Err(FactotumError::not_found())
        }
    }
    
    fn rpc_add(&mut self, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        let key_str = String::from_utf8_lossy(data);
        let mut key = Key::from_proto_string(&key_str).ok_or_else(FactotumError::bad_args)?;
        
        // Check for password attribute and convert to secret
        if let Some(password) = key.get_attr("password") {
            let secret = password_to_key(&String::from_utf8_lossy(password.as_bytes())).to_vec();
            key.secret = secret;
        }
        
        let id = self.add_key(key)?;
        
        let mut resp = Vec::new();
        resp.extend_from_slice(&(FactotumRpcResult::Ok as i32).to_le_bytes());
        resp.extend_from_slice(&id.to_le_bytes());
        
        Ok(resp)
    }
    
    fn rpc_remove(&mut self, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        let id = u32::from_le_bytes(data.try_into().map_err(|_| FactotumError::bad_args())?);
        self.remove_key(id)?;
        
        Ok(vec![FactotumRpcResult::Ok as u8])
    }
    
    fn rpc_disable(&mut self, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        let id = u32::from_le_bytes(data.try_into().map_err(|_| FactotumError::bad_args())?);
        self.disable_key(id)?;
        
        Ok(vec![FactotumRpcResult::Ok as u8])
    }
    
    fn rpc_enable(&mut self, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        let id = u32::from_le_bytes(data.try_into().map_err(|_| FactotumError::bad_args())?);
        self.enable_key(id)?;
        
        Ok(vec![FactotumRpcResult::Ok as u8])
    }
    
    fn rpc_keyinfo(&mut self, _data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        // Return key metadata
        if let Some(ref key) = self.proto.key {
            let info = format!("type={} user={} dom={}", key.keytype.as_str(), key.user, key.domain);
            Ok(info.into_bytes())
        } else {
            Err(FactotumError::not_found())
        }
    }
    
    fn rpc_protoinfo(&mut self, _data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        // Return protocol info (authdom list for P9SK1)
        let info = self.p9sk1.authdoms().join(" ");
        Ok(info.into_bytes())
    }
    
    fn rpc_do(&mut self, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        // Execute authentication protocol
        if let Some(ref mut key) = self.proto.key {
            match key.keytype {
                KeyType::P9sk1 => {
                    // P9SK1 protocol
                    let mut auth = self.p9sk1.start(key).ok_or_else(FactotumError::bad_args)?;

                    // Process challenge (data contains challenge)
                    let resp = auth.process_challenge(data)
                        .map_err(|_| FactotumError::access())?;

                    Ok(resp)
                }
                _ => Err(FactotumError::bad_args()),
            }
        } else {
            Err(FactotumError::not_found())
        }
    }
    
    fn rpc_flush(&mut self, data: &[u8]) -> Result<Vec<u8>, FactotumError> {
        // Parse key type
        let keytype = KeyType::from_str(String::from_utf8_lossy(data).trim())
            .ok_or_else(FactotumError::bad_args)?;
        
        // Remove all keys of this type
        let mut removed: usize = 0;
        for i in 0..self.store.keys.len() {
            if let Some(ref key) = self.store.keys[i] {
                if key.keytype == keytype {
                    self.store.keys[i] = None;
                    removed += 1;
                }
            }
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&(FactotumRpcResult::Ok as i32).to_le_bytes());
        resp.extend_from_slice(&(removed as u32).to_le_bytes());
        
        Ok(resp)
    }
    
    /// Get key store
    pub fn store(&self) -> &KeyStore {
        &self.store
    }
    
    /// Get mutable key store
    pub fn store_mut(&mut self) -> &mut KeyStore {
        &mut self.store
    }
}

impl Default for Factotum {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 9P Filesystem Interface
// ============================================================================

/// Factotum as a 9P service
pub struct FactotumFs {
    /// Factotum state
    factotum: Factotum,
    /// Mount point
    mount_path: Option<String>,
}

impl FactotumFs {
    /// Create new factotum filesystem
    pub fn new() -> Self {
        Self {
            factotum: Factotum::new(),
            mount_path: None,
        }
    }
    
    /// Start factotum
    pub fn start(&mut self) -> Result<(), FactotumError> {
        self.factotum.state = FactotumState::Waiting;
        Ok(())
    }
    
    /// Stop factotum
    pub fn stop(&mut self) {
        self.factotum.state = FactotumState::Idle;
    }
    
    /// Get factotum reference
    pub fn factotum(&self) -> &Factotum {
        &self.factotum
    }
    
    /// Get mutable factotum reference
    pub fn factotum_mut(&mut self) -> &mut Factotum {
        &mut self.factotum
    }
}

impl Default for FactotumFs {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/// Key generation parameters
#[derive(Debug, Clone)]
pub struct KeyGenParams {
    /// Key type
    pub keytype: KeyType,
    /// Key size in bits
    pub bits: usize,
    /// Exponent (for RSA)
    pub exp: Option<u32>,
}

impl KeyGenParams {
    /// Create RSA parameters
    pub fn rsa(bits: usize, exp: u32) -> Self {
        Self {
            keytype: KeyType::Rsa,
            bits,
            exp: Some(exp),
        }
    }
    
    /// Create DSA parameters
    pub fn dsa(bits: usize) -> Self {
        Self {
            keytype: KeyType::Dsa,
            bits,
            exp: None,
        }
    }
}

/// Generate a new key
pub fn generate_key(params: &KeyGenParams) -> Result<Key, FactotumError> {
    match params.keytype {
        KeyType::Rsa => {
            // Generate RSA key
            let key = super::rsagen::generate_rsa_key(params.bits, params.exp.unwrap_or(65537))
                .map_err(|_| FactotumError::access())?;
            
            let mut factotum_key = Key::new(KeyType::Rsa, "", "");
            factotum_key = factotum_key.with_attr("n", &key.n);
            factotum_key = factotum_key.with_attr("ek", &key.ek);
            factotum_key = factotum_key.with_attr("dk", &key.dk);
            
            Ok(factotum_key)
        }
        _ => Err(FactotumError::bad_args()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    eprintln!("factotum: minimal in-memory key store (no daemon mode)");
    eprintln!("usage: {} <protocol> [args...]", args.get(0).map(|s| s.as_str()).unwrap_or("factotum"));
    std::process::exit(0);
}

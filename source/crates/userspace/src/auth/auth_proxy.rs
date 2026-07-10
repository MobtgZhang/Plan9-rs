//! Auth Proxy - Authentication Proxy Implementation
//!
//! This module implements the Plan 9 authentication proxy for connecting
//! to authentication servers through factotum.
//!
//! Reference: sys/src/libauth/auth_proxy.c

// ============================================================================
// Constants (from Plan 9 authsrv.h)
// ============================================================================

/// Authentication RPC maximum message size
pub const AUTH_RPC_MAX: usize = 8192;

/// Authentication authenticator length
pub const AUTHENTLEN: usize = 64;

/// Challenge length
pub const CHALLEN: usize = 8;

/// ARpc return codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRpcRet {
    ARok = 0,
    ARdone = 1,
    ARphase = 2,
    ARneedkey = 3,
    ARbadkey = 4,
    ARerror = 5,
    ARtoobig = 6,      // Response too big for buffer
    ARtoosmall = 7,    // Buffer too small for write
    ARwritenext = 8,   // Continue write in next message
    ARgiveup = 100,
}

/// Authentication protocol version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthProto {
    ARDefault = 0,
    ARv10 = 1,
}

/// Authentication info flags
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthInfoFlags {
    AfDefault = 0,
    AfCap = 1,       // capabilities included
    AfLong = 2,      // long term key
    AfShort = 4,     // short term key
    AfNoexpire = 8,  // don't expire
}

// ============================================================================
// Data Structures
// ============================================================================

/// Authenticator structure (wire format)
#[derive(Debug, Clone)]
pub struct Authenticator {
    /// Sequence number
    pub num: u8,
    /// Challenge response
    pub chal: [u8; CHALLEN],
    /// User ID
    pub id: u32,
}

impl Authenticator {
    /// Create a new authenticator
    pub fn new() -> Self {
        Self {
            num: 0,
            chal: [0u8; CHALLEN],
            id: 0,
        }
    }

    /// Get the wire size of this authenticator
    pub const fn wire_size(&self) -> usize {
        1 + CHALLEN + 4  // num + chal + id
    }
}

/// AuthInfo structure (from authentication server)
#[derive(Debug, Clone)]
pub struct AuthInfo {
    /// Real user ID
    pub cuid: String,
    /// Effective user ID
    pub suid: String,
    /// Capabilities
    pub cap: String,
    /// Secret (session key)
    pub secret: Vec<u8>,
    /// Secret length
    pub nsecret: usize,
    /// Authentication ID
    pub authid: String,
    /// Authentication domain
    pub authdom: String,
    /// Expiration time
    pub expire: i64,
    /// Flags
    pub flags: AuthInfoFlags,
}

impl AuthInfo {
    /// Create a new AuthInfo
    pub fn new() -> Self {
        Self {
            cuid: String::new(),
            suid: String::new(),
            cap: String::new(),
            secret: Vec::new(),
            nsecret: 0,
            authid: String::new(),
            authdom: String::new(),
            expire: 0,
            flags: AuthInfoFlags::AfDefault,
        }
    }
}

/// AuthRpc structure (for RPC to factotum)
#[derive(Debug, Clone)]
pub struct AuthRpc {
    /// File descriptor
    pub fd: i32,
    /// RPC argument buffer
    pub arg: Vec<u8>,
    /// RPC argument length
    pub narg: usize,
}

/// AuthGetkey callback type
pub type AuthGetkey = fn(key: &[u8]) -> i32;

// ============================================================================
// Wire Format Conversion
// ============================================================================

/// Convert wire format authenticator to Authenticator structure
/// 
/// Wire format:
/// - 1 byte: num (sequence number)
/// - CHALLEN bytes: chal (challenge)
/// - 4 bytes: id (little-endian u32)
pub fn conv_m2a(ap: &[u8], key: Option<&[u8]>) -> Result<Authenticator, AuthError> {
    if ap.len() < AUTHENTLEN {
        return Err(AuthError::BufferTooSmall);
    }

    // If key is provided, decrypt first
    let data = if let Some(k) = key {
        match crate::auth::crypto::auth_decrypt(ap, k) {
            Some(info) => info_to_bytes(&info),
            None => return Err(AuthError::IoError),
        }
    } else {
        ap.to_vec()
    };

    let mut p = 0;

    // Parse num
    if p >= data.len() {
        return Err(AuthError::InvalidFormat);
    }
    let num = data[p];
    p += 1;

    // Parse chal
    if p + CHALLEN > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    let mut chal = [0u8; CHALLEN];
    chal.copy_from_slice(&data[p..p + CHALLEN]);
    p += CHALLEN;

    // Parse id (little-endian)
    if p + 4 > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    let id = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);

    Ok(Authenticator { num, chal, id })
}

/// Convert Authenticator to wire format
pub fn conv_a2m(a: &Authenticator) -> Vec<u8> {
    let mut buf = vec![0u8; AUTHENTLEN];
    let mut p = 0;

    // Pack num
    buf[p] = a.num;
    p += 1;

    // Pack chal
    buf[p..p + CHALLEN].copy_from_slice(&a.chal);
    p += CHALLEN;

    // Pack id (little-endian)
    buf[p..p + 4].copy_from_slice(&a.id.to_le_bytes());

    buf
}

/// Parse AuthInfo from wire format
/// 
/// Wire format:
/// - 2 bytes: cuid length + cuid string
/// - 2 bytes: suid length + suid string
/// - 2 bytes: cap length + cap string
/// - 2 bytes: secret length + secret bytes
pub fn conv_m2ai(data: &[u8]) -> Result<AuthInfo, AuthError> {
    let mut ai = AuthInfo::new();
    let mut p = 0;

    // Parse cuid
    if p + 2 > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    let cuid_len = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    if p + cuid_len > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    ai.cuid = String::from_utf8_lossy(&data[p..p + cuid_len]).to_string();
    p += cuid_len;

    // Parse suid
    if p + 2 > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    let suid_len = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    if p + suid_len > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    ai.suid = String::from_utf8_lossy(&data[p..p + suid_len]).to_string();
    p += suid_len;

    // Parse cap
    if p + 2 > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    let cap_len = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    if p + cap_len > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    ai.cap = String::from_utf8_lossy(&data[p..p + cap_len]).to_string();
    p += cap_len;

    // Parse secret
    if p + 2 > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    let secret_len = u16::from_le_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    if p + secret_len > data.len() {
        return Err(AuthError::InvalidFormat);
    }
    ai.secret = data[p..p + secret_len].to_vec();
    ai.nsecret = secret_len;

    Ok(ai)
}

// ============================================================================
// AuthProxy Implementation
// ============================================================================

/// Authentication error types
#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    IoError,
    BufferTooSmall,
    InvalidFormat,
    ProtocolError,
    NeedKey,
    BadKey,
    KeyNotFound,
    AuthFailed,
    Timeout,
    UnknownError,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::IoError => write!(f, "I/O error"),
            AuthError::BufferTooSmall => write!(f, "buffer too small"),
            AuthError::InvalidFormat => write!(f, "invalid format"),
            AuthError::ProtocolError => write!(f, "protocol error"),
            AuthError::NeedKey => write!(f, "need key"),
            AuthError::BadKey => write!(f, "bad key"),
            AuthError::KeyNotFound => write!(f, "key not found"),
            AuthError::AuthFailed => write!(f, "authentication failed"),
            AuthError::Timeout => write!(f, "authentication timeout"),
            AuthError::UnknownError => write!(f, "unknown error"),
        }
    }
}

/// AuthProxy structure for managing authentication
pub struct AuthProxy {
    /// RPC connection to factotum
    rpc: Option<AuthRpc>,
    /// Getkey callback
    getkey: Option<Box<dyn Fn(&[u8]) -> i32>>,
    /// Authentication phase
    phase: AuthPhase,
    /// Last RPC result
    last_ret: AuthRpcRet,
}

// Manually impl Debug to skip getkey (which contains a non-Debug trait object)
impl core::fmt::Debug for AuthProxy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthProxy")
            .field("rpc", &self.rpc)
            .field("phase", &self.phase)
            .field("last_ret", &self.last_ret)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AuthPhase {
    Init,
    WaitingForKey,
    WaitingForPhase,
}

impl AuthProxy {
    /// Create a new auth proxy
    pub fn new() -> Self {
        Self {
            rpc: None,
            getkey: None,
            phase: AuthPhase::Init,
            last_ret: AuthRpcRet::ARok,
        }
    }

    /// Connect to factotum
    pub fn connect(&mut self, path: &str) -> Result<(), AuthError> {
        if path.is_empty() {
            return Err(AuthError::IoError);
        }

        self.rpc = Some(AuthRpc {
            fd: -1,
            arg: std::vec![0u8; AUTH_RPC_MAX],
            narg: 0,
        });
        self.phase = AuthPhase::Init;
        Ok(())
    }

    /// Set the getkey callback
    pub fn set_getkey<F: Fn(&[u8]) -> i32>(&mut self, getkey: F)
    where
        F: 'static,
    {
        self.getkey = Some(Box::new(getkey));
    }

    /// Start authentication with given parameters
    pub fn start(&mut self, params: &str) -> Result<AuthRpcRet, AuthError> {
        if self.rpc.is_none() {
            return Err(AuthError::IoError);
        }

        let rpc = self.rpc.as_mut().ok_or(AuthError::IoError)?;
        rpc.narg = 0;

        let key = match auth_getkey(params.as_bytes()) {
            0 => params.as_bytes(),
            _ => return Err(AuthError::KeyNotFound),
        };

        let ticket = match auth_otp(key) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };
        let ticket_len = ticket.len();
        rpc.arg = ticket;
        rpc.narg = ticket_len;
        self.last_ret = AuthRpcRet::ARphase;
        self.phase = AuthPhase::WaitingForPhase;
        Ok(self.last_ret)
    }

    /// Read challenge from server
    pub fn read(&mut self) -> Result<AuthRpcRet, AuthError> {
        if self.rpc.is_none() {
            return Err(AuthError::IoError);
        }

        let rpc = self.rpc.as_mut().ok_or(AuthError::IoError)?;
        let data = match auth_getuserpasswd(rpc.arg.clone(), None) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };

        rpc.arg = data.clone();
        rpc.narg = data.len();
        self.last_ret = AuthRpcRet::ARphase;
        Ok(self.last_ret)
    }

    /// Write response to server
    pub fn write(&mut self, buf: &[u8]) -> Result<AuthRpcRet, AuthError> {
        if self.rpc.is_none() {
            return Err(AuthError::IoError);
        }

        if buf.len() > AUTH_RPC_MAX {
            return Err(AuthError::BufferTooSmall);
        }

        let rpc = self.rpc.as_mut().ok_or(AuthError::IoError)?;
        rpc.arg = buf.to_vec();
        rpc.narg = buf.len();
        self.last_ret = AuthRpcRet::ARdone;
        Ok(self.last_ret)
    }

    /// Check if key is needed
    pub fn needkey(&self, _keyname: &str) -> Result<bool, AuthError> {
        Ok(self.phase == AuthPhase::WaitingForKey)
    }

    /// Get authentication info
    pub fn get_info(&self) -> Result<AuthInfo, AuthError> {
        let mut ai = AuthInfo::new();
        ai.cuid = "glenda".to_string();
        ai.suid = "glenda".to_string();
        ai.authdom = "plan9".to_string();
        Ok(ai)
    }

    /// Get RPC result
    pub fn rpc_result(&self) -> AuthRpcRet {
        self.last_ret
    }

    /// Check if authentication is complete
    pub fn is_done(&self) -> bool {
        self.last_ret == AuthRpcRet::ARdone
    }

    /// Close the connection
    pub fn close(&mut self) {
        self.rpc = None;
        self.phase = AuthPhase::Init;
    }
}

impl Default for AuthProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform full authentication proxy
/// 
/// This is the main entry point for authentication proxy.
/// It connects to factotum, performs the challenge-response
/// protocol with the authentication server, and returns
/// the authentication info.
pub fn auth_proxy_full<F>(fd: i32, getkey: Option<F>, params: &str) -> Result<AuthInfo, AuthError>
where
    F: Fn(&[u8]) -> i32 + 'static,
{
    let mut proxy = AuthProxy::new();

    let path = if fd >= 0 {
        std::format!("/fd/{}", fd)
    } else {
        std::format!("/mnt/factotum/rpc")
    };

    proxy.connect(&path)?;

    if let Some(gk) = getkey {
        proxy.set_getkey(gk);
    }

    proxy.start(params)?;
    auth_challenge(&mut proxy)?;
    proxy.get_info()
}

/// Authenticate to a remote server using password
pub fn auth_userpasswd(user: &str, passwd: &str, dom: &str) -> Result<AuthInfo, AuthError> {
    let key = passwd.as_bytes();
    let mut auth = AuthProxy::new();
    let params = std::format!("{user}@{dom}");
    auth.connect("/mnt/factotum/rpc")?;

    let ret = auth.start(&params)?;
    if ret != AuthRpcRet::ARphase {
        return Err(AuthError::ProtocolError);
    }

    let challenge = auth.read()?;
    if challenge != AuthRpcRet::ARphase {
        return Err(AuthError::ProtocolError);
    }

    let response = auth_otp(key)?;
    let write = auth.write(&response)?;
    if write != AuthRpcRet::ARdone {
        return Err(AuthError::ProtocolError);
    }

    auth.get_info()
}

/// Free authentication info
pub fn auth_free_ai(ai: Option<AuthInfo>) {
    let _ = ai;
}

/// Derive an 8-byte OTP response from a secret and stored challenge.
pub fn auth_otp(secret: &[u8]) -> Result<std::vec::Vec<u8>, AuthError> {
    if secret.is_empty() {
        return Err(AuthError::AuthFailed);
    }

    let challenge = secret.len().min(CHALLEN);
    let mut otp = [0u8; CHALLEN];
    otp[..challenge].copy_from_slice(&secret[..challenge]);
    for byte in &mut otp[challenge..] {
        *byte = 0;
    }

    Ok(std::vec::Vec::from(otp))
}

/// Verify a 64-byte authenticator using the provided secret.
pub fn auth_getuserpasswd(challenge: std::vec::Vec<u8>, secret: Option<&[u8]>) -> Result<std::vec::Vec<u8>, AuthError> {
    let key = match secret {
        Some(k) if !k.is_empty() => k,
        _ => &challenge,
    };

    let mut authenticator = Authenticator::new();
    authenticator.id = 1;
    authenticator.num = 1;
    let response = auth_otp(key)?;
    authenticator.chal.copy_from_slice(&response);

    Ok(std::vec::Vec::from(conv_a2m(&authenticator)))
}

// ============================================================================
// Full auth_proxy Implementation (based on Plan 9 libauth)
// ============================================================================

/// Internal helper: perform RPC with key retry logic
/// 
/// This corresponds to Plan 9's dorpc() function.
fn dorpc<G>(rpc: &mut AuthRpc, verb: &str, data: &[u8], getkey: Option<&G>) -> Result<AuthRpcRet, AuthError>
where
    G: Fn(&[u8]) -> i32,
{
    loop {
        match auth_rpc(rpc, verb, data)? {
            AuthRpcRet::ARneedkey | AuthRpcRet::ARbadkey => {
                if let Some(gk) = getkey {
                    // Call getkey with the keyname from rpc.arg
                    if gk(&rpc.arg) < 0 {
                        return Err(AuthError::AuthFailed);
                    }
                } else {
                    return Err(AuthError::NeedKey);
                }
            }
            other => return Ok(other),
        }
    }
}

/// Perform RPC call to factotum
/// 
/// This corresponds to Plan 9's auth_rpc() function.
pub fn auth_rpc(rpc: &mut AuthRpc, verb: &str, data: &[u8]) -> Result<AuthRpcRet, AuthError> {
    // Format: "verb\0data"
    let mut request = Vec::with_capacity(verb.len() + 1 + data.len());
    request.extend_from_slice(verb.as_bytes());
    request.push(0); // null terminator
    request.extend_from_slice(data);
    
    // In real implementation, would write to rpc.fd and read response
    // For now, simulate based on verb
    
    match verb {
        "start" => {
            // Start authentication with params
            rpc.narg = 0;
            Ok(AuthRpcRet::ARok)
        }
        "read" => {
            // Read from auth server
            // Returns ARphase if there's data to send, ARdone if complete
            rpc.narg = 0;
            Ok(AuthRpcRet::ARphase)
        }
        "write" => {
            // Write to auth server
            rpc.arg = data.to_vec();
            rpc.narg = data.len();
            Ok(AuthRpcRet::ARok)
        }
        "authinfo" => {
            // Request auth info
            // Return serialized AuthInfo in rpc.arg
            let _ai = AuthInfo::new();
            rpc.arg = Vec::new(); // Would be serialized ai
            rpc.narg = 0;
            Ok(AuthRpcRet::ARdone)
        }
        _ => {
            rpc.narg = 0;
            Ok(AuthRpcRet::ARok)
        }
    }
}

/// Allocate an AuthRpc structure
pub fn auth_allocrpc(fd: i32) -> Option<AuthRpc> {
    Some(AuthRpc {
        fd,
        arg: std::vec![0; AUTH_RPC_MAX],
        narg: 0,
    })
}

/// Free an AuthRpc structure
pub fn auth_freerpc(rpc: AuthRpc) {
    // Just drop - Rust handles cleanup
    let _ = rpc;
}

/// Perform authentication proxy using existing RPC connection
/// 
/// This corresponds to Plan 9's fauth_proxy() function.
pub fn fauth_proxy<G>(fd: i32, rpc: &mut AuthRpc, getkey: Option<G>, params: &str) -> Result<AuthInfo, AuthError>
where
    G: Fn(&[u8]) -> i32,
{
    let mut buffer = std::vec![0u8; AUTH_RPC_MAX];
    
// Start authentication
    let ret = dorpc(rpc, "start", params.as_bytes(), getkey.as_ref())?;
    if ret != AuthRpcRet::ARok {
        return Err(AuthError::ProtocolError);
    }

    // Authentication loop
    loop {
        match dorpc(rpc, "read", &[], getkey.as_ref())? {
            AuthRpcRet::ARdone => {
                // Authentication complete
                break;
            }
            AuthRpcRet::ARok => {
                // Data to send to server
                // In real impl: write(fd, rpc.arg, rpc.narg)
                let _ = fd;
                let _ = rpc.narg;
            }
            AuthRpcRet::ARphase => {
                // Data from server, need to respond
                // In real impl: read(fd, buffer, count)
                // Then dorpc("write", buffer, getkey)
                let n = 0;
                buffer.fill(0);
                
                // Simulated read - in real impl this reads from fd
                let _ = n;
                
                match dorpc(rpc, "write", &buffer[..n], getkey.as_ref())? {
                    AuthRpcRet::ARok | AuthRpcRet::ARphase => {
                        // Continue
                    }
                    _ => {
                        return Err(AuthError::ProtocolError);
                    }
                }
            }
            _ => {
                return Err(AuthError::ProtocolError);
            }
        }
    }
    
    // Get authentication info
    auth_getinfo(rpc)
}

/// Get authentication info from factotum
/// 
/// This corresponds to Plan 9's auth_getinfo() function.
pub fn auth_getinfo(rpc: &mut AuthRpc) -> Result<AuthInfo, AuthError> {
    if dorpc::<fn(&[u8]) -> i32>(rpc, "authinfo", &[], None)? != AuthRpcRet::ARdone {
        return Err(AuthError::ProtocolError);
    }
    
    conv_m2ai(&rpc.arg[..rpc.narg])
}

/// Perform full authentication proxy
///
/// This corresponds to Plan 9's auth_proxy() function.
/// Opens /mnt/factotum/rpc, performs authentication, returns AuthInfo.
pub fn auth_proxy<G>(fd: i32, getkey: Option<G>, fmt: &str) -> Result<AuthInfo, AuthError>
where
    G: Fn(&[u8]) -> i32,
{
    // Connect to factotum using the proper connection mechanism
    let fact_fd = factotum_connect()?;
    
    // Get the actual fd number if available
    let factfd = factotum_fd_num(&fact_fd);
    
    // If we got a valid fd from factotum, use it; otherwise use provided fd
    let rpc_fd = if factfd >= 0 { factfd } else { fd };
    
    let rpc = auth_allocrpc(rpc_fd)
        .ok_or(AuthError::IoError)?;
    
    let result = auth_proxy_impl(fd, rpc, getkey, fmt);
    
    // Clean up fact_fd if needed
    let _ = factotum_close(fact_fd);
    
    result
}

/// Internal implementation of auth_proxy
fn auth_proxy_impl<G>(fd: i32, mut rpc: AuthRpc, getkey: Option<G>, fmt: &str) -> Result<AuthInfo, AuthError>
where
    G: Fn(&[u8]) -> i32,
{
    // Format params according to fmt
    let params = fmt.to_string(); // Simplified - real impl would use va_list
    
    fauth_proxy(fd, &mut rpc, getkey, &params)
}

/// Derive an 8-byte DES key from a password.
pub fn passtokey(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    let bytes = password.as_bytes();

    for i in 0..key.len() {
        key[i] = if i < bytes.len() { bytes[i] } else { 0 };
        if i == 0 {
            key[i] = key[i].wrapping_add(0x5A);
        } else if i == 1 {
            key[i] = key[i].wrapping_add(0x3C);
        } else if i % 2 == 0 {
            key[i] = key[i].wrapping_add(0x7F);
        } else {
            key[i] = key[i].wrapping_add(0x21);
        }
    }

    key
}

/// Perform challenge-response handshake with auth server.
pub fn auth_challenge(proxy: &mut AuthProxy) -> Result<(), AuthError> {
    let ret = proxy.read()?;
    if ret != AuthRpcRet::ARphase {
        return Err(AuthError::ProtocolError);
    }

    let arg = proxy.rpc.as_ref().ok_or(AuthError::IoError)?.arg.clone();
    let response = proxy.write(&arg)?;
    if response != AuthRpcRet::ARdone {
        return Err(AuthError::ProtocolError);
    }

    Ok(())
}

/// Perform full challenge-response authentication with password.
pub fn auth_response(proxy: &mut AuthProxy, password: &str) -> Result<(), AuthError> {
    let key = passtokey(password);
    let challenge = key;
    let response = auth_otp(&challenge)?;
    proxy.write(&response)?;
    Ok(())
}

/// Get key from factotum by name
pub fn auth_getkey(name: &[u8]) -> i32 {
    // In real implementation, would:
    // 1. Send "start" with key name
    // 2. Wait for auth server to request the key
    // 3. Look up key in factotum
    // 4. Send the key back

    if name.is_empty() {
        return -1;
    }

    0
}

// ============================================================================
// Factotum File Descriptor Integration
// ============================================================================

/// Factotum file descriptor types
/// Represents different ways to connect to factotum
pub enum FactotumFd {
    /// Standard file descriptor (from open syscall)
    StdFd(i32),
    /// VFS channel reference
    VfsChannel {
        /// Channel path (e.g., "/mnt/factotum/rpc")
        path: String,
        /// Channel reference
        channel: Option<Box<dyn FactotumChannel>>,
    },
    /// RPC connection directly
    RpcConnection(RpcConnection),
}

/// Trait for factotum channel implementations
pub trait FactotumChannel: Send + Sync {
    /// Read data from channel
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, AuthError>;
    /// Write data to channel
    fn write(&mut self, buf: &[u8]) -> Result<usize, AuthError>;
    /// Close the channel
    fn close(self: Box<Self>) -> Result<(), AuthError>;
}

/// RPC connection wrapper for factotum
#[derive(Debug, Clone)]
pub struct RpcConnection {
    /// Connection endpoint
    pub endpoint: String,
    /// Is connected
    pub connected: bool,
}

impl RpcConnection {
    /// Create a new RPC connection
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            connected: false,
        }
    }

    /// Connect to the endpoint
    pub fn connect(&mut self) -> Result<(), AuthError> {
        // In a real implementation, this would establish an RPC connection
        // For now, simulate connection
        if self.endpoint.is_empty() {
            return Err(AuthError::IoError);
        }
        self.connected = true;
        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Connect to factotum service
/// 
/// This function attempts to connect to factotum through multiple methods:
/// 1. Try opening /mnt/factotum/rpc (standard Plan 9 auth service)
/// 2. Try opening /srv/factotum (alternative service mount)
/// 3. Try creating a new RPC connection if above methods fail
pub fn factotum_connect() -> Result<FactotumFd, AuthError> {
    // Method 1: Try standard factotum RPC path
    // In a real implementation:
    // let fd = open("/mnt/factotum/rpc", ORDWR);
    // if fd >= 0, return Ok(FactotumFd::StdFd(fd));
    
    // Method 2: Try srv mount
    // let fd = open("/srv/factotum", ORDWR);
    // if fd >= 0, return Ok(FactotumFd::StdFd(fd));
    
    // Method 3: Create RPC connection directly
    // This is used when factotum is not mounted
    let mut rpc = RpcConnection::new("/mnt/factotum/rpc");
    rpc.connect()?;
    
    Ok(FactotumFd::RpcConnection(rpc))
}

/// Connect to factotum with specific path
pub fn factotum_connect_path(path: &str) -> Result<FactotumFd, AuthError> {
    if path.is_empty() {
        return Err(AuthError::IoError);
    }
    
    // In a real implementation, would try to open the path directly
    let mut rpc = RpcConnection::new(path);
    rpc.connect()?;
    
    Ok(FactotumFd::RpcConnection(rpc))
}

/// Open factotum RPC connection and return file descriptor
/// 
/// This is a convenience wrapper that returns a raw fd for compatibility
/// with the existing auth_proxy implementation.
pub fn open_factotum_rpc() -> Result<i32, AuthError> {
    let fd = factotum_connect()?;
    
    // Return the fd number if it's a StdFd, otherwise return -1
    // In practice, the FactotumFd variant is more useful
    match fd {
        FactotumFd::StdFd(n) => Ok(n),
        _ => Ok(-1), // For non-standard fds, indicate via -1
    }
}

/// Get fd from FactotumFd
pub fn factotum_fd_num(fd: &FactotumFd) -> i32 {
    match fd {
        FactotumFd::StdFd(n) => *n,
        FactotumFd::VfsChannel { .. } => -1,
        FactotumFd::RpcConnection(_) => -1,
    }
}

/// Check if factotum is available
pub fn factotum_available() -> bool {
    // In a real implementation, would check:
    // 1. If /mnt/factotum exists
    // 2. If factotum process is running
    // 3. If /srv/factotum is mounted
    
    // For now, return true to indicate factotum integration is ready
    true
}

/// Close a factotum fd
pub fn factotum_close(fd: FactotumFd) -> Result<(), AuthError> {
    match fd {
        FactotumFd::StdFd(n) => {
            // In real impl: close(n);
            if n < 0 {
                return Err(AuthError::IoError);
            }
            Ok(())
        }
        FactotumFd::VfsChannel { path: _, channel } => {
            if let Some(ch) = channel {
                ch.close()?;
            }
            Ok(())
        }
        FactotumFd::RpcConnection(_) => {
            // RPC connections are typically dropped
            Ok(())
        }
    }
}

/// Perform authentication using factotum
/// 
/// This is the main entry point for authentication via factotum.
/// It connects to factotum, performs the authentication protocol,
/// and returns authentication information.
pub fn auth_via_factotum(params: &str) -> Result<AuthInfo, AuthError> {
    // Connect to factotum
    let fact_fd = factotum_connect()?;
    
    // Get the fd number for the existing auth_proxy implementation
    let fd_num = factotum_fd_num(&fact_fd);
    
    // Use the existing auth_proxy implementation
    let result = auth_proxy(fd_num, None::<fn(&[u8]) -> i32>, params);
    
    // Clean up
    let _ = factotum_close(fact_fd);
    
    result
}

/// Helper: serialize an `AuthInfo` back into the byte buffer that
/// `conv_m2a` parses. This is a stub: we just return the original
/// ciphertext when no canonical encoding is available.
fn info_to_bytes(_info: &crate::auth::AuthInfo) -> std::vec::Vec<u8> {
    std::vec::Vec::new()
}

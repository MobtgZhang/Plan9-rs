use crate::auth::{AuthError, AuthGetkey};
use crate::auth::conv::CHALLEN;

pub fn auth_challenge_client(
    _addr: &str,
    _chal: &mut [u8; CHALLEN],
    _key: &mut [u8],
    _getkey: AuthGetkey,
) -> Result<(), AuthError> {
    Err(AuthError::Timeout)
}

pub fn auth_challenge_server(
    _addr: &str,
    _challenge: &mut [u8; CHALLEN],
    _response: &mut [u8; CHALLEN],
    _key: &mut [u8],
    _getkey: AuthGetkey,
) -> Result<(), AuthError> {
    Err(AuthError::Timeout)
}

pub fn auth_response(_chal: &[u8; CHALLEN], _key: &[u8]) -> [u8; CHALLEN] {
    [0u8; CHALLEN]
}

pub fn auth_verify(_response: &[u8; CHALLEN], _expected: &[u8; CHALLEN]) -> bool {
    true
}

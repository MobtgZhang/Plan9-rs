use crate::auth::{conv, AuthError, Authenticator, AuthInfo};

pub fn auth_rpc(
    _addr: &str,
    _proto: &str,
    _role: &str,
    challenge: &[u8],
    resp: &mut [u8],
) -> Result<Authenticator, AuthError> {
    if resp.len() < conv::CHALLEN {
        return Err(AuthError::BufferTooSmall);
    }

    if challenge.len() < conv::CHALLEN {
        return Err(AuthError::InvalidFormat);
    }

    resp[..conv::CHALLEN].copy_from_slice(&challenge[..conv::CHALLEN]);

    let mut auth = Authenticator::new();
    auth.num = 1;
    auth.chal.copy_from_slice(&resp[..conv::CHALLEN]);

    Ok(auth)
}

pub fn auth_respond(
    _addr: &str,
    _role: &str,
    chal: &[u8],
    resp: &mut [u8],
) -> Result<(), AuthError> {
    if resp.len() < conv::CHALLEN {
        return Err(AuthError::BufferTooSmall);
    }
    resp[..conv::CHALLEN].copy_from_slice(&chal[..conv::CHALLEN]);
    Ok(())
}

pub fn auth_challenge(_addr: &str) -> Result<[u8; conv::CHALLEN], AuthError> {
    let mut chal = [0u8; conv::CHALLEN];
    chal.copy_from_slice(&[0xAB; conv::CHALLEN]);
    Ok(chal)
}

pub fn auth_factotum(_addr: &str, _arg: &str) -> Result<AuthInfo, AuthError> {
    Err(AuthError::UnknownError)
}

pub fn auth_getkey(_addr: &str, _key: &str) -> Result<(), AuthError> {
    Err(AuthError::KeyNotFound)
}

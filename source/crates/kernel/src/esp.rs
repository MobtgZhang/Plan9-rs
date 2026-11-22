use aes::{
    Aes128,
    cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit},
};
use alloc::{vec, vec::Vec};
use smoltcp::wire::{IpAddress, IpProtocol};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::dev::Error;

pub const PROTOCOL: IpProtocol = IpProtocol::IpSecEsp;
const TAG: usize = 12;
const HEADER: usize = 8;
const BLOCK: usize = 16;
const USER_HEADER: usize = 4;

struct Authentication {
    cipher: Aes128,
    complete: Zeroizing<[u8; BLOCK]>,
    partial: Zeroizing<[u8; BLOCK]>,
}

impl Authentication {
    fn new(key: &[u8; BLOCK]) -> Self {
        let master = Aes128::new(key.into());
        let working = Zeroizing::new(encrypt(&master, [1; BLOCK]));
        Self {
            cipher: Aes128::new((&*working).into()),
            complete: Zeroizing::new(encrypt(&master, [2; BLOCK])),
            partial: Zeroizing::new(encrypt(&master, [3; BLOCK])),
        }
    }

    fn tag(&self, input: &[u8]) -> [u8; TAG] {
        let mut blocks = input.chunks(BLOCK).peekable();
        let mut state = [0; BLOCK];
        while let Some(block) = blocks.next() {
            if blocks.peek().is_none() {
                let key = if block.len() == BLOCK {
                    &self.complete
                } else {
                    state[block.len()] ^= 0x80;
                    &self.partial
                };
                xor(&mut state, key.as_ref());
            }
            xor(&mut state, block);
            state = encrypt(&self.cipher, state);
        }
        let mut tag = [0; TAG];
        tag.copy_from_slice(&state[..TAG]);
        tag
    }
}

pub struct Association {
    pub local: IpAddress,
    pub peer: IpAddress,
    pub spi: u32,
    pub incoming: bool,
    user_header: bool,
    highest: u32,
    window: u64,
    cipher: Option<Aes128>,
    iv_cipher: Option<Aes128>,
    auth: Option<Authentication>,
    sealed: bool,
}

impl Association {
    pub fn new(local: IpAddress, peer: IpAddress, spi: u32, incoming: bool) -> Self {
        Self {
            local,
            peer,
            spi,
            incoming,
            user_header: false,
            highest: 0,
            window: 0,
            cipher: None,
            iv_cipher: None,
            auth: None,
            sealed: false,
        }
    }

    pub fn control(&mut self, command: &str) -> Result<(), Error> {
        let mut fields = command.split_whitespace();
        match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some("esp"), Some("aes_128_cbc"), Some(secret), None) if !self.sealed => {
                self.cipher = Some(Aes128::new((&*key(secret)?).into()));
            }
            (Some("ah"), Some("aes_xcbc_mac_96"), Some(secret), None) if !self.sealed => {
                self.auth = Some(Authentication::new(&*key(secret)?));
            }
            (Some("ivseed"), Some(secret), None, None) if !self.incoming && !self.sealed => {
                self.iv_cipher = Some(Aes128::new((&*key(secret)?).into()));
            }
            (Some("header"), None, None, None) => self.user_header = true,
            (Some("noheader"), None, None, None) => self.user_header = false,
            _ => return Err(Error::Einval),
        }
        Ok(())
    }

    pub fn ready(&self) -> bool {
        self.cipher.is_some() && self.auth.is_some() && (self.incoming || self.iv_cipher.is_some())
    }

    pub fn encode(&self, input: &[u8], ip_length: usize) -> Result<Vec<u8>, Error> {
        let (Some(cipher), Some(authentication), Some(iv_cipher)) =
            (&self.cipher, &self.auth, &self.iv_cipher)
        else {
            return Err(Error::Eperm);
        };
        let (next, input) = if self.user_header {
            (
                input.get(..USER_HEADER).ok_or(Error::Einval)?[0],
                &input[USER_HEADER..],
            )
        } else {
            (0, input)
        };
        if input.is_empty() || input.len() > 1500 {
            return Err(Error::Einval);
        }
        let padding = (BLOCK - ((input.len() + 2) % BLOCK)) % BLOCK;
        let length = HEADER + BLOCK + input.len() + padding + 2;
        if ip_length + length + TAG > 1500 {
            return Err(Error::Einval);
        }

        let sequence = self.highest.checked_add(1).ok_or(Error::Eclosed)?;
        let mut packet = vec![0; length];
        packet[..4].copy_from_slice(&self.spi.to_be_bytes());
        packet[4..8].copy_from_slice(&sequence.to_be_bytes());
        let mut iv_input = [0; BLOCK];
        iv_input[..HEADER].copy_from_slice(&packet[..HEADER]);
        let mut chain = encrypt(iv_cipher, iv_input);
        packet[HEADER..HEADER + BLOCK].copy_from_slice(&chain);
        let start = HEADER + BLOCK;
        packet[start..start + input.len()].copy_from_slice(input);
        for (index, byte) in packet[start + input.len()..length - 2]
            .iter_mut()
            .enumerate()
        {
            *byte = (index + 1) as u8;
        }
        packet[length - 2] = padding as u8;
        packet[length - 1] = next;
        for block in packet[start..].chunks_exact_mut(BLOCK) {
            xor(&mut chain, block);
            chain = encrypt(cipher, chain);
            block.copy_from_slice(&chain);
        }
        packet.extend(authentication.tag(&packet));
        Ok(packet)
    }

    pub fn sent(&mut self) {
        self.highest += 1;
        self.sealed = true;
    }

    pub fn decode(&mut self, packet: &[u8], output: &mut [u8]) -> Option<usize> {
        if !self.incoming
            || packet.len() < HEADER + 2 * BLOCK + TAG
            || packet[..4] != self.spi.to_be_bytes()
        {
            return None;
        }
        let cipher = self.cipher.as_ref()?;
        let authentication = self.auth.as_ref()?;
        let sequence = u32::from_be_bytes(packet[4..8].try_into().ok()?);
        let distance = self.highest.saturating_sub(sequence);
        if sequence == 0
            || distance >= 64
            || (sequence <= self.highest && self.window & (1 << distance) != 0)
        {
            return None;
        }
        let (authenticated, tag) = packet.split_at(packet.len() - TAG);
        let encrypted = &authenticated[HEADER + BLOCK..];
        if !encrypted.len().is_multiple_of(BLOCK)
            || !bool::from(authentication.tag(authenticated).as_slice().ct_eq(tag))
        {
            return None;
        }

        let mut content = Zeroizing::new(encrypted.to_vec());
        let mut chain = <[u8; BLOCK]>::try_from(&authenticated[HEADER..HEADER + BLOCK]).ok()?;
        for block in content.chunks_exact_mut(BLOCK) {
            let ciphertext = <[u8; BLOCK]>::try_from(&*block).ok()?;
            let mut bytes = Block::<Aes128>::from(ciphertext);
            cipher.decrypt_block(&mut bytes);
            block.copy_from_slice(&bytes);
            xor(block, &chain);
            chain = ciphertext;
        }
        let (padding, next) = (
            usize::from(content[content.len() - 2]),
            content[content.len() - 1],
        );
        let length = content.len().checked_sub(padding + 2)?;
        if length == 0 || padding >= BLOCK || (self.user_header && output.len() < USER_HEADER) {
            return None;
        }
        if sequence > self.highest {
            self.window = self
                .window
                .checked_shl(sequence - self.highest)
                .unwrap_or(0)
                | 1;
            self.highest = sequence;
        } else {
            self.window |= 1 << distance;
        }
        self.sealed = true;
        let offset = if self.user_header {
            output
                .get_mut(..USER_HEADER)?
                .copy_from_slice(&[next, 0, 0, 0]);
            USER_HEADER
        } else {
            0
        };
        let count = (output.len() - offset).min(length);
        output[offset..offset + count].copy_from_slice(&content[..count]);
        Some(count + offset)
    }
}

fn key(secret: &str) -> Result<Zeroizing<[u8; BLOCK]>, Error> {
    if secret.len() != BLOCK * 2 || !secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Einval);
    }
    let mut key = Zeroizing::new([0; BLOCK]);
    for (index, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&secret[index * 2..index * 2 + 2], 16).map_err(|_| Error::Einval)?;
    }
    Ok(key)
}

fn encrypt(cipher: &Aes128, input: [u8; BLOCK]) -> [u8; BLOCK] {
    let mut block = Block::<Aes128>::from(input);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn xor(left: &mut [u8], right: &[u8]) {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= right;
    }
}

use alloc::{collections::{BTreeMap, VecDeque}, vec::Vec};

use crate::dev::Error;
use crate::netstack::{self, Protocol};

use super::{NOTAG, RERROR, RFLUSH, TCLUNK, TFLUSH, reply_result};

struct Frame {
    bytes: Vec<u8>,
    written: usize,
}

struct Request {
    kind: u8,
    result: Option<Result<Vec<u8>, Error>>,
    flush: Option<u16>,
    abandoned: bool,
    cleanup_fid: Option<u32>,
    deadline: u64,
}

#[derive(Default)]
pub(super) struct Mux {
    next_tag: u16,
    broken: bool,
    requests: BTreeMap<u16, Request>,
    flushes: BTreeMap<u16, u16>,
    outgoing: VecDeque<Frame>,
    incoming: Vec<u8>,
    received: usize,
}

impl Mux {
    fn tag(&mut self) -> Result<u16, Error> {
        for _ in 0..NOTAG {
            let tag = self.next_tag;
            self.next_tag = if tag == NOTAG - 1 { 0 } else { tag + 1 };
            if !self.requests.contains_key(&tag) && !self.flushes.contains_key(&tag) {
                return Ok(tag);
            }
        }
        Err(Error::Enomem)
    }

    fn send(&mut self, kind: u8, tag: u16, body: &[u8]) {
        let size = (7 + body.len()) as u32;
        let mut bytes = Vec::with_capacity(size as usize);
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(body);
        self.outgoing.push_back(Frame { bytes, written: 0 });
    }

    pub(super) fn submit(&mut self, kind: u8, body: &[u8], msize: u32) -> Result<u16, Error> {
        self.submit_request(kind, body, msize, false)
    }

    fn submit_request(&mut self, kind: u8, body: &[u8], msize: u32, abandoned: bool) -> Result<u16, Error> {
        if self.broken {
            return Err(Error::Eio);
        }
        if body.len() > msize as usize - 7 {
            return Err(Error::Einval);
        }
        let tag = self.tag()?;
        self.requests.insert(tag, Request { kind, result: None, flush: None, abandoned, cleanup_fid: None,
            deadline: netstack::now().saturating_add(netstack::IO_TIMEOUT) });
        self.send(kind, tag, body);
        Ok(tag)
    }

    pub(super) fn submit_background(&mut self, kind: u8, body: &[u8], msize: u32) -> bool {
        self.submit_request(kind, body, msize, true).is_ok()
    }

    pub(super) fn has_background(&self) -> bool {
        self.requests.values().any(|request| request.abandoned)
    }

    pub(super) fn interrupt(&mut self, tag: u16) {
        if !self.requests.get(&tag).is_some_and(|request| request.result.is_none() && request.flush.is_none()) {
            return;
        }
        let Ok(flush) = self.tag() else {
            self.fail();
            return;
        };
        if let Some(request) = self.requests.get_mut(&tag) {
            request.flush = Some(flush);
            request.deadline = netstack::now().saturating_add(netstack::IO_TIMEOUT);
        }
        self.flushes.insert(flush, tag);
        self.send(TFLUSH, flush, &tag.to_le_bytes());
    }

    pub(super) fn abandon(&mut self, tag: u16) {
        self.interrupt(tag);
        self.detach(tag);
    }

    pub(super) fn abandon_and_clunk(&mut self, tag: u16, fid: u32, msize: u32) {
        self.interrupt(tag);
        if let Some(request) = self.requests.get_mut(&tag).filter(|request| request.flush.is_some()) {
            request.abandoned = true;
            request.cleanup_fid = Some(fid);
        } else {
            self.requests.remove(&tag);
            self.clunk(fid, msize);
        }
    }

    fn clunk(&mut self, fid: u32, msize: u32) {
        if !self.submit_background(TCLUNK, &fid.to_le_bytes(), msize) {
            self.fail();
        }
    }

    pub(super) fn detach(&mut self, tag: u16) {
        if let Some(request) = self.requests.get_mut(&tag) {
            if request.result.is_some() && request.flush.is_none() {
                self.requests.remove(&tag);
            } else {
                request.abandoned = true;
            }
        }
    }

    pub(super) fn take(&mut self, tag: u16) -> Option<Result<Vec<u8>, Error>> {
        let request = self.requests.get_mut(&tag)?;
        if request.flush.is_some() {
            return None;
        }
        let result = request.result.take()?;
        self.requests.remove(&tag);
        Some(result)
    }

    fn fail(&mut self) {
        self.broken = true;
        self.outgoing.clear();
        self.incoming.clear();
        self.flushes.clear();
        self.requests.retain(|_, request| {
            if request.result.is_none() {
                request.result = Some(Err(Error::Eio));
            }
            request.flush = None;
            !request.abandoned
        });
    }

    fn receive(&mut self, msize: u32) -> Result<(), Error> {
        let kind = self.incoming[4];
        let tag = u16::from_le_bytes([self.incoming[5], self.incoming[6]]);
        let body = &self.incoming[7..];
        if let Some(target) = self.flushes.remove(&tag) {
            if kind != RFLUSH || !body.is_empty() {
                return Err(Error::Eio);
            }
            let request = self.requests.get_mut(&target).ok_or(Error::Eio)?;
            if request.abandoned {
                let fid = request.cleanup_fid;
                self.requests.remove(&target);
                if let Some(fid) = fid {
                    self.clunk(fid, msize);
                }
            } else {
                request.flush = None;
                if request.result.is_none() {
                    request.result = Some(Err(Error::Eintr));
                }
            }
        } else {
            let request = self.requests.get_mut(&tag).ok_or(Error::Eio)?;
            if request.result.is_some() || (kind != request.kind + 1 && kind != RERROR) {
                return Err(Error::Eio);
            }
            if request.abandoned && request.flush.is_none() {
                self.requests.remove(&tag);
            } else {
                request.result = Some(reply_result(request.kind, kind, body.to_vec()));
            }
        }
        self.incoming.clear();
        self.received = 0;
        Ok(())
    }

    pub(super) fn poll(&mut self, tcp: u32, msize: u32) {
        if self.broken {
            return;
        }
        let now = netstack::now();
        if self.progress(tcp, msize).is_err() || self.requests.values().any(|request|
            now >= request.deadline && (request.flush.is_some() || request.result.is_none()))
        {
            self.fail();
        }
    }

    fn progress(&mut self, tcp: u32, msize: u32) -> Result<(), Error> {
        for _ in 0..8 {
            let Some(frame) = self.outgoing.front_mut() else { break };
            let pending = &frame.bytes[frame.written..];
            let Some(count) = netstack::with_network(|network| network.write(Protocol::Tcp, tcp, pending))? else { break };
            if count == 0 || count > pending.len() {
                return Err(Error::Eio);
            }
            frame.written += count;
            if frame.written == frame.bytes.len() {
                self.outgoing.pop_front();
            }
        }
        for _ in 0..8 {
            if self.incoming.is_empty() {
                self.incoming.resize(7, 0);
            }
            let pending = &mut self.incoming[self.received..];
            let Some(count) = netstack::with_network(|network| network.read(Protocol::Tcp, tcp, pending))? else { break };
            if count == 0 || count > pending.len() {
                return Err(Error::Eio);
            }
            self.received += count;
            if self.received == self.incoming.len() {
                let size = u32::from_le_bytes(self.incoming[..4].try_into().map_err(|_| Error::Eio)?);
                if !(7..=msize).contains(&size) {
                    return Err(Error::Eio);
                }
                if size as usize == self.received {
                    self.receive(msize)?;
                } else {
                    self.incoming.resize(size as usize, 0);
                }
            }
        }
        Ok(())
    }
}

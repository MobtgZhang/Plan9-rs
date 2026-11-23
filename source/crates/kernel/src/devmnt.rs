use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::dev::{self, Chan, Dev, DirEntry, Error, Qid, qidtype};
use crate::plan9_common::sync::Spinlock;

mod mux;

const TVERSION: u8 = 100;
const TAUTH: u8 = 102;
const TATTACH: u8 = 104;
const RERROR: u8 = 107;
const TFLUSH: u8 = 108;
const RFLUSH: u8 = 109;
const TWALK: u8 = 110;
const TOPEN: u8 = 112;
const TCREATE: u8 = 114;
const TREAD: u8 = 116;
const TWRITE: u8 = 118;
const TCLUNK: u8 = 120;
const TREMOVE: u8 = 122;
const TSTAT: u8 = 124;
const TWSTAT: u8 = 126;
const NOTAG: u16 = u16::MAX;
const NOFID: u32 = u32::MAX;
const IOHDRSZ: u32 = 24;
const MSIZE: u32 = 8192 + IOHDRSZ;

type Transport = dyn crate::proc::Chan;

static BACKGROUND: Spinlock<Vec<Arc<Session>>> = Spinlock::new(Vec::new());

pub(crate) fn poll_background() {
    BACKGROUND.lock().retain(|session| {
        let mut mux = session.state.mux.lock();
        mux.poll(session.tcp.expect("background 9P requires TCP"), session.msize);
        mux.has_background()
    });
}

#[doc(hidden)]
pub struct MountState {
    connection: Spinlock<Connection>,
    mux: Spinlock<mux::Mux>,
    next_fid: AtomicU32,
}

impl MountState {
    pub(crate) fn new() -> Self {
        Self {
            connection: Spinlock::new(Connection { tag: 0, broken: false, msize: None }),
            mux: Spinlock::new(mux::Mux::default()),
            next_fid: AtomicU32::new(0),
        }
    }
}

struct Session {
    file: Spinlock<Box<Transport>>,
    state: Arc<MountState>,
    msize: u32,
    open_id: usize,
    tcp: Option<u32>,
}

struct Connection {
    tag: u16,
    broken: bool,
    msize: Option<u32>,
}

impl Connection {
    fn negotiate(&mut self, file: &mut Transport) -> Result<u32, Error> {
        if self.broken {
            return Err(Error::Eio);
        }
        if let Some(msize) = self.msize {
            return Ok(msize);
        }
        let mut request = MSIZE.to_le_bytes().to_vec();
        string(&mut request, b"9P2000")?;
        let result = self.exchange(file, TVERSION, &request, MSIZE).and_then(|reply| {
            let mut reply = Decoder::new(&reply);
            let msize = reply.u32()?;
            if !(256..=MSIZE).contains(&msize) || reply.string()? != b"9P2000" || !reply.done() {
                return Err(Error::Enotsup);
            }
            Ok(msize)
        });
        match result {
            Ok(msize) => self.msize = Some(msize),
            Err(_) => self.broken = true,
        }
        result
    }

    fn next_tag(&mut self) -> u16 {
        let tag = self.tag;
        self.tag = if tag == NOTAG - 1 { 0 } else { tag + 1 };
        tag
    }

    fn exchange(&mut self, file: &mut Transport, kind: u8, body: &[u8], msize: u32) -> Result<Vec<u8>, Error> {
        if self.broken {
            return Err(Error::Eio);
        }
        let size = u32::try_from(7 + body.len()).map_err(|_| Error::Einval)?;
        if size > msize {
            return Err(Error::Einval);
        }
        let interruptible = matches!(kind, TREAD | TWRITE);
        if interruptible && crate::syscall::user_io_interrupted() {
            return Err(Error::Eintr);
        }
        let tag = if kind == TVERSION { NOTAG } else { self.next_tag() };
        let mut request = Vec::with_capacity(size as usize);
        request.extend_from_slice(&size.to_le_bytes());
        request.push(kind);
        request.extend_from_slice(&tag.to_le_bytes());
        request.extend_from_slice(body);
        let response = self.transmit(file, &request, tag, msize, interruptible);
        let (reply_type, reply) = match response {
            Ok(response) => response,
            Err(Error::Eintr) => return Err(Error::Eintr),
            Err(error) => {
                self.broken = true;
                return Err(error);
            }
        };
        if reply_type != kind + 1 && reply_type != RERROR {
            self.broken = true;
        }
        reply_result(kind, reply_type, reply)
    }

    fn write_all(file: &mut Transport, mut request: &[u8]) -> Result<(), Error> {
        while !request.is_empty() {
            let count = file.write(request).map_err(|_| Error::Eio)?;
            if count == 0 || count > request.len() {
                return Err(Error::Eio);
            }
            request = &request[count..];
        }
        Ok(())
    }

    fn transmit(&mut self, file: &mut Transport, request: &[u8], tag: u16, msize: u32, interruptible: bool) -> Result<(u8, Vec<u8>), Error> {
        Self::write_all(file, request)?;
        let mut flush = None;
        let mut completed = None;
        loop {
            let mut header = [0; 7];
            self.read_exact(file, &mut header, tag, interruptible, &mut flush)?;
            let mut header = Decoder::new(&header);
            let size = header.u32()?;
            let kind = header.u8()?;
            let reply_tag = header.u16()?;
            if size < 7 || size > msize {
                return Err(Error::Eio);
            }
            let mut reply = vec![0; size as usize - 7];
            self.read_exact(file, &mut reply, tag, interruptible, &mut flush)?;
            if let Some(flush_tag) = flush {
                if reply_tag == flush_tag && kind == RFLUSH && reply.is_empty() {
                    return completed.ok_or(Error::Eintr);
                }
                if reply_tag != tag || completed.is_some() {
                    return Err(Error::Eio);
                }
                completed = Some((kind, reply));
            } else if reply_tag == tag {
                return Ok((kind, reply));
            } else {
                return Err(Error::Eio);
            }
        }
    }

    fn read_exact(&mut self, file: &mut Transport, mut output: &mut [u8], tag: u16, interruptible: bool, flush: &mut Option<u16>) -> Result<(), Error> {
        while !output.is_empty() {
            let count = if interruptible && flush.is_none() {
                match file.read_interruptible(output) {
                    Ok(count) => count,
                    Err(crate::proc::Error::Eintr) => {
                        let flush_tag = self.next_tag();
                        let [flush_low, flush_high] = flush_tag.to_le_bytes();
                        let [tag_low, tag_high] = tag.to_le_bytes();
                        Self::write_all(file, &[9, 0, 0, 0, TFLUSH, flush_low, flush_high, tag_low, tag_high])?;
                        *flush = Some(flush_tag);
                        continue;
                    }
                    Err(_) => return Err(Error::Eio),
                }
            } else {
                file.read(output).map_err(|_| Error::Eio)?
            };
            if count == 0 || count > output.len() {
                return Err(Error::Eio);
            }
            output = &mut output[count..];
        }
        Ok(())
    }
}

fn reply_result(kind: u8, reply_type: u8, reply: Vec<u8>) -> Result<Vec<u8>, Error> {
    if reply_type == kind + 1 {
        return Ok(reply);
    }
    if reply_type != RERROR {
        return Err(Error::Eio);
    }
    let mut reply = Decoder::new(&reply);
    let message = reply.string()?;
    if !reply.done() {
        return Err(Error::Eio);
    }
    Err(match message {
        b"file does not exist" | b"does not exist" | b"not found" | b"No such file or directory" => Error::Enoent,
        b"permission denied" | b"Permission denied" => Error::Eperm,
        b"file already exists" | b"File exists" => Error::Eexists,
        _ => Error::Eio,
    })
}

impl Session {
    fn schedule_background(self: &Arc<Self>) {
        let mut sessions = BACKGROUND.lock();
        if !sessions.iter().any(|session| Arc::ptr_eq(&session.state, &self.state)) {
            sessions.push(self.clone());
        }
    }

    fn fid(&self) -> Result<u32, Error> {
        self.state.next_fid.try_update(Ordering::Relaxed, Ordering::Relaxed, |fid| fid.checked_add(1))
            .map_err(|_| Error::Enomem)
    }

    fn call(&self, kind: u8, request: &[u8]) -> Result<Vec<u8>, Error> {
        let Some(tcp) = self.tcp else {
            return self.state.connection.lock().exchange(self.file.lock().as_mut(), kind, request, self.msize);
        };
        let interruptible = matches!(kind, TREAD | TWRITE);
        if interruptible && crate::syscall::user_io_interrupted() {
            return Err(Error::Eintr);
        }
        let tag = self.state.mux.lock().submit(kind, request, self.msize)?;
        loop {
            let interrupted = interruptible && crate::syscall::user_io_interrupted();
            if let Some(result) = self.poll_rpc(tcp, tag, interrupted) {
                return result;
            }
            core::hint::spin_loop();
        }
    }

    fn poll_rpc(&self, tcp: u32, tag: u16, interrupted: bool) -> Option<Result<Vec<u8>, Error>> {
        let mut mux = self.state.mux.lock();
        if interrupted {
            mux.interrupt(tag);
        }
        mux.poll(tcp, self.msize);
        mux.take(tag)
    }
}

struct Fid {
    session: Arc<Session>,
    number: u32,
    valid: AtomicBool,
    io_active: AtomicBool,
    iounit: u32,
    directory: Spinlock<Directory>,
}

#[derive(Default)]
struct Directory {
    wire_offset: u64,
    offset: u64,
    pending: Vec<u8>,
    eof: bool,
}

impl Directory {
    fn seek(&mut self, offset: u64) -> Result<(), Error> {
        if offset == 0 && self.offset != 0 {
            *self = Self::default();
        }
        if offset != self.offset {
            return Err(Error::Einval);
        }
        Ok(())
    }

    fn readable(&self, capacity: usize, names: bool) -> Result<usize, Error> {
        if names || self.pending.is_empty() {
            return Ok(capacity.min(self.pending.len()));
        }
        let mut end = 0;
        while end < self.pending.len() {
            let size = u16::from_le_bytes(self.pending[end..end + 2].try_into().unwrap()) as usize + 2;
            if size > capacity - end {
                break;
            }
            end += size;
        }
        if end == 0 { Err(Error::Einval) } else { Ok(end) }
    }

    fn consume(&mut self, count: usize) {
        self.pending.drain(..count);
        self.offset += count as u64;
    }

    fn accept(&mut self, bytes: &[u8], device: usize, names: bool) -> Result<(), Error> {
        let mut records = Decoder::new(bytes);
        let mut pending = Vec::new();
        while !records.done() {
            let length = records.u16()?;
            let body = records.take(length as usize)?;
            let name = stat_fields(body)?[0];
            if names {
                if !name.contains(&b'\n') {
                    pending.extend_from_slice(name);
                    pending.push(b'\n');
                }
            } else {
                pending.extend_from_slice(&length.to_le_bytes());
                pending.extend_from_slice(&(b'M' as u16).to_le_bytes());
                pending.extend_from_slice(&(device as u32).to_le_bytes());
                pending.extend_from_slice(&body[6..]);
            }
        }
        self.wire_offset = self.wire_offset.checked_add(bytes.len() as u64).ok_or(Error::Eio)?;
        self.pending = pending;
        self.eof = bytes.is_empty();
        Ok(())
    }
}

impl Fid {
    fn new(session: Arc<Session>, number: u32) -> Self {
        Self { session, number, valid: AtomicBool::new(true), io_active: AtomicBool::new(false), iounit: 0,
            directory: Spinlock::new(Directory::default()) }
    }

    fn call(&self, kind: u8, args: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.valid.load(Ordering::Acquire) {
            return Err(Error::Ebadfd);
        }
        let mut request = self.number.to_le_bytes().to_vec();
        request.extend_from_slice(args);
        self.session.call(kind, &request)
    }

    fn walk(&self, name: Option<&str>) -> Result<(Self, Option<Qid>), Error> {
        let number = self.session.fid()?;
        let mut args = number.to_le_bytes().to_vec();
        args.extend_from_slice(&u16::from(name.is_some()).to_le_bytes());
        if let Some(name) = name {
            string(&mut args, name.as_bytes())?;
        }
        let reply = self.call(TWALK, &args)?;
        let mut reply = Decoder::new(&reply);
        let count = reply.u16()?;
        if name.is_some() && count == 0 {
            return Err(Error::Enoent);
        }
        let fid = Self::new(self.session.clone(), number);
        if count != u16::from(name.is_some()) {
            return Err(Error::Eio);
        }
        let qid = if count == 1 { Some(reply.qid()?) } else { None };
        if !reply.done() {
            return Err(Error::Eio);
        }
        Ok((fid, qid))
    }

    fn max_io(&self) -> usize {
        let limit = self.session.msize - IOHDRSZ;
        if self.iounit == 0 { limit as usize } else { self.iounit.min(limit) as usize }
    }

    fn read_at(&self, offset: u64, count: usize) -> Result<Vec<u8>, Error> {
        let count = count.min(self.max_io()) as u32;
        let mut args = offset.to_le_bytes().to_vec();
        args.extend_from_slice(&count.to_le_bytes());
        let reply = self.call(TREAD, &args)?;
        Ok(read_payload(&reply, count as usize)?.to_vec())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, Error> {
        let mut args = offset.to_le_bytes().to_vec();
        args.extend_from_slice(&(data.len() as u32).to_le_bytes());
        args.extend_from_slice(data);
        write_count(&self.call(TWRITE, &args)?, data.len())
    }

    fn transfer(&self, offset: u64, len: usize, mut chunk: impl FnMut(u64, core::ops::Range<usize>) -> Result<usize, Error>) -> Result<usize, Error> {
        let mut done = 0;
        while done < len {
            let count = (len - done).min(self.max_io());
            let result = offset.checked_add(done as u64).ok_or(Error::Einval)
                .and_then(|position| chunk(position, done..done + count));
            let transferred = match result {
                Ok(transferred) => transferred,
                Err(_) if done != 0 => return Ok(done),
                Err(error) => return Err(error),
            };
            done += transferred;
            if transferred < count || crate::proc::curproc().is_some_and(|proc| proc.has_pending_signals()) {
                break;
            }
        }
        Ok(done)
    }

    fn read_dir(&self, output: &mut [u8], offset: u64, device: usize, names: bool) -> Result<usize, Error> {
        let mut dir = self.directory.lock();
        dir.seek(offset)?;
        let mut written = 0;
        while written < output.len() {
            if dir.pending.is_empty() && !dir.eof {
                let offset = dir.wire_offset;
                if let Err(error) = self.read_at(offset, self.max_io())
                    .and_then(|data| dir.accept(&data, device, names)) {
                    return if written == 0 { Err(error) } else { Ok(written) };
                }
            }
            if dir.pending.is_empty() {
                if dir.eof {
                    break;
                }
                continue;
            }
            let count = match dir.readable(output.len() - written, names) {
                Ok(count) => count,
                Err(error) => return if written == 0 { Err(error) } else { Ok(written) },
            };
            output[written..written + count].copy_from_slice(&dir.pending[..count]);
            dir.consume(count);
            written += count;
        }
        Ok(written)
    }

}

impl Drop for Fid {
    fn drop(&mut self) {
        if !self.valid.load(Ordering::Relaxed) {
            return;
        }
        if let Some(tcp) = self.session.tcp {
            let queued = {
                let mut mux = self.session.state.mux.lock();
                let queued = mux.submit_background(TCLUNK, &self.number.to_le_bytes(), self.session.msize);
                mux.poll(tcp, self.session.msize);
                queued && mux.has_background()
            };
            if queued {
                self.session.schedule_background();
            }
        } else {
            let _ = self.call(TCLUNK, &[]);
        }
    }
}

fn string(output: &mut Vec<u8>, text: &[u8]) -> Result<(), Error> {
    if text.contains(&0) || core::str::from_utf8(text).is_err() {
        return Err(Error::Einval);
    }
    counted_bytes(output, text)
}

fn counted_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let length = u16::try_from(bytes.len()).map_err(|_| Error::Einval)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Decoder<'a>(&'a [u8]);

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self { Self(input) }
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.0.split_at_checked(count).ok_or(Error::Eio)?;
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn string(&mut self) -> Result<&'a [u8], Error> {
        let length = self.u16()?;
        self.take(length as usize)
    }
    fn qid(&mut self) -> Result<Qid, Error> {
        let kind = self.u8()?;
        let version = self.u32()?;
        Ok(Qid::new(self.u64()?, version, kind))
    }
    fn done(&self) -> bool { self.0.is_empty() }
}

fn decode_stat(input: &mut Decoder<'_>, dev: usize) -> Result<DirEntry, Error> {
    input.take(6)?;
    let qid = input.qid()?;
    let mode = input.u32()?;
    let atime = input.u32()?;
    let mtime = input.u32()?;
    let length = input.u64()?;
    let name = input.string()?.to_vec();
    let uid = core::str::from_utf8(input.string()?).map_err(|_| Error::Eio)?;
    let gid = core::str::from_utf8(input.string()?).map_err(|_| Error::Eio)?;
    input.string()?;
    if !input.done() || name.contains(&0) || name.contains(&b'\n') {
        return Err(Error::Eio);
    }
    Ok(DirEntry { dev, qid, mode, atime, mtime, length, name,
        uid: uid.parse().unwrap_or(u32::MAX), gid: gid.parse().unwrap_or(u32::MAX) })
}

fn fid(chan: &Chan) -> Result<&Fid, Error> {
    chan.aux.as_deref().and_then(|aux| aux.downcast_ref::<Fid>()).ok_or(Error::Ebadfd)
}

fn read_payload(reply: &[u8], requested: usize) -> Result<&[u8], Error> {
    let mut reply = Decoder::new(reply);
    let count = reply.u32()? as usize;
    let data = reply.take(count)?;
    if count > requested || !reply.done() {
        return Err(Error::Eio);
    }
    Ok(data)
}

fn write_count(reply: &[u8], requested: usize) -> Result<usize, Error> {
    let mut reply = Decoder::new(reply);
    let count = reply.u32()? as usize;
    if count > requested || !reply.done() {
        return Err(Error::Eio);
    }
    Ok(count)
}

pub(crate) enum PendingIo {
    Data(PendingData),
    Metadata(PendingMetadata),
    Close(PendingClose),
    Open(PendingOpen),
}

impl PendingIo {
    pub(crate) fn start(channel: Box<Transport>, address: u64, size: usize, write: bool) -> core::result::Result<Self, Box<Transport>> {
        PendingData::start(channel, address, size, write).map(Self::Data)
    }

    pub(crate) fn list(chan: &Chan, address: u64, size: usize) -> Option<Self> {
        let (fid, tcp) = tcp_fid(chan)?;
        let channel = Box::new(crate::vfs::DevChanAdapter::new(chan.clone()));
        Some(Self::Data(PendingData {
            channel, fid, rpc: PendingRpc::new(tcp), address, size, offset: None, done: 0,
            write: false, directory: Some(chan.dev), names: true, count: 0,
        }))
    }

    pub(crate) fn stat(chan: &Chan, address: u64, size: usize, use_path_name: bool) -> Option<Self> {
        let (fid, tcp) = tcp_fid(chan)?;
        let name = if use_path_name {
            chan.namespace_path.as_deref().and_then(crate::vfs::file_name).map(<[u8]>::to_vec)
        } else {
            None
        };
        Some(Self::Metadata(PendingMetadata {
            fid, rpc: PendingRpc::new(tcp), request: Some(Vec::new()),
            operation: Metadata::Stat { device: chan.dev, address, size, name },
        }))
    }

    pub(crate) fn wstat(chan: &Chan, stat: &[u8]) -> Result<Option<Self>, Error> {
        let Some((fid, tcp)) = tcp_fid(chan) else { return Ok(None) };
        decode_wstat(stat, chan.dev)?;
        let mut args = Vec::new();
        counted_bytes(&mut args, stat)?;
        Ok(Some(Self::Metadata(PendingMetadata {
            fid, rpc: PendingRpc::new(tcp), request: Some(args),
            operation: Metadata::Wstat { size: stat.len() },
        })))
    }

    pub(crate) fn poll(&mut self, proc: &crate::proc::Proc) -> Option<crate::syscall::Result<usize>> {
        match self {
            Self::Data(pending) => pending.poll(proc),
            Self::Metadata(pending) => pending.progress(proc).transpose(),
            Self::Close(pending) => pending.poll(proc),
            Self::Open(pending) => pending.progress(proc).transpose(),
        }
    }
}

fn tcp_fid(chan: &Chan) -> Option<(Arc<Fid>, u32)> {
    let fid = chan.aux.clone()?.downcast::<Fid>().ok()?;
    let tcp = fid.session.tcp?;
    Some((fid, tcp))
}

struct PendingRpc {
    tcp: u32,
    tag: Option<u16>,
}

impl PendingRpc {
    fn new(tcp: u32) -> Self {
        Self { tcp, tag: None }
    }

    fn submit(&mut self, session: &Session, kind: u8, body: &[u8]) -> Result<(), Error> {
        let mut mux = session.state.mux.lock();
        self.tag = Some(mux.submit(kind, body, session.msize)?);
        mux.poll(self.tcp, session.msize);
        Ok(())
    }

    fn poll(&mut self, session: &Session, interrupted: bool) -> Option<Result<Vec<u8>, Error>> {
        let reply = session.poll_rpc(self.tcp, self.tag?, interrupted)?;
        self.tag = None;
        Some(reply)
    }

    fn abandon(&mut self, session: &Arc<Session>) {
        if let Some(tag) = self.tag.take() {
            let mut mux = session.state.mux.lock();
            mux.abandon(tag);
            mux.poll(self.tcp, session.msize);
            if mux.has_background() {
                drop(mux);
                session.schedule_background();
            }
        }
    }
}

#[doc(hidden)]
pub struct PendingClose {
    session: Arc<Session>,
    rpc: PendingRpc,
}

impl PendingClose {
    pub(crate) fn start(chan: &mut Chan) -> Option<Self> {
        let fid = unique_fid(chan)?;
        let tcp = fid.session.tcp?;
        if !*fid.valid.get_mut() {
            return None;
        }
        let mut rpc = PendingRpc::new(tcp);
        rpc.submit(&fid.session, TCLUNK, &fid.number.to_le_bytes()).ok()?;
        *fid.valid.get_mut() = false;
        Some(Self { session: fid.session.clone(), rpc })
    }

    fn poll(&mut self, proc: &crate::proc::Proc) -> Option<crate::syscall::Result<usize>> {
        if self.rpc.poll(&self.session, false).is_some() || proc.has_pending_signals() {
            Some(Ok(0))
        } else {
            None
        }
    }
}

impl Drop for PendingClose {
    fn drop(&mut self) {
        if let Some(tag) = self.rpc.tag.take() {
            self.session.state.mux.lock().detach(tag);
            self.session.schedule_background();
        }
    }
}

pub(crate) struct PendingOpen {
    chan: Option<Chan>,
    rpc: PendingRpc,
    mode: u8,
    close_on_exec: bool,
}

fn unique_fid(chan: &mut Chan) -> Option<&mut Fid> {
    Arc::get_mut(chan.aux.as_mut()?)?.downcast_mut::<Fid>()
}

impl PendingOpen {
    pub(crate) fn start(mut chan: Chan, mode: u8, close_on_exec: bool) -> Result<Self, Chan> {
        let Some(tcp) = unique_fid(&mut chan).and_then(|fid| fid.session.tcp) else { return Err(chan) };
        Ok(Self { chan: Some(chan), rpc: PendingRpc::new(tcp), mode, close_on_exec })
    }

    fn progress(&mut self, proc: &crate::proc::Proc) -> crate::syscall::Result<Option<usize>> {
        let chan = self.chan.as_mut().ok_or(Error::Ebadfd)?;
        let fid = unique_fid(chan).ok_or(Error::Ebadfd)?;
        let interrupted = proc.has_pending_signals();
        if self.rpc.tag.is_none() {
            if interrupted {
                return Err(Error::Eintr.into());
            }
            if !*fid.valid.get_mut() {
                return Err(Error::Ebadfd.into());
            }
            let mut body = [0; 5];
            body[..4].copy_from_slice(&fid.number.to_le_bytes());
            body[4] = self.mode;
            self.rpc.submit(&fid.session, TOPEN, &body)?;
        }
        let Some(reply) = self.rpc.poll(&fid.session, interrupted) else { return Ok(None) };
        let (qid, iounit) = decode_open(&reply?)?;
        fid.iounit = iounit;
        chan.qid = qid;
        chan.mode = self.mode;
        let group = proc.fgrp.as_deref().ok_or(Error::Eperm)?;
        let chan = self.chan.take().ok_or(Error::Ebadfd)?;
        let fd = crate::vfs::alloc_device_channel_in(group, chan, self.close_on_exec)?;
        Ok(Some(fd as usize))
    }
}

impl Drop for PendingOpen {
    fn drop(&mut self) {
        if let Some((tag, fid)) = self.rpc.tag.take().zip(self.chan.as_mut().and_then(unique_fid)) {
            *fid.valid.get_mut() = false;
            let session = &fid.session;
            session.state.mux.lock().abandon_and_clunk(tag, fid.number, session.msize);
            session.schedule_background();
        }
    }
}

fn decode_open(reply: &[u8]) -> Result<(Qid, u32), Error> {
    let mut reply = Decoder::new(reply);
    let qid = reply.qid()?;
    let iounit = reply.u32()?;
    if !reply.done() {
        return Err(Error::Eio);
    }
    Ok((qid, iounit))
}

enum Metadata {
    Stat { device: usize, address: u64, size: usize, name: Option<Vec<u8>> },
    Wstat { size: usize },
}

pub(crate) struct PendingMetadata {
    fid: Arc<Fid>,
    rpc: PendingRpc,
    operation: Metadata,
    request: Option<Vec<u8>>,
}

impl PendingMetadata {
    fn progress(&mut self, proc: &crate::proc::Proc) -> crate::syscall::Result<Option<usize>> {
        let interrupted = proc.has_pending_signals();
        if let Some(args) = self.request.take() {
            if interrupted {
                return Err(crate::syscall::Error::Eintr);
            }
            if !self.fid.valid.load(Ordering::Acquire) {
                return Err(crate::syscall::Error::Ebadfd);
            }
            let kind = match self.operation {
                Metadata::Stat { .. } => TSTAT,
                Metadata::Wstat { .. } => TWSTAT,
            };
            let mut body = self.fid.number.to_le_bytes().to_vec();
            body.extend_from_slice(&args);
            self.rpc.submit(&self.fid.session, kind, &body)?;
        }
        let Some(reply) = self.rpc.poll(&self.fid.session, interrupted) else { return Ok(None) };
        let reply = reply?;
        match &self.operation {
            Metadata::Stat { device, address, size, name } => {
                let record = mount_stat_record(parse_remote_stat(&reply)?, *device)?;
                let record = rename_stat(record, name.as_deref())?;
                Ok(Some(crate::syscall::copy_stat_to_proc(proc, *address, *size, &record)?))
            }
            Metadata::Wstat { size } if reply.is_empty() => Ok(Some(*size)),
            Metadata::Wstat { .. } => Err(Error::Eio.into()),
        }
    }
}

impl Drop for PendingMetadata {
    fn drop(&mut self) {
        self.rpc.abandon(&self.fid.session);
    }
}

pub(crate) struct PendingData {
    channel: Box<Transport>,
    fid: Arc<Fid>,
    rpc: PendingRpc,
    address: u64,
    size: usize,
    offset: Option<u64>,
    done: usize,
    write: bool,
    directory: Option<usize>,
    names: bool,
    count: usize,
}

impl PendingData {
    fn start(channel: Box<Transport>, address: u64, size: usize, write: bool) -> core::result::Result<Self, Box<Transport>> {
        let prepared = channel.io_device_chan().and_then(|raw| {
            let directory = (raw.qid.type_ & qidtype::DIR != 0).then_some(raw.dev);
            if directory.is_some() && write {
                return None;
            }
            let (fid, tcp) = tcp_fid(&raw)?;
            Some((fid, tcp, directory))
        });
        let Some((fid, tcp, directory)) = prepared else { return Err(channel) };
        Ok(Self { channel, fid, rpc: PendingRpc::new(tcp), address, size, offset: None, done: 0, write,
            directory, names: false, count: 0 })
    }

    fn poll(&mut self, proc: &crate::proc::Proc) -> Option<crate::syscall::Result<usize>> {
        let result = self.progress(proc);
        match result {
            Ok(false) => None,
            Ok(true) => Some(Ok(self.done)),
            Err(_) if self.done != 0 => Some(Ok(self.done)),
            Err(error) => Some(Err(error)),
        }
    }

    fn progress(&mut self, proc: &crate::proc::Proc) -> crate::syscall::Result<bool> {
        if let Some(device) = self.directory {
            return self.progress_directory(proc, device);
        }
        let interrupted = proc.has_pending_signals();
        if self.rpc.tag.is_some() {
            let Some(reply) = self.rpc.poll(&self.fid.session, interrupted) else { return Ok(false) };
            let count = self.count;
            let reply = reply?;
            let transferred = if self.write {
                write_count(&reply, count)?
            } else {
                let data = read_payload(&reply, count)?;
                crate::syscall::put_user_bytes(proc, self.address + self.done as u64, data)?;
                data.len()
            };
            self.done += transferred;
            let offset = self.channel.offset().saturating_add(transferred as u64);
            self.channel.set_offset(offset);
            if transferred < count || self.done == self.size || interrupted {
                return Ok(true);
            }
        } else if interrupted {
            return Err(crate::syscall::Error::Eintr);
        }
        let Some(offset) = self.acquire()? else { return Ok(false) };
        let count = (self.size - self.done).min(self.fid.max_io());
        let offset = offset.checked_add(self.done as u64).ok_or(Error::Einval)?;
        let mut body = self.fid.number.to_le_bytes().to_vec();
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&(count as u32).to_le_bytes());
        let kind = if self.write {
            body.resize(16 + count, 0);
            crate::syscall::get_user_bytes(proc, self.address + self.done as u64, &mut body[16..])?;
            TWRITE
        } else {
            TREAD
        };
        self.submit(kind, &body, count)?;
        Ok(false)
    }

    fn progress_directory(&mut self, proc: &crate::proc::Proc, device: usize) -> crate::syscall::Result<bool> {
        let interrupted = proc.has_pending_signals();
        let reply = if self.rpc.tag.is_some() {
            let Some(reply) = self.rpc.poll(&self.fid.session, interrupted) else { return Ok(false) };
            Some(reply?)
        } else if interrupted {
            return Err(crate::syscall::Error::Eintr);
        } else {
            None
        };
        let Some(offset) = self.acquire()? else { return Ok(false) };
        let offset = offset.checked_add(self.done as u64).ok_or(Error::Einval)?;
        let mut dir = self.fid.directory.lock();
        dir.seek(offset)?;
        if let Some(reply) = reply {
            dir.accept(read_payload(&reply, self.count)?, device, self.names)?;
        }
        if !dir.pending.is_empty() || dir.eof {
            let count = dir.readable(self.size - self.done, self.names)?;
            crate::syscall::put_user_bytes(proc, self.address + self.done as u64, &dir.pending[..count])?;
            dir.consume(count);
            self.done += count;
            let (next, eof) = (dir.offset, dir.eof);
            drop(dir);
            self.channel.set_offset(next);
            return Ok(!self.names || eof || self.done == self.size || interrupted);
        }
        if interrupted {
            return Err(crate::syscall::Error::Eintr);
        }
        let position = dir.wire_offset;
        drop(dir);
        let count = self.fid.max_io();
        let mut body = self.fid.number.to_le_bytes().to_vec();
        body.extend_from_slice(&position.to_le_bytes());
        body.extend_from_slice(&(count as u32).to_le_bytes());
        self.submit(TREAD, &body, count)?;
        Ok(false)
    }

    fn acquire(&mut self) -> crate::syscall::Result<Option<u64>> {
        if !self.fid.valid.load(Ordering::Acquire) {
            return Err(crate::syscall::Error::Ebadfd);
        }
        if self.offset.is_none() && !self.fid.io_active.swap(true, Ordering::Acquire) {
            self.offset = Some(self.channel.offset());
        }
        Ok(self.offset)
    }

    fn submit(&mut self, kind: u8, body: &[u8], count: usize) -> Result<(), Error> {
        self.count = count;
        self.rpc.submit(&self.fid.session, kind, body)
    }
}

impl Drop for PendingData {
    fn drop(&mut self) {
        self.rpc.abandon(&self.fid.session);
        if self.offset.is_some() {
            self.fid.io_active.store(false, Ordering::Release);
        }
    }
}

fn remote_stat(chan: &Chan) -> Result<Vec<u8>, Error> {
    let reply = fid(chan)?.call(TSTAT, &[])?;
    parse_remote_stat(&reply)
}

fn parse_remote_stat(reply: &[u8]) -> Result<Vec<u8>, Error> {
    let mut reply = Decoder::new(reply);
    let bytes = reply.string()?;
    let size = bytes.get(..2).ok_or(Error::Eio)?;
    if !reply.done() || u16::from_le_bytes(size.try_into().unwrap()) as usize + 2 != bytes.len() {
        return Err(Error::Eio);
    }
    Ok(bytes.to_vec())
}

fn stat_fields(body: &[u8]) -> Result<[&[u8]; 4], Error> {
    let mut fields = Decoder::new(body.get(39..).ok_or(Error::Eio)?);
    let strings = [fields.string()?, fields.string()?, fields.string()?, fields.string()?];
    if !fields.done() {
        return Err(Error::Eio);
    }
    Ok(strings)
}

pub(crate) fn read_names(chan: &mut Chan, output: &mut [u8], offset: u64) -> Result<usize, Error> {
    if dev::devs().find_by_char('M') == Some(chan.dev) {
        return fid(chan)?.read_dir(output, offset, chan.dev, true);
    }
    dev::dev_read(chan, output, offset)
}

pub(crate) fn encode_stat(entry: &DirEntry, device_type: char) -> Result<Vec<u8>, Error> {
    let mut record = vec![0; 2];
    record.extend_from_slice(&(device_type as u16).to_le_bytes());
    record.extend_from_slice(&(entry.dev as u32).to_le_bytes());
    record.push(entry.qid.type_);
    record.extend_from_slice(&entry.qid.vers.to_le_bytes());
    record.extend_from_slice(&entry.qid.path.to_le_bytes());
    let directory = entry.qid.type_ & qidtype::DIR != 0;
    let mode = if directory { entry.mode & !0o170000 | 0x8000_0000 } else { entry.mode };
    record.extend_from_slice(&mode.to_le_bytes());
    record.extend_from_slice(&entry.atime.to_le_bytes());
    record.extend_from_slice(&entry.mtime.to_le_bytes());
    record.extend_from_slice(&entry.length.to_le_bytes());
    string(&mut record, &entry.name)?;
    let owner = crate::upasswd::user_by_uid(entry.uid)
        .map_or_else(|| alloc::format!("{}", entry.uid), |user| user.name);
    let group = crate::upasswd::group_by_gid(entry.gid)
        .map_or_else(|| alloc::format!("{}", entry.gid), |group| group.name);
    string(&mut record, owner.as_bytes())?;
    string(&mut record, group.as_bytes())?;
    string(&mut record, b"")?;
    set_stat_size(&mut record)?;
    Ok(record)
}

pub(crate) fn stat_record(chan: &mut Chan, use_path_name: bool) -> Result<Vec<u8>, Error> {
    let record = if dev::devs().find_by_char('M') == Some(chan.dev) {
        mount_stat_record(remote_stat(chan)?, chan.dev)?
    } else {
        let entry = dev::dev_stat(chan)?;
        let device_type = dev::devs().get(chan.dev).ok_or(Error::Enoent)?.dev_char();
        encode_stat(&entry, device_type)?
    };
    let name = chan.namespace_path.as_deref().and_then(crate::vfs::file_name).filter(|_| use_path_name);
    rename_stat(record, name)
}

fn rename_stat(record: Vec<u8>, name: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    if let Some(name) = name {
        let name_length = stat_fields(&record[2..])?[0].len();
        let mut replacement = record[..41].to_vec();
        string(&mut replacement, name)?;
        replacement.extend_from_slice(&record[43 + name_length..]);
        set_stat_size(&mut replacement)?;
        return Ok(replacement);
    }
    Ok(record)
}

fn mount_stat_record(mut record: Vec<u8>, device: usize) -> Result<Vec<u8>, Error> {
    stat_fields(&record[2..])?;
    record[2..4].copy_from_slice(&(b'M' as u16).to_le_bytes());
    record[4..8].copy_from_slice(&(device as u32).to_le_bytes());
    Ok(record)
}

fn set_stat_size(record: &mut [u8]) -> Result<(), Error> {
    let size = u16::try_from(record.len() - 2).map_err(|_| Error::Einval)?;
    record[..2].copy_from_slice(&size.to_le_bytes());
    Ok(())
}

fn decode_wstat(stat: &[u8], device: usize) -> Result<DirEntry, Error> {
    let mut decoder = Decoder::new(stat);
    let size = decoder.u16()? as usize;
    let mut fields = Decoder::new(decoder.take(size)?);
    if !decoder.done() {
        return Err(Error::Einval);
    }
    decode_stat(&mut fields, device)
}

pub(crate) fn wstat(chan: &mut Chan, stat: &[u8]) -> Result<(), Error> {
    let changes = decode_wstat(stat, chan.dev)?;
    if chan.dev != dev::devs().find_by_char('M').ok_or(Error::Enoent)? {
        let mut entry = dev::dev_stat(chan)?;
        if changes.mode != u32::MAX { entry.mode = changes.mode; }
        if changes.atime != u32::MAX { entry.atime = changes.atime; }
        if changes.mtime != u32::MAX { entry.mtime = changes.mtime; }
        if changes.length != u64::MAX { entry.length = changes.length; }
        if !changes.name.is_empty() { entry.name = changes.name; }
        let mut names = Decoder::new(&stat[41..]);
        names.string()?;
        let owner = core::str::from_utf8(names.string()?).map_err(|_| Error::Einval)?;
        let group = core::str::from_utf8(names.string()?).map_err(|_| Error::Einval)?;
        if !owner.is_empty() {
            entry.uid = owner.parse().ok().or_else(|| crate::upasswd::user_by_name(owner).map(|user| user.uid))
                .ok_or(Error::Einval)?;
        }
        if !group.is_empty() {
            entry.gid = group.parse().ok().or_else(|| crate::upasswd::group_by_name(group).map(|group| group.gid))
                .ok_or(Error::Einval)?;
        }
        return dev::dev_wstat(chan, &entry);
    }
    let mut args = Vec::new();
    counted_bytes(&mut args, stat)?;
    if !fid(chan)?.call(TWSTAT, &args)?.is_empty() {
        return Err(Error::Eio);
    }
    Ok(())
}

pub(crate) fn transport_id(chan: &Chan) -> Option<usize> {
    fid(chan).ok().map(|fid| fid.session.open_id)
}

fn session_for(mut file: Box<Transport>) -> Result<Arc<Session>, Error> {
    let index = dev::devs().find_by_char('M').ok_or(Error::Enoent)?;
    if file.access_mode() != 2 || file.dev() == index {
        return Err(Error::Eperm);
    }
    let open_id = file.open_id().ok_or(Error::Ebadfd)?;
    let state = file.mount_state().ok_or(Error::Ebadfd)?;
    let tcp = file.dev_chan().as_ref().and_then(crate::netfs::tcp_data_channel);
    let msize = state.connection.lock().negotiate(file.as_mut())?;
    Ok(Arc::new(Session { file: Spinlock::new(file), state, msize, open_id, tcp }))
}

const QTAUTH: u8 = 0x08;

pub(crate) fn auth_fd(file: Box<dyn crate::proc::Chan>, user: &[u8], aname: &[u8]) -> Result<Chan, Error> {
    let session = session_for(file)?;
    let number = session.fid()?;
    let mut request = number.to_le_bytes().to_vec();
    string(&mut request, user)?;
    string(&mut request, aname)?;
    let reply = session.call(TAUTH, &request)?;
    let fid = Fid::new(session, number);
    let mut reply = Decoder::new(&reply);
    let mut qid = reply.qid()?;
    if !reply.done() || (qid.type_ != QTAUTH && qid != Qid::empty()) {
        return Err(Error::Eio);
    }
    qid.type_ = QTAUTH;
    let index = dev::devs().find_by_char('M').ok_or(Error::Enoent)?;
    let mut chan = Chan::new(index, qid, 2);
    chan.aux = Some(Arc::new(fid));
    Ok(chan)
}

pub(crate) fn attach_fd(file: Box<dyn crate::proc::Chan>, auth: Option<&Chan>, user: &[u8], aname: &[u8]) -> Result<Chan, Error> {
    let index = dev::devs().find_by_char('M').ok_or(Error::Enoent)?;
    let auth = auth.map(|chan| {
        if chan.dev != index || chan.qid.type_ & QTAUTH == 0 {
            return Err(Error::Ebadfd);
        }
        let auth = fid(chan)?;
        if file.open_id() != Some(auth.session.open_id) || !auth.valid.load(Ordering::Acquire) {
            return Err(Error::Ebadfd);
        }
        Ok(auth)
    }).transpose()?;
    let session = session_for(file)?;
    let number = session.fid()?;
    let mut request = number.to_le_bytes().to_vec();
    request.extend_from_slice(&auth.map_or(NOFID, |fid| fid.number).to_le_bytes());
    string(&mut request, user)?;
    string(&mut request, aname)?;
    let reply = session.call(TATTACH, &request)?;
    let fid = Fid::new(session, number);
    let mut reply = Decoder::new(&reply);
    let qid = reply.qid()?;
    if !reply.done() {
        return Err(Error::Eio);
    }
    let mut chan = Chan::new(index, qid, 0);
    chan.aux = Some(Arc::new(fid));
    Ok(chan)
}

pub struct MntDev;

impl MntDev {
    pub fn new() -> Self { Self }

    fn open_fid(chan: &mut Chan, mut fid: Fid, kind: u8, args: &[u8], mode: u8) -> Result<(), Error> {
        let reply = fid.call(kind, args)?;
        let (qid, iounit) = decode_open(&reply)?;
        fid.iounit = iounit;
        chan.qid = qid;
        chan.mode = mode;
        chan.aux = Some(Arc::new(fid));
        Ok(())
    }
}

impl Dev for MntDev {
    fn attach(&mut self, _spec: Option<&str>) -> Result<Chan, Error> { Err(Error::Eperm) }

    fn walk(&mut self, chan: &mut Chan, name: &str) -> Result<Option<Qid>, Error> {
        let (fid, qid) = fid(chan)?.walk(Some(name))?;
        chan.qid = qid.ok_or(Error::Enoent)?;
        chan.aux = Some(Arc::new(fid));
        Ok(qid)
    }

    fn open(&mut self, chan: &mut Chan, mode: u8) -> Result<(), Error> {
        let (fid, _) = fid(chan)?.walk(None)?;
        Self::open_fid(chan, fid, TOPEN, &[mode], mode)
    }

    fn create(&mut self, chan: &mut Chan, name: &str, mode: u8, perm: u32) -> Result<(), Error> {
        let (fid, _) = fid(chan)?.walk(None)?;
        let mut args = Vec::new();
        string(&mut args, name.as_bytes())?;
        args.extend_from_slice(&perm.to_le_bytes());
        args.push(mode);
        Self::open_fid(chan, fid, TCREATE, &args, mode)?;
        chan.flag |= dev::CREATED_OPEN;
        Ok(())
    }

    fn read(&mut self, chan: &mut Chan, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        let fid = fid(chan)?;
        if chan.qid.type_ & qidtype::DIR != 0 {
            return fid.read_dir(buf, offset, chan.dev, false);
        }
        fid.transfer(offset, buf.len(), |position, range| {
            let data = fid.read_at(position, range.len())?;
            buf[range.start..range.start + data.len()].copy_from_slice(&data);
            Ok(data.len())
        })
    }

    fn write(&mut self, chan: &mut Chan, buf: &[u8], offset: u64) -> Result<usize, Error> {
        let fid = fid(chan)?;
        fid.transfer(offset, buf.len(), |position, range| fid.write_at(position, &buf[range]))
    }

    fn stat(&mut self, chan: &mut Chan) -> Result<DirEntry, Error> {
        let record = remote_stat(chan)?;
        decode_stat(&mut Decoder::new(&record[2..]), chan.dev)
    }

    fn wstat(&mut self, chan: &mut Chan, entry: &DirEntry) -> Result<(), Error> {
        let original = self.stat(chan)?;
        let mut stat = vec![0xff; 41];
        if entry.mode != original.mode {
            stat[21..25].copy_from_slice(&entry.mode.to_le_bytes());
        }
        if entry.atime != original.atime {
            stat[25..29].copy_from_slice(&entry.atime.to_le_bytes());
        }
        if entry.mtime != original.mtime {
            stat[29..33].copy_from_slice(&entry.mtime.to_le_bytes());
        }
        if entry.length != original.length {
            stat[33..41].copy_from_slice(&entry.length.to_le_bytes());
        }
        string(&mut stat, if entry.name == original.name { &[] } else { &entry.name })?;
        let owner = if entry.uid == original.uid { None } else { crate::upasswd::user_by_uid(entry.uid) };
        let group = if entry.gid == original.gid { None } else { crate::upasswd::group_by_gid(entry.gid) };
        if (entry.uid != original.uid && owner.is_none()) || (entry.gid != original.gid && group.is_none()) {
            return Err(Error::Einval);
        }
        string(&mut stat, owner.as_ref().map_or(&[], |user| user.name.as_bytes()))?;
        string(&mut stat, group.as_ref().map_or(&[], |group| group.name.as_bytes()))?;
        string(&mut stat, &[])?;
        let length = u16::try_from(stat.len() - 2).map_err(|_| Error::Einval)?;
        stat[..2].copy_from_slice(&length.to_le_bytes());
        wstat(chan, &stat)
    }

    fn truncate(&mut self, chan: &mut Chan) -> Result<(), Error> {
        let mut stat = vec![0xff; 41];
        stat[..2].copy_from_slice(&47u16.to_le_bytes());
        stat[33..41].copy_from_slice(&0u64.to_le_bytes());
        stat.extend_from_slice(&[0; 8]);
        wstat(chan, &stat)
    }

    fn remove(&mut self, chan: &mut Chan) -> Result<(), Error> {
        let (fid, _) = fid(chan)?.walk(None)?;
        let result = fid.call(TREMOVE, &[]);
        fid.valid.store(false, Ordering::Release);
        result.map(|_| ())
    }

    fn dev_char(&self) -> char { 'M' }
    fn name(&self) -> &'static str { "mnt" }
}

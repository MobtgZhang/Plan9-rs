use alloc::{boxed::Box, sync::{Arc, Weak}, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::dev::{self, Chan, Dev, DirEntry, Error, Qid, qidtype};
use crate::plan9_common::sync::Spinlock;

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

static SESSIONS: Spinlock<Vec<(usize, Weak<Session>)>> = Spinlock::new(Vec::new());

struct Session {
    connection: Spinlock<Connection>,
    next_fid: AtomicU32,
    msize: u32,
    open_id: usize,
}

struct Connection {
    file: Box<dyn crate::proc::Chan>,
    tag: u16,
    broken: bool,
}

impl Connection {
    fn next_tag(&mut self) -> u16 {
        let tag = self.tag;
        self.tag = if tag == NOTAG - 1 { 0 } else { tag + 1 };
        tag
    }

    fn exchange(&mut self, kind: u8, body: &[u8], msize: u32) -> Result<Vec<u8>, Error> {
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
        let response = self.transmit(&request, tag, msize, interruptible);
        let (reply_type, reply) = match response {
            Ok(response) => response,
            Err(Error::Eintr) => return Err(Error::Eintr),
            Err(error) => {
                self.broken = true;
                return Err(error);
            }
        };
        if reply_type == kind + 1 {
            return Ok(reply);
        }
        if reply_type == RERROR {
            let message = Decoder::new(&reply).string()?;
            return Err(match message {
                b"file does not exist" | b"does not exist" | b"not found" | b"No such file or directory" => Error::Enoent,
                b"permission denied" | b"Permission denied" => Error::Eperm,
                b"file already exists" | b"File exists" => Error::Eexists,
                _ => Error::Eio,
            });
        }
        self.broken = true;
        Err(Error::Eio)
    }

    fn write_all(&mut self, mut request: &[u8]) -> Result<(), Error> {
        while !request.is_empty() {
            let count = self.file.write(request).map_err(|_| Error::Eio)?;
            if count == 0 || count > request.len() {
                return Err(Error::Eio);
            }
            request = &request[count..];
        }
        Ok(())
    }

    fn transmit(&mut self, request: &[u8], tag: u16, msize: u32, interruptible: bool) -> Result<(u8, Vec<u8>), Error> {
        self.write_all(request)?;
        let mut flush = None;
        let mut completed = None;
        loop {
            let mut header = [0; 7];
            self.read_exact(&mut header, tag, interruptible, &mut flush)?;
            let mut header = Decoder::new(&header);
            let size = header.u32()?;
            let kind = header.u8()?;
            let reply_tag = header.u16()?;
            if size < 7 || size > msize {
                return Err(Error::Eio);
            }
            let mut reply = vec![0; size as usize - 7];
            self.read_exact(&mut reply, tag, interruptible, &mut flush)?;
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

    fn read_exact(&mut self, mut output: &mut [u8], tag: u16, interruptible: bool, flush: &mut Option<u16>) -> Result<(), Error> {
        while !output.is_empty() {
            let count = if interruptible && flush.is_none() {
                match self.file.read_interruptible(output) {
                    Ok(count) => count,
                    Err(crate::proc::Error::Eintr) => {
                        let flush_tag = self.next_tag();
                        let [flush_low, flush_high] = flush_tag.to_le_bytes();
                        let [tag_low, tag_high] = tag.to_le_bytes();
                        self.write_all(&[9, 0, 0, 0, TFLUSH, flush_low, flush_high, tag_low, tag_high])?;
                        *flush = Some(flush_tag);
                        continue;
                    }
                    Err(_) => return Err(Error::Eio),
                }
            } else {
                self.file.read(output).map_err(|_| Error::Eio)?
            };
            if count == 0 || count > output.len() {
                return Err(Error::Eio);
            }
            output = &mut output[count..];
        }
        Ok(())
    }
}

impl Session {
    fn new(file: Box<dyn crate::proc::Chan>, open_id: usize) -> Result<Self, Error> {
        let mut connection = Connection { file, tag: 0, broken: false };
        let mut request = MSIZE.to_le_bytes().to_vec();
        string(&mut request, b"9P2000")?;
        let reply = connection.exchange(TVERSION, &request, MSIZE)?;
        let mut reply = Decoder::new(&reply);
        let msize = reply.u32()?;
        if !(256..=MSIZE).contains(&msize) || reply.string()? != b"9P2000" || !reply.done() {
            return Err(Error::Enotsup);
        }
        Ok(Self { connection: Spinlock::new(connection), next_fid: AtomicU32::new(0), msize, open_id })
    }

    fn fid(&self) -> Result<u32, Error> {
        self.next_fid.try_update(Ordering::Relaxed, Ordering::Relaxed, |fid| fid.checked_add(1))
            .map_err(|_| Error::Enomem)
    }

    fn call(&self, kind: u8, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.connection.lock().exchange(kind, request, self.msize)
    }
}

struct Fid {
    session: Arc<Session>,
    number: u32,
    valid: AtomicBool,
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

impl Fid {
    fn new(session: Arc<Session>, number: u32) -> Self {
        Self { session, number, valid: AtomicBool::new(true), iounit: 0,
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
        let mut reply = Decoder::new(&reply);
        let length = reply.u32()?;
        let data = reply.take(length as usize)?;
        if length > count || !reply.done() {
            return Err(Error::Eio);
        }
        Ok(data.to_vec())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, Error> {
        let mut args = offset.to_le_bytes().to_vec();
        args.extend_from_slice(&(data.len() as u32).to_le_bytes());
        args.extend_from_slice(data);
        let reply = self.call(TWRITE, &args)?;
        let mut reply = Decoder::new(&reply);
        let written = reply.u32()? as usize;
        if written > data.len() || !reply.done() {
            return Err(Error::Eio);
        }
        Ok(written)
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
        if offset == 0 && dir.offset != 0 {
            *dir = Directory::default();
        }
        if offset != dir.offset {
            return Err(Error::Einval);
        }
        let mut written = 0;
        while written < output.len() {
            if dir.pending.is_empty() && !dir.eof {
                if let Err(error) = self.read_dir_batch(&mut dir, device, names) {
                    return if written == 0 { Err(error) } else { Ok(written) };
                }
            }
            if dir.pending.is_empty() {
                if dir.eof {
                    break;
                }
                continue;
            }
            let remaining = output.len() - written;
            let count = if names {
                remaining.min(dir.pending.len())
            } else {
                let mut end = 0;
                while end < dir.pending.len() {
                    let size = u16::from_le_bytes(dir.pending[end..end + 2].try_into().unwrap()) as usize;
                    if end + size + 2 > remaining {
                        break;
                    }
                    end += size + 2;
                }
                if end == 0 {
                    return if written == 0 { Err(Error::Einval) } else { Ok(written) };
                }
                end
            };
            output[written..written + count].copy_from_slice(&dir.pending[..count]);
            dir.pending.drain(..count);
            dir.offset += count as u64;
            written += count;
        }
        Ok(written)
    }

    fn read_dir_batch(&self, dir: &mut Directory, device: usize, names: bool) -> Result<(), Error> {
        let bytes = self.read_at(dir.wire_offset, self.max_io())?;
        let mut records = Decoder::new(&bytes);
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
        dir.wire_offset += bytes.len() as u64;
        dir.pending = pending;
        dir.eof = bytes.is_empty();
        Ok(())
    }
}

impl Drop for Fid {
    fn drop(&mut self) {
        if self.valid.load(Ordering::Relaxed) {
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

fn remote_stat(chan: &Chan) -> Result<Vec<u8>, Error> {
    let reply = fid(chan)?.call(TSTAT, &[])?;
    let mut reply = Decoder::new(&reply);
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
    let mut record = if dev::devs().find_by_char('M') == Some(chan.dev) {
        let mut record = remote_stat(chan)?;
        stat_fields(&record[2..])?;
        record[2..4].copy_from_slice(&(b'M' as u16).to_le_bytes());
        record[4..8].copy_from_slice(&(chan.dev as u32).to_le_bytes());
        record
    } else {
        let entry = dev::dev_stat(chan)?;
        let device_type = dev::devs().get(chan.dev).ok_or(Error::Enoent)?.dev_char();
        encode_stat(&entry, device_type)?
    };
    if let Some(name) = chan.namespace_path.as_deref().and_then(crate::vfs::file_name).filter(|_| use_path_name) {
        let name_length = stat_fields(&record[2..])?[0].len();
        let mut replacement = record[..41].to_vec();
        string(&mut replacement, name)?;
        replacement.extend_from_slice(&record[43 + name_length..]);
        set_stat_size(&mut replacement)?;
        record = replacement;
    }
    Ok(record)
}

fn set_stat_size(record: &mut [u8]) -> Result<(), Error> {
    let size = u16::try_from(record.len() - 2).map_err(|_| Error::Einval)?;
    record[..2].copy_from_slice(&size.to_le_bytes());
    Ok(())
}

pub(crate) fn wstat(chan: &mut Chan, stat: &[u8]) -> Result<(), Error> {
    let mut decoder = Decoder::new(stat);
    let size = decoder.u16()? as usize;
    let mut fields = Decoder::new(decoder.take(size)?);
    if !decoder.done() {
        return Err(Error::Einval);
    }
    let changes = decode_stat(&mut fields, chan.dev)?;
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

fn session_for(file: Box<dyn crate::proc::Chan>) -> Result<Arc<Session>, Error> {
    let index = dev::devs().find_by_char('M').ok_or(Error::Enoent)?;
    if file.access_mode() != 2 || file.dev() == index {
        return Err(Error::Eperm);
    }
    let open_id = file.open_id().ok_or(Error::Ebadfd)?;
    let mut sessions = SESSIONS.lock();
    sessions.retain(|(_, session)| session.strong_count() > 0);
    if let Some(session) = sessions.iter().find(|(id, _)| *id == open_id)
        .and_then(|(_, session)| session.upgrade())
    {
        return Ok(session);
    }
    let session = Arc::new(Session::new(file, open_id)?);
    sessions.push((open_id, Arc::downgrade(&session)));
    Ok(session)
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
    let qid = reply.qid()?;
    if !reply.done() || qid.type_ & QTAUTH == 0 {
        return Err(Error::Eio);
    }
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
        let mut reply = Decoder::new(&reply);
        let qid = reply.qid()?;
        fid.iounit = reply.u32()?;
        if !reply.done() {
            return Err(Error::Eio);
        }
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

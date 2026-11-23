#![no_std]
#![no_main]

use cmd::{arg, parse_u64, syscall};
use core::fmt::{self, Write};

const PAGE_SIZE: usize = 1024;
const USAGE: &str = "usage: snap [-o new-file] pid...";
type Result<T> = core::result::Result<T, &'static str>;

struct File(i64);

impl Drop for File {
    fn drop(&mut self) {
        syscall::close(self.0);
    }
}

struct Text {
    bytes: [u8; 96],
    len: usize,
}

impl Text {
    fn new(args: fmt::Arguments<'_>) -> Result<Self> {
        let mut text = Self { bytes: [0; 96], len: 0 };
        text.write_fmt(args).map_err(|_| "record header too long")?;
        Ok(text)
    }
}

impl Write for Text {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn open_proc(pid: u64, name: &str) -> Option<File> {
    let path = Text::new(format_args!("/proc/{pid}/{name}\0")).ok()?;
    let fd = syscall::open(path.bytes.as_ptr(), syscall::OREAD);
    (fd >= 0).then(|| File(fd))
}

fn read(fd: i64, bytes: &mut [u8]) -> Result<usize> {
    loop {
        let count = syscall::read(fd, bytes.as_mut_ptr(), bytes.len());
        match count {
            syscall::EINTR => continue,
            count if count >= 0 && count as usize <= bytes.len() => return Ok(count as usize),
            _ => return Err("cannot read process data"),
        }
    }
}

fn read_record<'a>(file: &File, bytes: &'a mut [u8]) -> Result<&'a [u8]> {
    let mut used = 0;
    while used < bytes.len() {
        let count = read(file.0, &mut bytes[used..])?;
        if count == 0 {
            return Ok(&bytes[..used]);
        }
        used += count;
    }
    Err("process metadata is too large")
}

fn write(fd: i64, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let count = syscall::write(fd, bytes.as_ptr(), bytes.len());
        match count {
            syscall::EINTR => continue,
            count if count > 0 && count as usize <= bytes.len() => bytes = &bytes[count as usize..],
            _ => return Err("cannot write snapshot"),
        }
    }
    Ok(())
}

fn header(fd: i64, args: fmt::Arguments<'_>) -> Result<()> {
    let text = Text::new(args)?;
    write(fd, &text.bytes[..text.len])
}

fn record(fd: i64, pid: u64, name: &str, bytes: &[u8]) -> Result<()> {
    header(fd, format_args!("{pid:<11} {name}\n{:<11} ", bytes.len()))?;
    write(fd, bytes)
}

fn region(output: i64, input: &File, offset: u64, length: u64) -> Result<()> {
    if syscall::seek(input.0, offset as i64, 0) != offset as i64 {
        return Err("cannot seek to process data");
    }
    header(output, format_args!("{offset:<11} {length:<11} "))?;
    let mut page = [0; PAGE_SIZE + 1];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(PAGE_SIZE as u64) as usize;
        let mut used = 1;
        while used <= count {
            let part = read(input.0, &mut page[used..=count])?;
            if part == 0 {
                return Err("unexpected EOF reading process data");
            }
            used += part;
        }
        if page[1..=count].iter().all(|byte| *byte == 0) {
            write(output, b"z")?;
        } else {
            page[0] = b'r';
            write(output, &page[..=count])?;
        }
        remaining -= count as u64;
    }
    Ok(())
}

fn bounds(line: &str) -> Result<(u64, u64)> {
    let mut fields = line.get(10..).ok_or("bad process segment record")?.split_ascii_whitespace();
    let mut address = || {
        fields.next().and_then(|field| u64::from_str_radix(field, 16).ok())
            .ok_or("bad process segment address")
    };
    let base = address()?;
    let top = address()?;
    Ok((base, top.checked_sub(base).ok_or("bad process segment bounds")?))
}

fn capture(output: i64, pid: u64) -> Result<()> {
    let status = open_proc(pid, "status").ok_or("cannot open process status")?;
    let mut scratch = [0; 1024];
    let state = |status: &[u8]| match status.get(56..67) {
        Some(b"Broken     ") => Ok(true),
        Some(b"Stop       ") => Ok(false),
        _ => Err("process is not stopped or Broken"),
    };
    let saved_status = read_record(&status, &mut scratch)?;
    let broken = state(saved_status)?;
    let regs = open_proc(pid, "regs").ok_or("cannot open process registers")?;
    let mem = open_proc(pid, "mem").ok_or("cannot open process memory")?;
    let text = open_proc(pid, "text").ok_or("cannot open process executable")?;
    let text_len = syscall::seek(text.0, 0, 2);
    if text_len <= 0 {
        return Err("cannot determine process executable length");
    }

    let segment = open_proc(pid, "segment").ok_or("cannot open process segments")?;
    let mut segment_bytes = [0; 2048];
    let segments = read_record(&segment, &mut segment_bytes)?;
    let lines = core::str::from_utf8(segments).map_err(|_| "bad process segment table")?.lines();
    for line in lines.clone() {
        bounds(line)?;
    }

    record(output, pid, "status", saved_status)?;
    record(output, pid, "segment", segments)?;
    let registers = read_record(&regs, &mut scratch)?;
    if registers.is_empty() {
        return Err("missing process registers");
    }
    record(output, pid, "regs", registers)?;
    for name in ["fpregs", "kregs", "noteid"] {
        if let Some(file) = open_proc(pid, name) {
            let bytes = read_record(&file, &mut scratch)?;
            if !bytes.is_empty() {
                record(output, pid, name, bytes)?;
            }
        }
    }
    header(output, format_args!("{pid:<11} text\n"))?;
    region(output, &text, 0, text_len as u64)?;
    header(output, format_args!("{pid:<11} mem\n{:<11} ", lines.clone().count()))?;
    for line in lines {
        let (offset, length) = bounds(line)?;
        region(output, &mem, offset, length)?;
    }
    if syscall::seek(status.0, 0, 0) != 0 || broken != state(read_record(&status, &mut scratch)?)? {
        return Err("process changed state while being captured");
    }
    Ok(())
}

fn snapshot(argc: usize, argv: *const *const u8) -> Result<()> {
    let named = arg(argc, argv, 1) == Some("-o");
    let first = if named { 3 } else { 1 };
    if argc <= first {
        return Err(USAGE);
    }
    let pid_at = |index| {
        let pid = arg(argc, argv, index).and_then(parse_u64)
            .filter(|pid| *pid != 0 && *pid <= i32::MAX as u64).ok_or(USAGE)?;
        if pid == syscall::getpid() as u64 {
            return Err("cannot snapshot self");
        }
        Ok(pid)
    };
    for index in first..argc {
        pid_at(index)?;
    }
    let file = if named {
        let path = arg(argc, argv, 2).filter(|path| !path.is_empty() && path.len() < 256).ok_or(USAGE)?;
        let mut name = [0u8; 256];
        name[..path.len()].copy_from_slice(path.as_bytes());
        let fd = syscall::create3(name.as_ptr(), syscall::OWRITE | syscall::OEXCL, 0o600);
        if fd < 0 {
            return Err("cannot create new snapshot file");
        }
        Some(File(fd))
    } else {
        None
    };
    let output = file.as_ref().map_or(1, |file| file.0);
    let mut username = [0; 28];
    let length = syscall::getuser(&mut username);
    let user = usize::try_from(length).ok().and_then(|length| username.get(..length))
        .and_then(|name| core::str::from_utf8(name).ok()).unwrap_or("none");
    let arch = cmd::uname::KERNEL_ARCH;
    let time = syscall::time(0).max(0);
    header(output, format_args!("process snapshot {time} {user}@plan9 {arch} 0 \"Plan9-rs\"\n"))?;
    for index in first..argc {
        capture(output, pid_at(index)?)?;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn cmd_main(argc: u64, argv: u64) -> ! {
    if let Err(error) = snapshot(argc as usize, argv as *const *const u8) {
        syscall::write_all(2, b"snap: ");
        syscall::write_all(2, error.as_bytes());
        syscall::write_all(2, b"\n");
        syscall::exits(error);
    }
    syscall::exit(0)
}

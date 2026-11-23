#![no_std]
#![no_main]

use cmd::syscall::{self, EINTR, RFCFDG, RFFDG, RFNOWAIT, RFPROC};
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
const NOTE_PC: usize = 15;
#[cfg(any(target_arch = "aarch64", target_arch = "loongarch64"))]
const NOTE_PC: usize = 31;
#[cfg(target_arch = "riscv64")]
const NOTE_PC: usize = 32;
#[cfg(target_arch = "x86_64")]
const REGISTER_SP: usize = 18;
#[cfg(any(target_arch = "aarch64", target_arch = "loongarch64", target_arch = "riscv64"))]
const REGISTER_SP: usize = NOTE_PC + 2;
#[cfg(target_arch = "x86_64")]
const REGISTER_SIZE: usize = 20 * 8;
#[cfg(not(target_arch = "x86_64"))]
const REGISTER_SIZE: usize = (REGISTER_SP + 1) * 8;
const IO_ERROR: i64 = -3;
const CRASH_MARKER: u64 = 0x37c1_1fc3_b5e2_a069;
const CRASH_SNAPSHOT: &[u8] = b"/tmp/procsmoke.snap\0";

static SAVED_PC: AtomicU64 = AtomicU64::new(0);
static ASYNC_NOTES: AtomicU64 = AtomicU64::new(0);
static DEADLINE_NOTES: AtomicU64 = AtomicU64::new(0);

fn check(condition: bool, message: &str) {
    if !condition {
        syscall::write_all(2, message.as_bytes());
        syscall::write_all(2, b"\n");
        syscall::exits(message);
    }
}

fn check_descriptors(flags: u32) {
    let fd = cmd::open_read("/dev/null");
    check(fd >= 3, "open descriptor");
    let pid = syscall::rfork(RFPROC | flags);
    check(pid >= 0, "rfork descriptor group");
    if pid == 0 {
        let closed = syscall::close(fd) == 0;
        check(closed == (flags != RFCFDG), "child descriptor table");
        syscall::exit(0);
    }
    check(syscall::wait(pid as i32) == 0, "wait for descriptor test");
    check((syscall::close(fd) == 0) == (flags != 0), "parent descriptor table");
    let stdout = syscall::dup(1);
    check(stdout >= 0, "parent descriptor after child exit");
    syscall::close(stdout);
}

fn check_close_on_exec() {
    let flagged = syscall::open(c"/dev/null".as_ptr().cast(), syscall::OREAD | syscall::OCEXEC);
    let ordinary = cmd::open_read("/dev/null");
    let created = syscall::create3(c"/tmp/procsmoke-cexec".as_ptr().cast(),
        syscall::OWRITE | syscall::OCEXEC, 0o600);
    check(flagged >= 0 && ordinary >= 0 && created >= 0, "open close-on-exec test files");
    let pid = syscall::rfork(RFPROC | RFFDG);
    check(pid >= 0, "fork close-on-exec test");
    if pid == 0 {
        check(syscall::dup2(flagged, 70) == 70 && syscall::dup2(created, 71) == 71
            && syscall::dup2(ordinary, 72) == 72, "duplicate close-on-exec test files");
        let missing = b"/tmp/procsmoke-no-such-image\0";
        let args = [missing.as_ptr(), core::ptr::null()];
        check(syscall::exec(missing.as_ptr(), args.as_ptr()) < 0 && syscall::dup2(70, 70) == 70,
            "failed exec leaves marked descriptors open");
        exec_self(b"close-on-exec\0");
    }
    check(syscall::wait(pid as i32) == 0, "successful exec closes only marked descriptors");
    for fd in [flagged, ordinary, created] {
        check(syscall::close(fd) == 0, "exec in copied group leaves parent descriptors open");
    }
}

extern "C" fn note_handler(_registers: *mut u8, message: *const u8) {
    let message = unsafe { core::slice::from_raw_parts(message, 6) };
    if message == b"alarm\0" {
        syscall::noted(0);
    }
    syscall::noted(1);
}

extern "C" fn restore_note(registers: *mut u8, message: *const u8) {
    check(unsafe { core::slice::from_raw_parts(message, 6) } == b"alarm\0", "saved note message");
    let saved_pc = SAVED_PC.swap(0, Ordering::Relaxed);
    check(saved_pc != 0, "saved note context");
    unsafe { registers.cast::<u64>().add(NOTE_PC).write(saved_pc) };
    syscall::noted(3);
    syscall::exits("NRSTR returned to its caller");
}

extern "C" fn save_note(registers: *mut u8, _message: *const u8) {
    let pc = unsafe { registers.cast::<u64>().add(NOTE_PC) };
    SAVED_PC.store(unsafe { pc.read() }, Ordering::Relaxed);
    unsafe { pc.write(restore_note as *const () as u64) };
    syscall::noted(2);
    syscall::exits("NSAVE returned to its caller");
}

fn check_saved_note() {
    check(syscall::notify(Some(save_note)) == 0, "register saved note handler");
    syscall::alarm(20);
    check(syscall::sleep_ms(500) == EINTR, "NSAVE and NRSTR restore interrupted syscall");
    check(SAVED_PC.load(Ordering::Relaxed) == 0, "consume saved note context");
    check(syscall::notify(None) == 0, "unregister saved note handler");
}

#[inline(never)]
fn illegal_instruction() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2", options(nomem, nostack));
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
        core::arch::asm!(".4byte 0", options(nomem, nostack));
    }
}

#[cfg(target_arch = "loongarch64")]
const UNMAPPED_ADDRESS: usize = 0xffff_8000_0000_0001;
#[cfg(not(target_arch = "loongarch64"))]
const UNMAPPED_ADDRESS: usize = 1;

#[inline(never)]
fn unmapped_load() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("movzx eax, byte ptr [{address}]", address = in(reg) UNMAPPED_ADDRESS,
            out("eax") _, options(readonly, nostack));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("ldrb wzr, [{address}]", address = in(reg) UNMAPPED_ADDRESS, options(readonly, nostack));
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("lbu zero, 0({address})", address = in(reg) UNMAPPED_ADDRESS, options(readonly, nostack));
        #[cfg(target_arch = "loongarch64")]
        core::arch::asm!("ld.b {value}, {address}, 0", address = in(reg) UNMAPPED_ADDRESS,
            value = out(reg) _, options(readonly, nostack));
    }
}

extern "C" fn fault_handler(registers: *mut u8, message: *const u8) {
    let prefix = b"sys: trap: illegal instruction pc=";
    check(unsafe { core::slice::from_raw_parts(message, prefix.len()) } == prefix, "fault note message");
    let pc = unsafe { registers.cast::<u64>().add(NOTE_PC) };
    let instruction_size = if cfg!(target_arch = "x86_64") { 2 } else { 4 };
    unsafe { pc.write(pc.read() + instruction_size) };
    syscall::noted(0);
    syscall::exits("fault noted returned");
}

fn check_fault_notes() {
    check(syscall::notify(Some(fault_handler)) == 0, "register fault handler");
    illegal_instruction();
    check(syscall::notify(None) == 0, "unregister fault handler after NCONT");

    check_broken_child(illegal_instruction, b"sys: trap: illegal instruction", false);
    check_broken_child(unmapped_load, b"sys: trap: fault read addr=", true);
    check(syscall::remove(CRASH_SNAPSHOT.as_ptr()) == 0, "remove crash snapshot");
}

fn check_broken_child(fault: fn(), message: &[u8], capture: bool) {
    let mut marker = 0u64;
    let pid = syscall::fork();
    check(pid >= 0, "fork faulting child");
    if pid == 0 {
        unsafe { core::ptr::write_volatile(&mut marker, CRASH_MARKER) };
        fault();
        syscall::exit(0);
    }
    let mut record = [0; 256];
    let size = syscall::await_child(&mut record);
    check(size > 0 && record[..size as usize].windows(message.len())
        .any(|part| part == message), "await unhandled fault");
    check(ctl(pid, b"waitstop"), "inspect faulting process after await");
    let fd = open_proc(pid, b"/status", syscall::OREAD);
    check(fd >= 0, "open faulting process status");
    let count = syscall::read(fd, record.as_mut_ptr(), record.len());
    syscall::close(fd);
    check(count > 0 && record[..count as usize].windows(6).any(|part| part == b"Broken"),
        "unhandled fault enters Broken");
    let fd = open_proc(pid, b"/regs", syscall::OREAD);
    let mut registers = [0; REGISTER_SIZE];
    check(fd >= 0 && syscall::read(fd, registers.as_mut_ptr(), registers.len()) == REGISTER_SIZE as i64,
        "read fault registers");
    syscall::close(fd);
    let register = |index| u64::from_le_bytes(registers[index * 8..][..8].try_into().unwrap());
    let (pc, sp) = (register(NOTE_PC), register(REGISTER_SP));
    let fd = open_proc(pid, b"/kregs", syscall::OREAD);
    let mut kernel = [0; REGISTER_SIZE];
    check(fd >= 0 && syscall::read(fd, kernel.as_mut_ptr(), kernel.len()) == REGISTER_SIZE as i64,
        "read fault kernel register frame");
    check(kernel[NOTE_PC * 8..][..8] != [0; 8] && kernel[REGISTER_SP * 8..][..8] != [0; 8],
        "read fault kernel PC and SP");
    check(syscall::read(fd, record.as_mut_ptr(), 1) == 0, "kernel register frame ends at EOF");
    syscall::close(fd);
    if capture {
        let marker_address = &marker as *const u64 as u64;
        check_snapshot(pid, marker_address);
        cmd::out_str("crash registers ");
        let mut digits = [0; 20];
        for value in [pc, sp] {
            cmd::out_str(cmd::utoa(value, &mut digits));
            cmd::out_str(" ");
        }
        cmd::outln(cmd::utoa(marker_address, &mut digits));
    }
    check(!ctl(pid, b"start"), "cannot resume a Broken process");
    check(ctl(pid, b"kill") && !ctl(pid, b"waitstop"), "reclaim faulting process");
    check(syscall::await_child(&mut record) < 0, "do not report a Broken exit twice");
}

fn snap_read(fd: i64, mut bytes: &mut [u8]) {
    while !bytes.is_empty() {
        let count = syscall::read(fd, bytes.as_mut_ptr(), bytes.len());
        check(count > 0 && count as usize <= bytes.len(), "read complete snapshot record");
        bytes = &mut bytes[count as usize..];
    }
}

fn snap_line(fd: i64, line: &mut [u8]) -> &[u8] {
    for index in 0..line.len() {
        snap_read(fd, &mut line[index..=index]);
        if line[index] == b'\n' {
            return &line[..index];
        }
    }
    syscall::exits("snapshot line too long")
}

fn snap_number(fd: i64) -> u64 {
    let mut digits = [0; 20];
    let mut length = 0;
    loop {
        let mut byte = [0];
        snap_read(fd, &mut byte);
        if byte[0] == b' ' {
            break;
        }
        check(length < digits.len() && byte[0].is_ascii_digit(), "snapshot number prefix");
        digits[length] = byte[0];
        length += 1;
    }
    for _ in length + 1..12 {
        let mut padding = [0];
        snap_read(fd, &mut padding);
        check(padding[0] == b' ', "snapshot number padding");
    }
    core::str::from_utf8(&digits[..length]).ok().and_then(cmd::parse_u64).unwrap_or_else(|| {
        syscall::exits("invalid snapshot number")
    })
}

fn check_snapshot(pid: i64, marker: u64) {
    let snap = b"/bin/snap\0";
    let mut number = [0; 24];
    cmd::utoa(pid as u64, &mut number);
    let args = [snap.as_ptr(), b"-o\0".as_ptr(), CRASH_SNAPSHOT.as_ptr(), number.as_ptr(), core::ptr::null()];
    for expected_success in [true, false] {
        let child = syscall::fork();
        check(child >= 0, "fork snapshot command");
        if child == 0 {
            if !expected_success {
                let null = cmd::open_read("/dev/null");
                syscall::dup2(null, 2);
            }
            syscall::exec(snap.as_ptr(), args.as_ptr());
            syscall::exits("exec snap failed");
        }
        check((syscall::wait(child as i32) == 0) == expected_success, "snapshot exclusive output");
    }

    let fd = syscall::open(CRASH_SNAPSHOT.as_ptr(), syscall::OREAD);
    check(fd >= 0, "open crash snapshot");
    let mut line = [0; 96];
    check(snap_line(fd, &mut line).starts_with(b"process snapshot "), "snapshot signature");
    loop {
        let record = snap_line(fd, &mut line);
        check(record.starts_with(cmd::utoa(pid as u64, &mut number).as_bytes()), "snapshot process ID");
        let field = record.get(12..).unwrap_or_default();
        if field == b"text" {
            break;
        }
        let length = snap_number(fd);
        if field == b"status" {
            let mut status = [0; 176];
            check(length == status.len() as u64, "snapshot status length");
            snap_read(fd, &mut status);
            check(&status[56..62] == b"Broken", "snapshot retained Broken status");
        } else {
            check(syscall::seek(fd, length as i64, 1) >= 0, "skip snapshot metadata");
        }
    }

    check(snap_number(fd) == 0, "snapshot executable file offset");
    let text_len = snap_number(fd);
    let mut found_stack = false;
    for region in 0..=1 {
        let count = if region == 0 { 1 } else {
            check(snap_line(fd, &mut line).ends_with(b" mem"), "snapshot memory section");
            snap_number(fd)
        };
        for _ in 0..count {
            let base = if region == 0 { 0 } else { snap_number(fd) };
            let length = if region == 0 { text_len } else { snap_number(fd) };
            for offset in (0..length).step_by(1024) {
                let mut page = [0; 1024];
                let size = (length - offset).min(1024) as usize;
                let mut tag = [0];
                snap_read(fd, &mut tag);
                check(matches!(tag[0], b'r' | b'z'), "snapshot page tag");
                if tag[0] == b'r' {
                    snap_read(fd, &mut page[..size]);
                }
                if region == 0 && offset == 0 {
                    check(&page[..4] == b"\x7fELF", "snapshot executable header");
                }
                if region == 1 {
                    if let Some(index) = marker.checked_sub(base + offset).filter(|index| *index + 8 <= size as u64) {
                        check(page[index as usize..][..8] == CRASH_MARKER.to_le_bytes(), "snapshot crash stack bytes");
                        found_stack = true;
                    }
                }
            }
        }
    }
    let mut tail = [0];
    check(found_stack && syscall::read(fd, tail.as_mut_ptr(), 1) == 0, "complete crash snapshot");
    syscall::close(fd);
}

fn check_bad_syscall_buffers() {
    const BAD_ADDRESS: i64 = -24;
    let invalid = UNMAPPED_ADDRESS as *mut u8;
    let path = c"/dev/null".as_ptr().cast::<u8>();
    let fd = syscall::open(path, syscall::ORDWR);
    check(fd >= 0, "open channel for invalid buffer checks");
    check(syscall::read(fd, invalid, 1) == BAD_ADDRESS, "reject unmapped read destination");
    check(syscall::write(fd, invalid, 1) == BAD_ADDRESS, "reject unmapped write source");
    check(syscall::read(fd, path.cast_mut(), 1) == BAD_ADDRESS, "reject read into read-only memory");
    check(syscall::write(fd, path, usize::MAX) == BAD_ADDRESS, "reject overflowing buffer length");
    check(syscall::open(invalid, syscall::OREAD) == BAD_ADDRESS, "reject unmapped pathname");
    check(syscall::exec(path, invalid.cast()) == BAD_ADDRESS, "reject unmapped argument vector");
    let result = unsafe { syscall::syscall1(syscall::SYS_PIPE, UNMAPPED_ADDRESS as u64) };
    check(result == BAD_ADDRESS, "reject invalid pipe descriptor output");
    check(syscall::write(fd, path, 1) == 1, "channel still usable after bad addresses");
    syscall::close(fd);
}

extern "C" fn async_note_handler(_registers: *mut u8, message: *const u8) {
    let message = unsafe { core::slice::from_raw_parts(message, 6) };
    let bit = match message {
        b"alarm\0" => 1,
        b"child\0" => 2,
        _ => {
            syscall::noted(1);
            return;
        }
    };
    ASYNC_NOTES.fetch_or(bit, Ordering::Relaxed);
    syscall::noted(0);
}

fn check_async_notes() {
    check(syscall::notify(Some(async_note_handler)) == 0, "register asynchronous note handler");
    let parent = syscall::getpid();
    let child = syscall::fork();
    check(child >= 0, "fork for timer preemption");
    if child == 0 {
        let mut number_buffer = [0; 24];
        let number = cmd::itoa(parent, &mut number_buffer).as_bytes();
        let mut path = [0; 40];
        path[..6].copy_from_slice(b"/proc/");
        path[6..6 + number.len()].copy_from_slice(number);
        path[6 + number.len()..11 + number.len()].copy_from_slice(b"/note");
        let fd = syscall::open(path.as_ptr(), syscall::OWRITE);
        check(fd >= 0 && syscall::write(fd, b"child".as_ptr(), 5) == 5, "post note to spinning parent");
        syscall::close(fd);
        syscall::exit(0);
    }
    syscall::alarm(60);
    while ASYNC_NOTES.load(Ordering::Relaxed) != 3 {
        core::hint::spin_loop();
    }
    check(syscall::wait(child as i32) == 0, "run child while parent is spinning");
    check(syscall::notify(None) == 0, "unregister asynchronous note handler");
}

fn check_await() {
    let pid = syscall::fork();
    check(pid >= 0, "fork for await");
    if pid == 0 {
        syscall::sleep_ms(500);
        syscall::exits("await status");
    }
    check(syscall::notify(Some(note_handler)) == 0, "register await note handler");
    syscall::alarm(20);
    let mut record = [0; 256];
    check(syscall::await_child(&mut record) == EINTR, "alarm interrupts blocked await");
    let size = syscall::await_child(&mut record);
    check(size > 0 && record[..size as usize].ends_with(b" 'await status'"), "retry await and read child status");
    check(syscall::wait(pid as i32) < 0, "await consumes the wait record");
    check(syscall::notify(None) == 0, "unregister await note handler");
}

fn open_proc(pid: i64, leaf: &[u8], mode: u32) -> i64 {
    let mut number = [0; 24];
    let number = cmd::itoa(pid, &mut number).as_bytes();
    let mut path = [0; 40];
    path[..6].copy_from_slice(b"/proc/");
    path[6..6 + number.len()].copy_from_slice(number);
    path[6 + number.len()..6 + number.len() + leaf.len()].copy_from_slice(leaf);
    syscall::open(path.as_ptr(), mode)
}

fn check_proc_wait() {
    let pid = syscall::getpid();
    let fd = open_proc(pid, b"/wait", syscall::OREAD);
    check(fd >= 0, "open own proc wait");
    let mut record = [0; 256];
    check(syscall::read(fd, record.as_mut_ptr(), record.len()) < 0, "proc wait without children");
    let mut pipe = [-1; 2];
    check(syscall::pipe(&mut pipe) == 0, "pipe for proc wait");
    let [reader, writer] = pipe;
    let child = syscall::rfork(RFPROC | RFFDG);
    check(child >= 0, "fork for proc wait");
    if child == 0 {
        syscall::close(writer);
        check(syscall::read(reader, record.as_mut_ptr(), 1) == 1, "release proc wait child");
        syscall::exits("proc wait 'status'");
    }
    syscall::close(reader);
    check(syscall::notify(Some(note_handler)) == 0, "register proc wait note handler");
    syscall::alarm(20);
    check(syscall::read(fd, record.as_mut_ptr(), record.len()) == EINTR, "note interrupts blocked proc wait");
    check(syscall::notify(None) == 0, "unregister proc wait note handler");
    syscall::write_all(writer, b"x");
    syscall::close(writer);
    let count = syscall::read(fd, record.as_mut_ptr(), record.len());
    check(count > 0 && record[..count as usize].ends_with(b" 'proc wait ''status'''"), "read proc wait record");
    check(syscall::wait(child as i32) < 0, "proc wait consumes await record");

    let child = syscall::fork();
    check(child >= 0, "fork for short proc wait");
    if child == 0 {
        syscall::exits("short wait record");
    }
    record[3] = u8::MAX;
    check(syscall::read(fd, record.as_mut_ptr(), 4) == 3 && record[3] == 0, "truncate and terminate short proc wait record");
    check(syscall::wait(child as i32) < 0, "short proc wait consumes wait record");
    syscall::close(fd);

    let parent = syscall::fork();
    check(parent >= 0, "fork target for external proc wait");
    if parent == 0 {
        let grandchild = syscall::fork();
        check(grandchild >= 0, "fork child for external proc wait");
        if grandchild == 0 {
            syscall::sleep_ms(100);
            syscall::exits("external proc wait");
        }
        syscall::sleep_ms(250);
        check(syscall::wait(grandchild as i32) < 0, "external reader consumes await record");
        syscall::exit(0);
    }
    let fd = open_proc(parent, b"/wait", syscall::OREAD);
    check(fd >= 0, "open external proc wait");
    let count = syscall::read(fd, record.as_mut_ptr(), record.len());
    check(count > 0 && record[..count as usize].ends_with(b" 'external proc wait'"), "read external proc wait record");
    check(syscall::read(fd, record.as_mut_ptr(), record.len()) < 0, "target exit unblocks external proc wait");
    syscall::close(fd);
    check(syscall::wait(parent as i32) == 0, "reap external wait target");

    let status = open_proc(pid, b"/status", syscall::OREAD);
    check(status >= 0, "open proc status");
    check(syscall::read(status, record.as_mut_ptr(), record.len()) == 176
        && record[..27].starts_with(b"procsmoke") && record[56..67].starts_with(b"Run")
        && record[68..176].chunks_exact(12).all(|field| field[11] == b' '), "Plan 9 proc status fields");
    syscall::close(status);

    let text = open_proc(pid, b"/text", syscall::OREAD);
    check(text >= 0, "open proc executable image");
    check(syscall::read(text, record.as_mut_ptr(), 4) == 4 && record[..4] == *b"\x7fELF", "read proc executable image");
    syscall::close(text);
    check(open_proc(pid, b"/text", syscall::OWRITE) < 0, "proc executable image is read only");

    let init_text = open_proc(1, b"/text", syscall::OREAD);
    check(init_text >= 0, "open boot init executable image");
    check(syscall::read(init_text, record.as_mut_ptr(), 4) == 4 && record[..4] == *b"\x7fELF", "read boot init executable image");
    syscall::close(init_text);
}

fn ctl(pid: i64, command: &[u8]) -> bool {
    let fd = open_proc(pid, b"/ctl", syscall::OWRITE);
    if fd < 0 {
        return false;
    }
    let count = syscall::write(fd, command.as_ptr(), command.len());
    syscall::close(fd);
    count == command.len() as i64
}

fn check_registers() {
    let pid = syscall::fork();
    check(pid >= 0, "fork register target");
    if pid == 0 {
        syscall::sleep_ms(250);
        syscall::exit(0);
    }
    check(ctl(pid, b"stop"), "stop register target");
    let regs = open_proc(pid, b"/regs", syscall::ORDWR);
    check(regs >= 0, "open stopped target registers");
    let pc_offset = (NOTE_PC * 8) as i64;
    let mut pc = [0; 8];
    check(syscall::seek(regs, pc_offset, 0) == pc_offset
        && syscall::read(regs, pc.as_mut_ptr(), pc.len()) == 8 && pc != [0; 8], "read saved program counter");
    check(syscall::seek(regs, pc_offset, 0) == pc_offset
        && syscall::write(regs, [0u8; 8].as_ptr(), 8) < 0, "reject invalid program counter");
    check(syscall::write(regs, pc.as_ptr(), pc.len()) == 8, "write valid program counter");
    syscall::close(regs);
    check_text_write(pid, u64::from_ne_bytes(pc));
    check(ctl(pid, b"start") && syscall::wait(pid as i32) == 0, "resume register target");
}

fn check_text_write(pid: i64, pc: u64) {
    let fd = open_proc(pid, b"/mem", syscall::ORDWR);
    check(fd >= 0, "open stopped target memory");
    let mut original = [0; 1];
    let mut changed = [0; 1];
    check(syscall::seek(fd, pc as i64, 0) == pc as i64
        && syscall::read(fd, original.as_mut_ptr(), 1) == 1, "read text segment byte");
    let patch = [original[0] ^ 0xff];
    check(syscall::seek(fd, pc as i64, 0) == pc as i64 && syscall::write(fd, patch.as_ptr(), 1) == 1,
        "write stopped target text");
    check(syscall::seek(fd, pc as i64, 0) == pc as i64 && syscall::read(fd, changed.as_mut_ptr(), 1) == 1
        && changed == patch, "read back text patch");
    check(syscall::seek(fd, pc as i64, 0) == pc as i64 && syscall::write(fd, original.as_ptr(), 1) == 1,
        "restore stopped target text");
    syscall::close(fd);
}

#[cfg(target_arch = "x86_64")]
const FP_OFFSET: i64 = 160 + 15 * 16;
#[cfg(target_arch = "aarch64")]
const FP_OFFSET: i64 = 31 * 16;
#[cfg(target_arch = "riscv64")]
const FP_OFFSET: i64 = 31 * 8;
#[cfg(target_arch = "loongarch64")]
const FP_OFFSET: i64 = 23 * 8;

#[inline(always)]
fn set_fp_marker(value: u64) {
    unsafe {
        use core::arch::asm;
        #[cfg(target_arch = "x86_64")]
        asm!("movq xmm15, {}", in(reg) value, options(nostack));
        #[cfg(target_arch = "aarch64")]
        asm!("fmov d31, {}", in(reg) value, out("v31") _, options(nostack));
        #[cfg(target_arch = "riscv64")]
        asm!(".option push", ".option arch, +d", "fmv.d.x f31, {}", ".option pop",
            in(reg) value, options(nostack));
        #[cfg(target_arch = "loongarch64")]
        asm!("movgr2fr.d $f23, {}", in(reg) value, out("$f23") _, options(nostack));
    }
}

#[inline(always)]
fn fp_marker() -> u64 {
    let value: u64;
    unsafe {
        use core::arch::asm;
        #[cfg(target_arch = "x86_64")]
        asm!("movq {}, xmm15", out(reg) value, options(nostack));
        #[cfg(target_arch = "aarch64")]
        asm!("fmov {}, d31", out(reg) value, options(nostack));
        #[cfg(target_arch = "riscv64")]
        asm!(".option push", ".option arch, +d", "fmv.x.d {}, f31", ".option pop",
            out(reg) value, options(nostack));
        #[cfg(target_arch = "loongarch64")]
        asm!("movfr2gr.d {}, $f23", out(reg) value, options(nostack));
    }
    value
}

fn check_fpregs() {
    const PARENT: u64 = 0x3ff0_0000_0000_0001;
    const CHILD: u64 = 0x4000_0000_0000_0002;
    const PATCHED: u64 = 0x4008_0000_0000_0003;
    set_fp_marker(PARENT);
    let pid = syscall::fork();
    check(pid >= 0, "fork floating point target");
    if pid == 0 {
        check(fp_marker() == PARENT, "fork inherits floating point state");
        let control = open_proc(syscall::getpid(), b"/ctl", syscall::OWRITE);
        check(control >= 0, "open own ctl for floating point test");
        set_fp_marker(CHILD);
        check(syscall::write(control, b"stop".as_ptr(), 4) == 4, "stop with live floating point state");
        check(fp_marker() == PATCHED, "debugger update reaches hardware floating point register");
        exec_self(b"exit\0");
    }
    check(ctl(pid, b"waitstop"), "wait for floating point target to stop");
    let fd = open_proc(pid, b"/fpregs", syscall::ORDWR);
    check(fd >= 0 && syscall::seek(fd, FP_OFFSET, 0) == FP_OFFSET, "seek stopped fpregs");
    let mut bytes = [0; 8];
    check(syscall::read(fd, bytes.as_mut_ptr(), 8) == 8 && u64::from_le_bytes(bytes) == CHILD,
        "fpregs exposes the captured register");
    let patch = PATCHED.to_le_bytes();
    check(syscall::seek(fd, FP_OFFSET, 0) == FP_OFFSET
        && syscall::write(fd, patch.as_ptr(), patch.len()) == 8, "patch stopped floating point target");
    check(ctl(pid, b"hang") && ctl(pid, b"start") && ctl(pid, b"waitstop"), "stop floating point target after exec");
    check(syscall::seek(fd, FP_OFFSET, 0) == FP_OFFSET
        && syscall::read(fd, bytes.as_mut_ptr(), 8) == 8 && bytes == [0; 8], "exec clears floating point state");
    syscall::close(fd);
    check(ctl(pid, b"start") && syscall::wait(pid as i32) == 0, "resume floating point target after exec");
    check(fp_marker() == PARENT, "floating point state remains private to the process");
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    "procsmoke_text_one: mov eax, 1; ret",
    "procsmoke_text_two: mov eax, 2; ret",
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".p2align 2", "procsmoke_text_one: mov w0, #1; ret",
    "procsmoke_text_two: mov w0, #2; ret",
);
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".option push", ".option norvc", ".p2align 2", "procsmoke_text_one: addi a0, zero, 1; ret",
    "procsmoke_text_two: addi a0, zero, 2; ret", ".option pop",
);
#[cfg(target_arch = "loongarch64")]
core::arch::global_asm!(
    ".p2align 2", "procsmoke_text_one: addi.w $a0, $zero, 1; jr $ra",
    "procsmoke_text_two: addi.w $a0, $zero, 2; jr $ra",
);

fn check_text_execution() {
    extern "C" {
        fn procsmoke_text_one() -> u64;
        fn procsmoke_text_two() -> u64;
    }
    let pid = syscall::fork();
    check(pid >= 0, "fork target for executable patch");
    if pid == 0 {
        check(ctl(syscall::getpid(), b"stop"), "stop before executing patched text");
        check(unsafe { procsmoke_text_one() } == 2, "execute modified text in child");
        syscall::exit(0);
    }
    check(ctl(pid, b"waitstop"), "wait for text patch target");
    let fd = open_proc(pid, b"/mem", syscall::ORDWR);
    let address = procsmoke_text_one as *const () as i64;
    let len = if cfg!(target_arch = "x86_64") { 5 } else { 4 };
    check(fd >= 0 && syscall::seek(fd, address, 0) == address
        && syscall::write(fd, procsmoke_text_two as *const () as *const u8, len) == len as i64,
        "patch executable instruction in a stopped child");
    syscall::close(fd);
    check(ctl(pid, b"start") && syscall::wait(pid as i32) == 0, "patched instruction finishes successfully");
    check(unsafe { procsmoke_text_one() } == 1, "patch does not change the parent executable text");
}

fn check_local_directories() {
    for (path, expected) in [("/proc", b"1".as_slice()), ("/env", b"cputype".as_slice()),
        ("/dev", b"null".as_slice()), ("/boot", b"init".as_slice())] {
        let fd = cmd::open_read(path);
        let mut output = [0; 1024];
        check(fd >= 0, path);
        if syscall::read(fd, output.as_mut_ptr(), 2) >= 0 {
            cmd::outln(path);
            check(false, "local directory does not split a stat record");
        }
        let count = syscall::read(fd, output.as_mut_ptr(), output.len());
        check(count > 0, "read local directory records after short buffer");
        check(syscall::seek(fd, 0, 0) == 0, "rewind local directory");
        let mut directory = cmd::DirReader::new(fd);
        let mut found = false;
        while let Some(name) = directory.next_name() {
            found |= name == expected;
        }
        check(found, "read expected local directory entry");
        syscall::close(fd);
    }
}

fn check_note_groups() {
    use cmd::syscall::RFNOTEG;

    let sender = syscall::rfork(RFPROC | RFFDG | RFNOTEG);
    check(sender >= 0, "fork note group leader");
    if sender == 0 {
        syscall::sleep_ms(3000);
        syscall::exits("note group leader was not stopped");
    }
    let recipient = syscall::rfork(RFPROC | RFFDG | RFNOTEG);
    check(recipient >= 0, "fork note group recipient");
    if recipient == 0 {
        syscall::sleep_ms(3000);
        syscall::exits("group note not received");
    }
    let group_file = open_proc(sender, b"/notepg", syscall::OWRITE);
    check(group_file >= 0, "open group note channel");
    let noteid = open_proc(recipient, b"/noteid", syscall::OWRITE);
    let mut number = [0; 24];
    let group = cmd::itoa(sender, &mut number).as_bytes();
    check(noteid >= 0 && syscall::write(noteid, group.as_ptr(), group.len()) == group.len() as i64,
        "join another process note group");
    syscall::close(noteid);
    check(ctl(sender, b"stop") && ctl(sender, b"kill"), "stop and kill note group leader");
    let mut status = [0; 64];
    check(syscall::wait_status(sender as i32, &mut status) > 0, "reap killed note group leader");
    let message = b"group-note";
    check(syscall::write(group_file, message.as_ptr(), message.len()) == message.len() as i64,
        "post group note after leader exits");
    syscall::close(group_file);
    check(syscall::wait_status(recipient as i32, &mut status) == message.len() as i64
        && &status[..message.len()] == message, "note group member exits on group note");
}

fn check_waitstop_note() {
    let pid = syscall::fork();
    check(pid >= 0, "fork for waitstop");
    if pid == 0 {
        check(syscall::notify(Some(note_handler)) == 0, "register waitstop note handler");
        syscall::alarm(30);
        check(syscall::sleep_ms(500) == EINTR, "resume note after debugger stop");
        syscall::exit(0);
    }
    check(ctl(pid, b"waitstop"), "waitstop intercepts a pending note");
    check(ctl(pid, b"start"), "resume process with pending note");
    check(syscall::wait(pid as i32) == 0, "wait for note after debugger stop");
}

fn exec_self(mode: &[u8]) -> ! {
    let path = b"/bin/aux/procsmoke\0";
    let argv = [path.as_ptr(), mode.as_ptr(), core::ptr::null()];
    syscall::exec(path.as_ptr(), argv.as_ptr());
    syscall::exits("exec procsmoke failed");
}

fn check_hang() {
    let current = syscall::getpid();
    check(ctl(current, b"hang"), "set hang on parent");
    let pid = syscall::fork();
    check(pid >= 0, "fork for hang");
    if pid == 0 {
        exec_self(b"hang-again\0");
    }
    check(ctl(current, b"nohang"), "clear parent hang bit");
    check(ctl(pid, b"waitstop"), "hang survives fork");
    check(ctl(pid, b"start"), "resume child after first exec");
    check(ctl(pid, b"waitstop"), "hang survives exec");
    check(ctl(pid, b"nohang") && ctl(pid, b"start"), "clear child hang bit");
    check(syscall::wait(pid as i32) == 0, "wait for child after clearing hang");
}

fn check_profile() {
    let pid = syscall::getpid();
    let fd = open_proc(pid, b"/profile", syscall::OREAD);
    let mut total = [0; 4];
    check(fd >= 0, "open process profile");
    check(syscall::read(fd, total.as_mut_ptr(), total.len()) < 0, "profile starts disabled");
    check(ctl(pid, b"profile"), "enable process profile");
    let until = syscall::time(1) + 80;
    while syscall::time(1) < until {
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
    }
    check(syscall::read(fd, total.as_mut_ptr(), 1) == 1
        && syscall::read(fd, total[1..].as_mut_ptr(), 3) == 3
        && u32::from_ne_bytes(total) > 0, "sample user instructions and read profile by byte offset");
    syscall::close(fd);
}

fn check_trace() {
    let trace = cmd::open_read("/proc/trace");
    check(trace >= 0 && cmd::open_read("/proc/trace") < 0, "one proc trace reader");
    let copy = syscall::dup(trace);
    check(copy >= 0 && syscall::close(trace) == 0, "duplicate trace descriptor");
    check(cmd::open_read("/proc/trace") < 0, "trace reader retained by duplicate");

    let pid = syscall::fork();
    check(pid >= 0, "fork trace child");
    if pid == 0 {
        check(ctl(syscall::getpid(), b"trace 1") && ctl(syscall::getpid(), b"event"), "enable trace and record user event");
        syscall::sleep_ms(20);
        syscall::exit(0);
    }
    check(syscall::wait(pid as i32) == 0, "wait for trace child");

    let mut records = [0; 160];
    check(syscall::read(copy, records.as_mut_ptr(), 15) == 0, "trace only returns full records");
    let count = syscall::read(copy, records.as_mut_ptr(), records.len());
    check(count == 80, "read five trace records");
    let mut previous = 0;
    for (record, event) in records[..count as usize].chunks_exact(16).zip([13, 5, 4, 3, 10]) {
        let timestamp = u64::from_ne_bytes(record[8..].try_into().unwrap());
        check(u32::from_ne_bytes(record[..4].try_into().unwrap()) == pid as u32, "trace process ID");
        check(u32::from_ne_bytes(record[4..8].try_into().unwrap()) == event, "trace event order");
        check(timestamp >= previous, "trace time is monotonic");
        let wall_time = syscall::time(0);
        if wall_time > 0 {
            check((timestamp / 1_000_000_000).abs_diff(wall_time as u64) < 5, "trace uses wall time");
        }
        previous = timestamp;
    }
    check(syscall::read(copy, records.as_mut_ptr(), records.len()) == 0, "trace records consumed once");
    syscall::close(copy);
    let reopened = cmd::open_read("/proc/trace");
    check(reopened >= 0, "reopen trace after last close");
    syscall::close(reopened);
}

fn check_process_memory() {
    static VALUE: AtomicU64 = AtomicU64::new(0x12345678);
    let address = &VALUE as *const AtomicU64 as i64;
    let mut ends = [-1; 2];
    check(syscall::pipe(&mut ends) == 0, "pipe for process memory child");
    let [reader, writer] = ends;
    let pid = syscall::rfork(RFPROC | RFFDG);
    check(pid >= 0, "fork process memory child");
    if pid == 0 {
        syscall::close(writer);
        let mut ready = 0;
        check(syscall::read(reader, &mut ready, 1) == 1, "wait for debugger write");
        syscall::close(reader);
        check(VALUE.load(Ordering::Relaxed) == 0x87654321, "child sees debugger write");
        syscall::exit(0);
    }
    syscall::close(reader);
    let fd = open_proc(pid, b"/mem", syscall::ORDWR);
    let mut value = [0; 8];
    check(fd >= 0, "open child memory");
    check(syscall::seek(fd, address, 0) == address, "seek to child virtual address");
    check(syscall::read(fd, value.as_mut_ptr(), value.len()) == 8, "read child memory by virtual address");
    check(u64::from_ne_bytes(value) == 0x12345678, "read expected value from child memory");
    let updated = 0x87654321u64.to_ne_bytes();
    check(syscall::seek(fd, address, 0) == address && syscall::write(fd, updated.as_ptr(), updated.len()) < 0,
        "reject memory write to runnable child");
    check(ctl(pid, b"stop") && syscall::write(fd, updated.as_ptr(), updated.len()) == 8,
        "write stopped child memory");
    syscall::close(fd);
    check(syscall::write(writer, b"x".as_ptr(), 1) == 1, "release process memory child");
    syscall::close(writer);
    check(ctl(pid, b"start") && syscall::wait(pid as i32) == 0, "resume and reap memory child");
    check(VALUE.load(Ordering::Relaxed) == 0x12345678, "child and parent memory are separate");
}

fn check_scheduling_controls() {
    let current = syscall::getpid();
    check(ctl(current, b"fixedpri 21") && ctl(current, b"wired 0") && ctl(current, b"noswap"),
        "configure fixed priority and CPU affinity");
    check(!ctl(current, b"pri invalid") && !ctl(current, b"fixedpri"), "reject malformed priority");
    let mut pipe = [-1; 2];
    check(syscall::pipe(&mut pipe) == 0, "pipe for scheduling order");
    let mut children = [0; 2];
    for (index, slot) in children.iter_mut().enumerate() {
        let pid = syscall::fork();
        check(pid >= 0, "fork for scheduling order");
        if pid == 0 {
            syscall::write_all(pipe[1] as i64, &[b'a' + index as u8]);
            syscall::exit(0);
        }
        *slot = pid;
        let command: &[u8] = if index == 0 { b"fixedpri 5" } else { b"fixedpri 18" };
        check(ctl(pid, command), "set child dispatch priority");
    }
    syscall::close(pipe[1] as i64);
    let mut order = [0; 2];
    for byte in &mut order {
        check(syscall::read(pipe[0] as i64, byte, 1) == 1, "read scheduled child");
    }
    check(order == *b"ba", "dispatch higher priority child first");
    syscall::close(pipe[0] as i64);
    for pid in children {
        check(syscall::wait(pid as i32) == 0, "reap scheduled child");
    }
    check(ctl(current, b"pri 10"), "restore dynamic priority");
    let args = open_proc(current, b"/args", syscall::OREAD);
    let mut output = [0; 128];
    let count = syscall::read(args, output.as_mut_ptr(), output.len());
    check(count > 0 && output[..count as usize].starts_with(b"'/bin/aux/procsmoke'"), "read quoted exec arguments");
    syscall::close(args);
}

extern "C" fn deadline_note(_registers: *mut u8, message: *const u8) {
    if unsafe { core::slice::from_raw_parts(message, 16) } != b"deadline missed\0" {
        syscall::noted(1);
        return;
    }
    DEADLINE_NOTES.fetch_add(1, Ordering::Relaxed);
    syscall::noted(0);
}

fn check_edf_notes_and_extra() {
    let pid = syscall::getpid();
    check(syscall::notify(Some(deadline_note)) == 0, "register EDF deadline note handler");
    check(ctl(pid, b"period 800ms") && ctl(pid, b"deadline 200ms") && ctl(pid, b"cost 20ms")
        && ctl(pid, b"sporadic") && ctl(pid, b"extra") && ctl(pid, b"deadlinenotes"),
        "configure sporadic EDF with extra time and deadline notes");
    let before = syscall::time(1);
    check(ctl(pid, b"admit"), "admit EDF extra-time reservation");
    let mut elapsed = 0;
    while elapsed < 60 {
        core::hint::spin_loop();
        elapsed = syscall::time(1) - before;
    }
    check(elapsed < 800 && DEADLINE_NOTES.load(Ordering::Relaxed) == 0,
        "extra runs after budget exhaustion without a missed-deadline note");
    check(ctl(pid, b"expel"), "expel EDF extra-time reservation");
    check(ctl(pid, b"cost 100ms") && ctl(pid, b"admit"), "admit EDF deadline-note reservation");
    check(syscall::sleep_ms(300) == 0 && DEADLINE_NOTES.load(Ordering::Relaxed) == 1,
        "deliver one deadline note on wake after an unfinished job");
    check(syscall::sleep_ms(60) == 0 && DEADLINE_NOTES.load(Ordering::Relaxed) == 1,
        "do not send duplicate deadline notes for the same release");
    check(ctl(pid, b"expel") && syscall::notify(None) == 0, "clear EDF note-test state");
}

fn check_edf() {
    let pid = syscall::getpid();
    check(!ctl(pid, b"admit") && !ctl(pid, b"period 1ms"), "reject missing or sub-tick EDF parameters");
    check(ctl(pid, b"period 0.2s") && ctl(pid, b"deadline 100ms") && ctl(pid, b"cost 20ms")
        && ctl(pid, b"sporadic") && ctl(pid, b"deadlinenotes"), "configure EDF reservation");
    let before = syscall::time(1);
    check(ctl(pid, b"admit"), "admit EDF reservation");
    check(syscall::sleep_ms(0) == 0 && syscall::time(1) - before >= 200, "yield until the next EDF release");
    let child = syscall::fork();
    check(child >= 0, "fork EDF admission competitor");
    if child == 0 {
        syscall::sleep_ms(10_000);
        syscall::exit(0);
    }
    check(ctl(child, b"stop"), "stop EDF admission competitor");
    check(ctl(child, b"period 200ms") && ctl(child, b"deadline 100ms") && ctl(child, b"cost 90ms")
        && ctl(child, b"extra") && !ctl(child, b"admit"), "reject oversubscribed EDF reservations");
    check(ctl(pid, b"expel") && ctl(child, b"admit"), "release EDF admission capacity");
    check(ctl(child, b"kill") && syscall::wait(child as i32) != 0, "reap EDF admission competitor");
    let before = syscall::time(1);
    check(ctl(pid, b"admit"), "readmit EDF process for budget test");
    let mut elapsed = 0;
    while elapsed < 60 {
        core::hint::spin_loop();
        elapsed = syscall::time(1) - before;
    }
    check(elapsed >= 200, "exhausted EDF budget cannot run before the next release");
    check(ctl(pid, b"expel"), "leave EDF scheduler after budget test");

    let mut pipe = [-1; 2];
    check(syscall::pipe(&mut pipe) == 0, "pipe for EDF dispatch order");
    check(ctl(pid, b"period 500ms") && ctl(pid, b"deadline 250ms") && ctl(pid, b"cost 180ms")
        && ctl(pid, b"admit"), "reserve earlier deadline for EDF test coordinator");
    let mut children = [0; 2];
    for (index, slot) in children.iter_mut().enumerate() {
        let child = syscall::fork();
        check(child >= 0, "fork EDF dispatch competitor");
        if child == 0 {
            syscall::write_all(pipe[1] as i64, &[b'a' + index as u8]);
            syscall::exit(0);
        }
        *slot = child;
        let deadline: &[u8] = if index == 0 { b"deadline 450ms" } else { b"deadline 350ms" };
        check(ctl(child, b"stop") && ctl(child, b"period 500ms") && ctl(child, deadline)
            && ctl(child, b"cost 20ms") && ctl(child, b"admit"), "admit EDF dispatch competitor");
    }
    check(ctl(children[0], b"start") && ctl(children[1], b"start"), "release both EDF competitors");
    check(ctl(pid, b"expel"), "release EDF test coordinator reservation");
    syscall::close(pipe[1] as i64);
    let mut order = [0; 2];
    for byte in &mut order {
        check(syscall::read(pipe[0] as i64, byte, 1) == 1, "read EDF dispatch order");
    }
    syscall::close(pipe[0] as i64);
    check(order == *b"ba", "dispatch earliest deadline first");
    for child in children {
        check(syscall::wait(child as i32) == 0, "reap EDF dispatch competitor");
    }
}

fn check_private_exec() {
    let current = syscall::getpid();
    check(ctl(current, b"private"), "make process private");
    let pid = syscall::fork();
    check(pid >= 0, "fork private process");
    if pid == 0 {
        check(!ctl(syscall::getpid(), b"nohang"), "private survives fork");
        exec_self(b"private-exec\0");
    }
    check(syscall::wait(pid as i32) == 0, "private clears on exec");
}

fn check_detached_children() {
    for _ in 0..270 {
        let pid = syscall::rfork(RFPROC | RFFDG | RFNOWAIT);
        check(pid >= 0, "reclaim detached child");
        if pid == 0 {
            syscall::exit(0);
        }
        syscall::yield_cpu();
        check(syscall::wait(pid as i32) < 0, "detached child has no wait record");
    }
}

fn check_srv_close_on_exit() {
    const ORCLOSE: u32 = 0x40;
    let path = b"/srv/procsmoke-orclose\0";
    let pid = syscall::fork();
    check(pid >= 0, "fork for service cleanup");
    if pid == 0 {
        let fd = syscall::create3(path.as_ptr(), syscall::OWRITE | ORCLOSE, 0o600);
        check(fd >= 0, "create remove-on-close service");
        let null = cmd::open_read("/dev/null");
        let mut number = [0; 24];
        let text = cmd::itoa(null, &mut number).as_bytes();
        check(null >= 0 && syscall::write(fd, text.as_ptr(), text.len()) == text.len() as i64,
            "publish remove-on-close service");
        syscall::exit(0);
    }
    check(syscall::wait(pid as i32) == 0, "wait for service owner");
    check(syscall::open(path.as_ptr(), syscall::OREAD) < 0, "unpublish service at last close on exit");
    let fd = syscall::create3(path.as_ptr(), syscall::OWRITE | ORCLOSE, 0o600);
    check(fd >= 0 && syscall::close(fd) == 0, "reuse removed service name");
}

fn check_mount_io() {
    let mut output = [0; 512];
    let file = cmd::open_read("/tmp/mnt9p/remote");
    check(file >= 0, "open remote file for fstat");
    check(syscall::fstat(file, &mut output[..1]) < 0, "fstat requires a size field");
    check(syscall::fstat(file, &mut output[..2]) == 2, "fstat short buffer returns the record size");
    let size = u16::from_le_bytes(output[..2].try_into().unwrap()) as usize + 2;
    check(syscall::fstat(file, &mut output[..size]) == size as i64, "fstat returns entire record");
    check(cmd::stat_name(&output[..size]) == Some(b"remote"), "fstat preserves server file name");
    check(output[2..4] == [b'M', 0] && output[33..41] == 9u64.to_le_bytes(), "fstat device and length");
    check(output[49..size] == *b"\x05\0alice\x05\0staff\x06\0editor", "fstat preserves remote owner fields");
    syscall::close(file);
    let count = syscall::stat(b"/tmp/mnt9p\0".as_ptr(), output.as_mut_ptr(), output.len());
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"mnt9p"), "stat uses mountpoint name");

    let payload = [b'x'; 260];
    let path = b"/tmp/mnt9p/chunked\0";
    let writer = syscall::create3(path.as_ptr(), syscall::OWRITE, 0o600);
    check(writer >= 0 && syscall::write(writer, payload.as_ptr(), payload.len()) == payload.len() as i64,
        "write across 9P iounits in one call");
    syscall::close(writer);
    let reader = syscall::open(path.as_ptr(), syscall::OREAD);
    let mut output = [0; 300];
    check(reader >= 0 && syscall::read(reader, output.as_mut_ptr(), output.len()) == payload.len() as i64,
        "read across 9P iounits to a short reply");
    check(output[..payload.len()] == payload, "9P chunks preserve offsets and content");
    syscall::close(reader);

    let reader = cmd::open_read("/tmp/mnt9p/flush");
    check(reader >= 0, "open file for canceled 9P read");
    check(syscall::notify(Some(note_handler)) == 0, "register 9P alarm handler");
    syscall::alarm(100);
    check(syscall::read(reader, output.as_mut_ptr(), output.len()) == EINTR, "canceled 9P read returns EINTR");
    let expected = b"after-flush\n";
    check(syscall::read(reader, output.as_mut_ptr(), output.len()) == expected.len() as i64
        && &output[..expected.len()] == expected, "9P session and offset survive cancellation");
    syscall::close(reader);

    let reader = cmd::open_read("/tmp/mnt9p/flush-race");
    check(reader >= 0, "open file for 9P flush race");
    syscall::alarm(100);
    let expected = b"completed\n";
    check(syscall::read(reader, output.as_mut_ptr(), output.len()) == expected.len() as i64
        && &output[..expected.len()] == expected, "preserve partially received reply that completes before Rflush");
    check(syscall::read(reader, output.as_mut_ptr(), output.len()) == 0, "9P flush race advances file offset");
    syscall::close(reader);

    let reader = cmd::open_read("/tmp/mnt9p/listing");
    check(reader >= 0, "open remote directory for interrupted read");
    check(syscall::read(reader, output.as_mut_ptr(), 2) < 0, "directory read cannot split a record");
    let count = syscall::read(reader, output.as_mut_ptr(), output.len());
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"first"),
        "directory read reports completed entries without waiting for another batch");
    check(output[2..4] == [b'M', 0] && output[48..count as usize] == *b"\x05\0alice\x05\0staff\x06\0editor",
        "directory record preserves remote owner fields");
    syscall::alarm(200);
    check(syscall::read(reader, output.as_mut_ptr(), output.len()) == EINTR, "cancel outstanding directory read");
    let count = syscall::read(reader, output.as_mut_ptr(), output.len());
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"second"),
        "continue directory read without repeating entries");
    check(syscall::read(reader, output.as_mut_ptr(), output.len()) == 0, "read remote directory to EOF");
    check(syscall::seek(reader, 1, 0) < 0 && syscall::seek(reader, 0, 0) == 0, "directory seek only supports rewind");
    let count = syscall::read(reader, output.as_mut_ptr(), 70);
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"first"), "rewind binary directory");
    syscall::close(reader);

    check(syscall::notify(None) == 0, "unregister 9P alarm handler");
    syscall::write_all(1, b"mount-io-ok\n");
    syscall::exit(0);
}

fn check_mount_mutations() -> ! {
    let source = c"/tmp/mnt9p/clone-cancel".as_ptr().cast();
    let target = c"/tmp/clone-cancel".as_ptr().cast();
    check(syscall::bind(source, target, 0) == 0, "bind a shared remote fid");
    check(syscall::notify(Some(note_handler)) == 0, "register fid operation alarm handler");
    syscall::alarm(200);
    check(syscall::open(target, syscall::OREAD) == EINTR, "interrupt zero-name Twalk");
    let reader = syscall::open(target, syscall::OREAD);
    let mut byte = 0;
    check(reader >= 0 && syscall::read(reader, &mut byte, 1) == 1 && byte == b'c',
        "reopen the shared fid after an interrupted clone");
    syscall::close(reader);
    check(syscall::unmount(core::ptr::null(), target) == 0, "unmount shared remote fid");

    let created = c"/tmp/mnt9p/create-cancel".as_ptr().cast();
    syscall::alarm(200);
    check(syscall::create3(created, syscall::OWRITE, 0o600) == EINTR, "interrupt Tcreate");
    let writer = syscall::create3(created, syscall::OWRITE, 0o600);
    check(writer >= 0, "create file after an interrupted Tcreate");
    syscall::close(writer);
    check(syscall::remove(created) == 0, "remove newly created file");

    let removed = c"/tmp/mnt9p/remove-cancel".as_ptr().cast();
    syscall::alarm(200);
    check(syscall::remove(removed) == EINTR, "interrupt Tremove");
    check(syscall::remove(removed) == 0, "remove file after an interrupted Tremove");
    check(syscall::notify(None) == 0, "unregister fid operation alarm handler");

    let ready = cmd::open_read("/tmp/mnt9p/remove-kill-ready");
    check(ready >= 0, "open Tremove cancellation barrier");
    let child = syscall::fork();
    check(child >= 0, "fork Tremove cancellation victim");
    if child == 0 {
        syscall::remove(c"/tmp/mnt9p/remove-kill".as_ptr().cast());
        check(false, "killed 9P remover must not return to user mode");
        syscall::exit(1);
    }
    check(syscall::read(ready, &mut byte, 1) == 1 && byte == b'r', "wait for the victim's Tremove");
    check(ctl(child, b"kill") && syscall::wait(child as i32) != 0, "kill the blocked 9P remover");
    syscall::close(ready);
    syscall::write_all(1, b"mount-mutations-ok\n");
    syscall::exit(0);
}

fn check_mount_parallel(disconnect: bool) -> ! {
    let paths = if disconnect {
        ["/tmp/drop9p/drop-one", "/tmp/drop9p/drop-two"]
    } else {
        ["/tmp/mnt9p/parallel-one", "/tmp/mnt9p/parallel-two"]
    };
    let run_pair = |paths: [&str; 2], cancel: bool, directory: bool| {
        let files = paths.map(cmd::open_read);
        check(files.iter().all(|fd| *fd >= 0), "open both multiplex test files");
        let mut children = [0; 2];
        for (index, child) in children.iter_mut().enumerate() {
            *child = syscall::fork();
            check(*child >= 0, "fork multiplex reader");
            if *child == 0 {
                if cancel && index == 0 {
                    check(syscall::notify(Some(note_handler)) == 0, "register multiplex alarm handler");
                    syscall::alarm(600);
                }
                let mut bytes = [0; 128];
                let count = syscall::read(files[index], bytes.as_mut_ptr(), bytes.len());
                if disconnect {
                    check(count == IO_ERROR,
                        "disconnected 9P wakes an outstanding reader with an I/O error");
                } else if cancel && index == 0 {
                    check(count == EINTR, "only the interrupted 9P request returns EINTR");
                } else if directory {
                    check(count > 0 && cmd::stat_name(&bytes[..count as usize]) == Some(&[b'1' + index as u8]),
                        "route 9P directory reply to its requesting process");
                } else {
                    check(count == 1 && bytes[0] == b'1' + index as u8, "route 9P reply to its requesting process");
                }
                syscall::exit(0);
            }
        }
        for child in children {
            check(syscall::wait(child as i32) == 0, "reap successful multiplex reader");
        }
        for fd in files {
            syscall::close(fd);
        }
    };
    run_pair(paths, false, false);
    if !disconnect {
        run_pair(["/tmp/mnt9p/dir-one", "/tmp/mnt9p/dir-two"], false, true);
        run_pair(["/tmp/mnt9p/cancel-one", "/tmp/mnt9p/cancel-two"], true, false);
        check_mount_shared_offset();
        check_mount_parallel_writes();
        check_mount_metadata();
        check_mount_path_metadata();
        check_mount_list();
        check_mount_clunk();
        check_mount_open();
        check_mount_killed_request();
    }
    syscall::write_all(1, if disconnect { b"mount-disconnect-ok\n" } else { b"mount-parallel-ok\n" });
    syscall::exit(0)
}

fn check_mount_metadata() {
    let [reader, writer, canceled] = ["/tmp/mnt9p/metadata-one", "/tmp/mnt9p/metadata-two", "/tmp/mnt9p/stat-cancel"]
        .map(cmd::open_read);
    check(reader >= 0 && writer >= 0 && canceled >= 0, "open metadata test files");
    let child = syscall::fork();
    check(child >= 0, "fork 9P metadata reader");
    if child == 0 {
        let mut output = [0; 128];
        let count = syscall::fstat(reader, &mut output);
        check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"metadata-one"),
            "route the delayed fstat response to its requesting process");
        syscall::exit(0);
    }
    let mut changes = [0xff; 49];
    changes[..2].copy_from_slice(&47u16.to_le_bytes());
    changes[21..25].copy_from_slice(&0o640u32.to_le_bytes());
    changes[41..].fill(0);
    check(syscall::fwstat(writer, &changes) == changes.len() as i64,
        "receive fwstat while another process has an fstat pending");
    check(syscall::wait(child as i32) == 0, "reap 9P metadata reader");

    let mut output = [0; 128];
    let count = syscall::fstat(writer, &mut output);
    check(count > 25 && u32::from_le_bytes(output[21..25].try_into().unwrap()) == 0o640,
        "read back the updated mode through fstat");
    check(syscall::notify(Some(note_handler)) == 0, "register metadata alarm handler");
    output.fill(0xa5);
    syscall::alarm(200);
    check(syscall::fstat(canceled, &mut output) == EINTR && output == [0xa5; 128],
        "cancel a delayed fstat without touching its output buffer");
    let count = syscall::fstat(canceled, &mut output);
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"stat-cancel"),
        "retry fstat on the same descriptor after cancellation");
    check(syscall::notify(None) == 0, "unregister metadata alarm handler");
    for fd in [reader, writer, canceled] {
        syscall::close(fd);
    }
}

fn check_mount_path_metadata() {
    let reader = b"/tmp/mnt9p/path-one\0";
    let writer = b"/tmp/mnt9p/path-two\0";
    let canceled = b"/tmp/mnt9p/path-cancel\0";
    let child = syscall::fork();
    check(child >= 0, "fork 9P path metadata reader");
    let mut output = [0; 128];
    if child == 0 {
        let count = syscall::stat(reader.as_ptr(), output.as_mut_ptr(), output.len());
        check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"path-one"),
            "route delayed path stat to its requesting process");
        syscall::exit(0);
    }
    let mut changes = [0xff; 49];
    changes[..2].copy_from_slice(&47u16.to_le_bytes());
    changes[21..25].copy_from_slice(&0o620u32.to_le_bytes());
    changes[41..].fill(0);
    check(syscall::wstat(writer.as_ptr(), &changes) == changes.len() as i64,
        "complete path wstat while another process has a path stat pending");
    check(syscall::wait(child as i32) == 0, "reap 9P path metadata reader");
    let count = syscall::stat(writer.as_ptr(), output.as_mut_ptr(), output.len());
    check(count > 25 && u32::from_le_bytes(output[21..25].try_into().unwrap()) == 0o620,
        "read back the updated mode through path stat");
    check(syscall::notify(Some(note_handler)) == 0, "register path metadata alarm handler");
    output.fill(0xa5);
    syscall::alarm(200);
    check(syscall::stat(canceled.as_ptr(), output.as_mut_ptr(), output.len()) == EINTR && output == [0xa5; 128],
        "cancel a delayed path stat without touching its output buffer");
    let count = syscall::stat(canceled.as_ptr(), output.as_mut_ptr(), output.len());
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"path-cancel"),
        "retry path stat after cancellation");
    check(syscall::notify(None) == 0, "unregister path metadata alarm handler");
}

fn check_mount_clunk() {
    for kill_closer in [false, true] {
        let [ready, reader] = ["/tmp/mnt9p/clunk-ready", "/tmp/mnt9p/clunk-read"].map(cmd::open_read);
        check(ready >= 0 && reader >= 0, "open clunk barrier files");
        let child = syscall::fork();
        check(child >= 0, "fork 9P closer");
        let mut byte = 0;
        if child == 0 {
            let closing = cmd::open_read("/tmp/mnt9p/clunk-hold");
            check(closing >= 0, "open fid only in its closing process");
            let duplicate = syscall::dup2(closing, 80);
            check(duplicate == 80 && syscall::close(closing) == 0, "close one of two descriptors");
            check(syscall::read(duplicate, &mut byte, 1) == 0, "duplicate still owns the fid");
            check(syscall::close(duplicate) == 0 && !kill_closer, "last close returns after Rclunk");
            syscall::exit(0);
        }
        check(syscall::read(ready, &mut byte, 1) == 1 && byte == b'c', "observe outstanding Tclunk");
        let status = open_proc(child, b"/status", syscall::OREAD);
        let mut record = [0; 176];
        check(status >= 0 && syscall::read(status, record.as_mut_ptr(), record.len()) == 176
            && &record[56..60] == b"Wait", "last close must still be waiting for Rclunk");
        syscall::close(status);
        if kill_closer {
            check(ctl(child, b"kill") && syscall::wait(child as i32) != 0, "kill the blocked 9P closer");
        }
        check(syscall::read(reader, &mut byte, 1) == 1 && byte == b'r',
            "read with a clunk still outstanding on the same connection");
        if !kill_closer {
            check(syscall::wait(child as i32) == 0, "reap 9P closer after Rclunk");
        }
        syscall::close(ready);
        syscall::close(reader);
    }
}

fn check_mount_list() {
    let child = syscall::fork();
    check(child >= 0, "fork 9P LIST reader");
    let mut names = [0xa5; 128];
    if child == 0 {
        let count = syscall::list(b"/tmp/mnt9p/list-one\0".as_ptr(), names.as_mut_ptr(), names.len());
        check(count == 11 && &names[..11] == b"one\nsecond\n", "read separate LIST batches in order");
        syscall::exit(0);
    }
    let count = syscall::list(b"/tmp/mnt9p/list-two\0".as_ptr(), names.as_mut_ptr(), names.len());
    check(count == 11 && &names[..11] == b"two\nsecond\n", "receive LIST while another LIST is pending");
    check(syscall::wait(child as i32) == 0, "reap 9P LIST reader");
    let delayed = b"/tmp/mnt9p/list-cancel\0";
    check(syscall::notify(Some(note_handler)) == 0, "register LIST alarm handler");
    names.fill(0xa5);
    syscall::alarm(200);
    let count = syscall::list(delayed.as_ptr(), names.as_mut_ptr(), names.len());
    check(count == 6 && &names[..6] == b"first\n" && names[6..] == [0xa5; 122],
        "interrupt LIST after one batch without overwriting the rest of the buffer");
    let count = syscall::list(delayed.as_ptr(), names.as_mut_ptr(), names.len());
    check(count == 13 && &names[..13] == b"first\nsecond\n", "reopen LIST after interruption");
    check(syscall::notify(None) == 0, "unregister LIST alarm handler");
}

fn check_mount_open() {
    let child = syscall::fork();
    check(child >= 0, "fork second 9P opener");
    let (path, expected) = if child == 0 { ("/tmp/mnt9p/open-one", b'1') } else { ("/tmp/mnt9p/open-two", b'2') };
    let fd = cmd::open_read(path);
    let mut byte = 0;
    check(fd >= 0 && syscall::read(fd, &mut byte, 1) == 1 && byte == expected,
        "route reordered Ropen to the right process and descriptor");
    syscall::close(fd);
    if child == 0 {
        syscall::exit(0);
    }
    check(syscall::wait(child as i32) == 0, "reap second 9P opener");

    let canceled = b"/tmp/mnt9p/open-cancel\0";
    check(syscall::notify(Some(note_handler)) == 0, "register open alarm handler");
    syscall::alarm(200);
    check(syscall::open(canceled.as_ptr(), syscall::OREAD) == EINTR, "interrupt outstanding Topen");
    let fd = syscall::open(canceled.as_ptr(), syscall::OREAD);
    check(fd >= 0 && syscall::read(fd, &mut byte, 1) == 1 && byte == b'o', "reopen after canceled Topen");
    syscall::close(fd);
    let walk = b"/tmp/mnt9p/walk-cancel\0";
    syscall::alarm(200);
    check(syscall::open(walk.as_ptr(), syscall::OREAD) == EINTR, "interrupt outstanding Twalk");
    let fd = syscall::open(walk.as_ptr(), syscall::OREAD);
    check(fd >= 0 && syscall::read(fd, &mut byte, 1) == 1 && byte == b'w', "open after canceled Twalk");
    syscall::close(fd);
    check(syscall::notify(None) == 0, "unregister open alarm handler");

    let [ready, done] = ["/tmp/mnt9p/open-kill-ready", "/tmp/mnt9p/open-kill-done"].map(cmd::open_read);
    check(ready >= 0 && done >= 0, "open Topen cancellation barriers");
    let child = syscall::fork();
    check(child >= 0, "fork Topen cancellation victim");
    if child == 0 {
        cmd::open_read("/tmp/mnt9p/open-kill");
        check(false, "killed 9P opener must not return to user mode");
        syscall::exit(1);
    }
    check(syscall::read(ready, &mut byte, 1) == 1 && byte == b'r', "wait for the victim's Topen");
    check(ctl(child, b"kill") && syscall::wait(child as i32) != 0, "kill the blocked 9P opener");
    check(syscall::read(done, &mut byte, 1) == 1 && byte == b'd', "keep the mount usable before Rflush");
    syscall::close(ready);
    syscall::close(done);
}

fn check_mount_killed_request() {
    let [victim, ready, done] = ["/tmp/mnt9p/killed", "/tmp/mnt9p/kill-ready", "/tmp/mnt9p/kill-done"]
        .map(cmd::open_read);
    check(victim >= 0 && ready >= 0 && done >= 0, "open 9P cancellation barrier files");
    let child = syscall::fork();
    check(child >= 0, "fork 9P cancellation victim");
    let mut byte = 0;
    if child == 0 {
        syscall::read(victim, &mut byte, 1);
        check(false, "killed 9P reader must not return to user mode");
        syscall::exit(1);
    }
    check(syscall::read(ready, &mut byte, 1) == 1 && byte == b'r', "wait for the victim's 9P request");
    check(ctl(child, b"kill") && syscall::wait(child as i32) != 0, "kill and reap blocked 9P reader");
    check(syscall::read(done, &mut byte, 1) == 1 && byte == b'd', "keep the mount usable after a blocked process dies");
    for fd in [victim, ready, done] {
        syscall::close(fd);
    }
}

fn check_mount_shared_offset() {
    let fd = cmd::open_read("/tmp/mnt9p/shared-offset");
    check(fd >= 0, "open shared 9P description");
    let duplicate = syscall::dup2(fd, 80);
    check(duplicate == 80, "duplicate shared 9P description");
    let mut children = [0; 2];
    for (child, reader) in children.iter_mut().zip([fd, duplicate]) {
        *child = syscall::fork();
        check(*child >= 0, "fork shared 9P reader");
        if *child == 0 {
            let mut byte = 0;
            check(syscall::read(reader, &mut byte, 1) == 1 && matches!(byte, b'1' | b'2'),
                "read one byte from the shared offset");
            syscall::exit(0);
        }
    }
    for child in children {
        check(syscall::wait(child as i32) == 0, "reap shared 9P reader");
    }
    let mut byte = 0;
    check(syscall::read(fd, &mut byte, 1) == 0, "shared 9P description reaches EOF");
    syscall::close(duplicate);
    syscall::close(fd);
}

fn check_mount_parallel_writes() {
    let paths = ["/tmp/mnt9p/write-one", "/tmp/mnt9p/write-two"];
    let files = paths.map(cmd::create_write);
    let messages: [&[u8]; 2] = [b"1", b"22"];
    check(files.iter().all(|fd| *fd >= 0), "create both multiplex write files");
    let mut children = [0; 2];
    for (index, child) in children.iter_mut().enumerate() {
        *child = syscall::fork();
        check(*child >= 0, "fork multiplex writer");
        if *child == 0 {
            let message = messages[index];
            check(syscall::write(files[index], message.as_ptr(), message.len()) == message.len() as i64,
                "route 9P write reply to its requesting process");
            syscall::exit(0);
        }
    }
    for child in children {
        check(syscall::wait(child as i32) == 0, "reap multiplex writer");
    }
    for ((path, writer), message) in paths.into_iter().zip(files).zip(messages) {
        syscall::close(writer);
        let reader = cmd::open_read(path);
        check(reader >= 0, "reopen multiplex write file");
        let mut bytes = [0; 4];
        check(syscall::read(reader, bytes.as_mut_ptr(), bytes.len()) == message.len() as i64
            && &bytes[..message.len()] == message, "read back multiplex write payload");
        syscall::close(reader);
    }
}

fn check_mount_union() -> ! {
    let mut output = [0; 1024];
    let srv = cmd::open_read("/srv");
    check(srv >= 0, "open srv directory");
    let count = syscall::read(srv, output.as_mut_ptr(), output.len());
    check(count > 0 && has_dir_entry(&output[..count as usize], b's', b"smoke9p"), "read binary srv directory");
    syscall::close(srv);

    let union = cmd::open_read("/tmp/mnt9p");
    check(union >= 0, "open local and remote union");
    check(syscall::read(union, output.as_mut_ptr(), 2) < 0, "union cannot split a stat record");
    let count = syscall::read(union, output.as_mut_ptr(), output.len());
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"local"), "read first union member");
    let [arm, release] = ["/tmp/mnt9p/union-arm", "/tmp/mnt9p/union-release"].map(cmd::open_read);
    let mut byte = 0;
    check(arm >= 0 && release >= 0 && syscall::read(arm, &mut byte, 1) == 1 && byte == b'a', "arm delayed union read");
    syscall::close(arm);
    let child = syscall::fork();
    check(child >= 0, "fork union reader");
    if child == 0 {
        let count = syscall::read(union, output.as_mut_ptr(), output.len());
        check(count > 0 && has_dir_entry(&output[..count as usize], b'M', b"remote"), "read remote union member");
        syscall::exit(0);
    }
    check(syscall::read(release, &mut byte, 1) == 1 && byte == b'r', "read with a union member outstanding");
    check(syscall::wait(child as i32) == 0, "reap union reader");
    syscall::close(release);
    check(syscall::seek(union, 0, 0) == 0, "rewind union");
    let count = syscall::read(union, output.as_mut_ptr(), output.len());
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"local"), "reread first union member");
    syscall::close(union);
    syscall::write_all(1, b"mount-union-ok\n");
    syscall::exit(0)
}

fn has_dir_entry(mut records: &[u8], device: u8, name: &[u8]) -> bool {
    while records.len() >= 2 {
        let length = u16::from_le_bytes([records[0], records[1]]) as usize + 2;
        let Some((record, remaining)) = records.split_at_checked(length) else { return false };
        if cmd::stat_name(record) == Some(name) && record.get(2) == Some(&device) {
            return true;
        }
        records = remaining;
    }
    false
}

fn check_orphan() {
    let mut ends = [-1; 2];
    check(syscall::pipe(&mut ends) == 0, "pipe for orphan");
    let [reader, writer] = ends;
    let pid = syscall::fork();
    check(pid >= 0, "fork orphan's parent");
    if pid == 0 {
        syscall::close(reader);
        let orphan = syscall::fork();
        check(orphan >= 0, "fork future orphan");
        if orphan != 0 {
            syscall::exit(0);
        }
        syscall::sleep_ms(30);
        syscall::write_all(writer, &syscall::getpid().to_le_bytes());
        syscall::exit(0);
    }
    syscall::close(writer);
    check(syscall::wait(pid as i32) == 0, "reap orphan's parent");
    let mut number = [0; 8];
    check(syscall::read(reader, number.as_mut_ptr(), number.len()) == number.len() as i64, "orphan survives parent exit");
    let orphan = i64::from_le_bytes(number);
    check(orphan > 0 && syscall::read(reader, number.as_mut_ptr(), number.len()) == 0, "orphan closes its descriptors");
    syscall::close(reader);
    check(!ctl(orphan, b"waitstop"), "orphan no longer exists in proc");
}

#[no_mangle]
pub extern "C" fn cmd_main(argc: u64, argv: u64) -> ! {
    match cmd::arg(argc as usize, argv as *const *const u8, 1) {
        Some("hang-again") => exec_self(b"hang-done\0"),
        Some("hang-done") => exec_self(b"exit\0"),
        Some("exit") => syscall::exit(0),
        Some("private-exec") => {
            check(ctl(syscall::getpid(), b"nohang"), "open own ctl after exec");
            syscall::exit(0);
        }
        Some("close-on-exec") => {
            check(syscall::dup2(70, 70) < 0 && syscall::dup2(71, 71) < 0
                && syscall::dup2(72, 72) == 72, "descriptor flags after exec");
            syscall::exit(0);
        }
        Some("mount-io") => check_mount_io(),
        Some("mount-mutations") => check_mount_mutations(),
        Some("mount-parallel") => check_mount_parallel(false),
        Some("mount-disconnect") => check_mount_parallel(true),
        Some("mount-union") => check_mount_union(),
        Some("crash-snapshot") => {
            check_broken_child(unmapped_load, b"sys: trap: fault read addr=", true);
            cmd::outln("crash snapshot verified");
            syscall::exit(0);
        }
        _ => {}
    }
    check_descriptors(0);
    check_descriptors(RFFDG);
    check_descriptors(RFCFDG);
    check_close_on_exec();
    check_await();
    check_proc_wait();
    check_registers();
    check_fpregs();
    check_text_execution();
    check_local_directories();
    check_saved_note();
    check_fault_notes();
    check_bad_syscall_buffers();
    check_async_notes();
    check_note_groups();
    check_waitstop_note();
    check_hang();
    check_profile();
    check_trace();
    check_process_memory();
    check_scheduling_controls();
    check_edf();
    check_edf_notes_and_extra();
    check_orphan();
    check_srv_close_on_exit();
    check_detached_children();
    check_private_exec();
    syscall::write_all(1, b"proc-smoke-ok\n");
    syscall::exit(0)
}

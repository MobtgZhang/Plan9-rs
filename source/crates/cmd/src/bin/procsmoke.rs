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

static SAVED_PC: AtomicU64 = AtomicU64::new(0);
static ASYNC_NOTES: AtomicU64 = AtomicU64::new(0);

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

    let pid = syscall::fork();
    check(pid >= 0, "fork faulting child");
    if pid == 0 {
        illegal_instruction();
        syscall::exit(0);
    }
    let mut record = [0; 256];
    let size = syscall::await_child(&mut record);
    check(size > 0 && record[..size as usize].windows(b"sys: trap: illegal instruction".len())
        .any(|part| part == b"sys: trap: illegal instruction"), "await unhandled fault");
    check(!ctl(pid, b"waitstop"), "reclaim faulting process");
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
    check(ctl(pid, b"start") && syscall::wait(pid as i32) == 0, "resume register target");
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
    syscall::alarm(200);
    let count = syscall::read(reader, output.as_mut_ptr(), output.len());
    check(count > 0 && cmd::stat_name(&output[..count as usize]) == Some(b"first"),
        "interrupted directory read reports completed entries");
    check(output[2..4] == [b'M', 0] && output[48..count as usize] == *b"\x05\0alice\x05\0staff\x06\0editor",
        "directory record preserves remote owner fields");
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
    let count = syscall::read(union, output.as_mut_ptr(), output.len());
    check(count > 0 && has_dir_entry(&output[..count as usize], b'M', b"remote"), "read remote union member");
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
        Some("mount-union") => check_mount_union(),
        _ => {}
    }
    check_descriptors(0);
    check_descriptors(RFFDG);
    check_descriptors(RFCFDG);
    check_close_on_exec();
    check_await();
    check_proc_wait();
    check_registers();
    check_local_directories();
    check_saved_note();
    check_fault_notes();
    check_async_notes();
    check_note_groups();
    check_waitstop_note();
    check_hang();
    check_profile();
    check_trace();
    check_process_memory();
    check_scheduling_controls();
    check_orphan();
    check_srv_close_on_exit();
    check_detached_children();
    check_private_exec();
    syscall::write_all(1, b"proc-smoke-ok\n");
    syscall::exit(0)
}

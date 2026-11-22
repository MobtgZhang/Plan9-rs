#!/usr/bin/env python3
"""Verify the GOP menu, kernel display and interactive shell in QEMU."""

import argparse
import json
import os
from pathlib import Path
from queue import Empty, Queue
import re
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor


PROMPT = re.compile(rb"(?:root|glenda)@plan9:[^\r\n]*> ")
COMMANDS = b"""
basename bind cat chmod chown clear cmp cp cut date dc diff dirname du echo ed env expr
false fortune grep group head hostname id ipconfig kill ln ls mkdir more mount mv netcat nl passwd ping printf
ps pwd rc rm rmdir seq sleep snoopy sort stat su tail tee test time touch tr traceroute true tty uname
uniq units unmount uptime useradd usermod wc who whoami yes
""".split()
HELP_FOOTER = b"redirection: < > >>    pipelines: cmd | cmd    lists: cmd ; cmd"
MENU_MARKER = b"bootloader: GOP menu"
FRAMEBUFFER_MARKER = b"bootloader: GOP linear framebuffer found"
INTERACTIVE_SELECTION = b"bootloader: selected Boot Plan 9 (verbose)"
UDP_HEADERS_READY = re.compile(rb"netcat: UDP headers ready\r?\n")


class SerialShell:
    def __init__(self, process, selector, log):
        self.process = process
        self.selector = selector
        self.log = log
        self.pending = b""
        selector.register(process.stdout, selectors.EVENT_READ)

    def read_prompt(self, timeout):
        return self.read_until(PROMPT, timeout, "serial shell prompt")

    def read_until(self, pattern, timeout, description):
        deadline = time.monotonic() + timeout
        while True:
            match = pattern.search(self.pending)
            if match:
                output = self.pending[:match.start()]
                self.pending = self.pending[match.end():]
                return output.replace(b"\r\n", b"\n")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise TimeoutError(f"{description} not received")
            chunk = os.read(self.process.stdout.fileno(), 8192)
            if not chunk:
                raise RuntimeError("QEMU exited before returning a shell prompt")
            self.log.write(chunk)
            self.pending += chunk

    def send(self, command):
        self.process.stdin.write(command + b"\r")
        self.process.stdin.flush()

    def command(self, command):
        self.send(command)
        return self.read_prompt(25)


class Qmp:
    def __init__(self, sock):
        self.socket = sock
        self.stream = sock.makefile("rb")
        greeting = self.receive()
        if "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting}")
        self.call("qmp_capabilities")

    def receive(self):
        line = self.stream.readline()
        if not line:
            raise RuntimeError("QEMU closed QMP")
        return json.loads(line)

    def call(self, operation, **arguments):
        request = {"execute": operation, "arguments": arguments}
        self.socket.sendall(json.dumps(request).encode() + b"\n")
        while True:
            reply = self.receive()
            if "error" in reply:
                raise RuntimeError(f"QMP {operation}: {reply['error']}")
            if "return" in reply:
                return reply["return"]

    def key(self, key):
        self.call("send-key", keys=[{"type": "qcode", "data": key}], **{"hold-time": 45})
        time.sleep(0.09)

    def capture(self, path, matches, description, timeout):
        deadline = time.monotonic() + timeout
        while True:
            self.call("screendump", filename=str(path))
            raw = path.read_bytes()
            magic, dimensions, maximum, pixels = raw.split(b"\n", 3)
            if magic != b"P6" or maximum != b"255":
                raise RuntimeError(f"unexpected QEMU screendump format: {path}")
            width, height = map(int, dimensions.split())
            if len(pixels) == width * height * 3 and matches(pixels):
                return pixels
            if time.monotonic() >= deadline:
                raise TimeoutError(f"expected {description} on the display; see {path}")
            time.sleep(0.08)


def connect_qmp(sock, path, process):
    deadline = time.monotonic() + 5
    sock.settimeout(5)
    while True:
        try:
            sock.connect(str(path))
            return
        except (FileNotFoundError, ConnectionRefusedError):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("QEMU did not open its QMP socket") from None
            time.sleep(0.02)


def check_help(output):
    header = b"builtins: . builtin cd eval exec exit flag help rfork shift wait whatis\n\ncommands:\n"
    _, found_header, listing = output.partition(header)
    commands, found_footer, _ = listing.partition(HELP_FOOTER)
    if not found_header or not found_footer or commands.split() != COMMANDS or b"\0" in output:
        raise RuntimeError(f"unexpected help output: {output!r}")


def check_boot(arch, shell, qmp, output_dir):
    shell.read_until(re.compile(MENU_MARKER), 90, "UEFI GOP menu")
    qmp.capture(output_dir / "smoke-menu.ppm",
                lambda pixels: pixels.startswith(bytes((6, 13, 43)))
                and pixels.count(bytes((42, 74, 168))) > 1000
                and pixels.endswith(bytes((5, 9, 30))), "GOP boot menu", 3)
    qmp.key("down")
    qmp.key("ret")

    boot = shell.read_prompt(45)
    if INTERACTIVE_SELECTION not in boot:
        raise RuntimeError("UEFI menu did not accept Down and Enter from the display keyboard")
    if FRAMEBUFFER_MARKER not in boot or b"[console] cols=" not in boot:
        raise RuntimeError("kernel did not initialize the graphical console from the firmware framebuffer")

    def shows_console(pixels):
        return pixels.count(b"\x00\x00\x00") > len(pixels) // 6 and pixels.count(b"\xcc\xcc\xcc") > 100

    before = qmp.capture(output_dir / "smoke-shell.ppm", shows_console, "kernel console", 5)
    for key in ("u", "n", "a", "m", "e", "ret"):
        qmp.key(key)
    identity = f"Plan9 plan9rs 1.0 {arch}".encode()
    if identity not in shell.read_prompt(25).splitlines():
        raise RuntimeError("uname did not identify the requested architecture")
    uname = qmp.capture(output_dir / "smoke-uname.ppm",
                        lambda pixels: shows_console(pixels) and pixels != before,
                        "kernel uname output", 5)

    for key in ("h", "e", "l", "p", "ret"):
        qmp.key(key)
    check_help(shell.read_prompt(25))
    qmp.capture(output_dir / "smoke-help.ppm",
                lambda pixels: shows_console(pixels) and pixels != uname, "kernel help output", 5)

    if b"plan9-smoke bookkeeper" not in shell.command(b"echo plan9-smoke bookkeeper").splitlines():
        raise RuntimeError("echo did not preserve spaces and repeated characters")
    check_system_files(shell, arch)
    check_rc_and_processes(shell)


def check_rc_and_processes(shell):
    def expect(command, expected):
        output = shell.command(command).partition(b"\n")[2].splitlines()
        if expected not in output:
            raise RuntimeError(f"{command!r}: expected {expected!r}, got {output!r}")
        return output

    expect(b"false && echo wrong || echo conditional", b"conditional")
    expect(b"fn greet { echo $1 }; greet hello", b"hello")
    expect(b"fn echo { builtin echo shadow }; echo; builtin echo original; fn echo", b"original")
    expect(b"rc -c 'greet inherited'", b"inherited")
    expect(b"fn greet; rc -c 'whatis greet' || echo function-removed", b"function-removed")
    expect(b"values=(one two three); var=values; echo $$var; echo $#values; echo $values(2-3)", b"two three")
    expect(b"item=outside; for (item in inside) echo $item; echo after-$item", b"after-outside")
    expect(b"mkdir /tmp/rc-glob-assign; touch /tmp/rc-glob-assign/one /tmp/rc-glob-assign/two; "
           b"files=/tmp/rc-glob-assign/*; echo count-$#files", b"count-2")
    expect(b"echo $(values)(0 3 2- 99 wrong)", b"three two three")
    expect(b"~ (one two) 'one two' && ! ~ (one two) one && echo match-list", b"match-list")
    expect(b"switch (one two) { case 'one two'; echo switch-list }", b"switch-list")
    expect("~ '甲' ? && ~ '乙' [甲乙] && ~ 'b' [c-a] && echo rune-match".encode(), b"rune-match")
    expect(b"env*name=expanded; echo $env*name", b"expanded")
    expect(b"rc -c 'false; while () { echo empty-while; exit }'", b"empty-while")
    expect(b"flag x -; flag x || echo flag-off", b"flag-off")
    expect(b"rc -e -c 'false || echo tested; ! true; echo survived'", b"survived")
    output = expect(b"rc -e -c 'false; echo wrong' || echo errexit", b"errexit")
    if output != [b"errexit"]:
        raise RuntimeError(f"unexpected errexit output: {output!r}")
    for failure in (b"~ miss match", b"@ false"):
        output = expect(b"rc -e -c '" + failure + b"; echo wrong' || echo errexit", b"errexit")
        if output != [b"errexit"]:
            raise RuntimeError(f"unexpected errexit output for {failure!r}: {output!r}")
    expect(b"value=outer; value=inner echo pipe | { cat; echo $value }; echo $value", b"inner")
    expect(b"value=prefix >/tmp/rc-assigned if (true) echo $value; cat /tmp/rc-assigned", b"prefix")
    expect(b"echo 'echo stdin-script' | rc -I", b"stdin-script")
    output = expect(b"printf 'if (false)\\n echo wrong\\nif not\\n echo continued\\n"
                    b"echo piped |\\n cat\\n' | rc -I", b"continued")
    if output != [b"continued", b"piped"]:
        raise RuntimeError(f"unexpected multiline rc output: {output!r}")
    output = expect(b"printf 'echo early-exit\\nexit\\n}\\n' | rc -I", b"early-exit")
    if output != [b"early-exit"]:
        raise RuntimeError(f"rc parsed past exit: {output!r}")
    expect(b"printf 'echo no-final-newline' | rc -I", b"no-final-newline")
    expect(b"echo '#!/bin/rc -I' > /tmp/rc-exec; echo 'echo executed $0 $*' >> /tmp/rc-exec; "
           b"chmod 755 /tmp/rc-exec && /tmp/rc-exec one two", b"executed /tmp/rc-exec one two")
    expect(b" >/tmp/rc-prefix if (true) echo prefix; cat /tmp/rc-prefix", b"prefix")
    expect(b"echo `{echo command-substitution}", b"command-substitution")
    expect(b"rc -c 'fn sigexit { echo exit-trap }; exit'", b"exit-trap")
    expect(b"rc -c 'exit ''custom status'''; echo $status", b"custom status")
    expect(b"rc -c 'exit left' | rc -c 'exit right'; echo $status", b"left|right")
    output = expect(b"pipeline_local=before; { pipeline_local=left; echo data } | { cat; echo $pipeline_local; pipeline_local=right }; echo $pipeline_local", b"right")
    if output != [b"data", b"before", b"right"]:
        raise RuntimeError(f"unexpected pipeline scope: {output!r}")
    expect(b"{ exit background-status } & wait $apid; echo $status", b"background-status")
    expect(b"cat <{echo pipe-file}", b"pipe-file")
    expect(b"cat < {echo spaced-pipe-file}", b"spaced-pipe-file")
    expect(b"echo output-file | tee >{cat > /tmp/pipe-file}; "
           b"for (try in `{seq 1 10}) { if (test -f /tmp/pipe-file) cat /tmp/pipe-file }", b"output-file")
    expect(b"seq 1 3000 | wc -l", b"3000")
    expect(b"echo redirected > /tmp/rc-redir; echo restored; cat /tmp/rc-redir", b"redirected")
    shell.command(b"echo 'cat <<EOF; echo tail' > /tmp/rc-here")
    shell.command(b"echo here-document >> /tmp/rc-here; echo EOF >> /tmp/rc-here")
    expect(b"rc /tmp/rc-here", b"here-document")
    shell.command("echo '变量*名=(here text); cat <<EOF; cat <<''RAW''' > /tmp/rc-here".encode())
    shell.command("echo '$变量*名^! $$ $1^arg $!' >> /tmp/rc-here; echo EOF >> /tmp/rc-here; "
                  "echo '$变量*名^! $$ $1^arg $!' >> /tmp/rc-here; echo RAW >> /tmp/rc-here".encode())
    output = expect(b"rc /tmp/rc-here first", b"here text! $ firstarg !")
    if output != [b"here text! $ firstarg !", "$变量*名^! $$ $1^arg $!".encode()]:
        raise RuntimeError(f"unexpected here-document expansion: {output!r}")
    expect(b"{ echo background } & wait", b"background")
    expect(b"{ while (! test -f /tmp/ctl-done) true } & p=$apid; "
           b"echo stop > /proc/$p/ctl && echo waitstop > /proc/$p/ctl && echo startsyscall > /proc/$p/ctl && "
           b"echo startstop > /proc/$p/ctl && "
           b"echo start > /proc/$p/ctl && touch /tmp/ctl-done && wait $p && echo ctl-ok", b"ctl-ok")
    shell.command(b"{ while (true) true } & p=$apid; echo stop > /proc/$p/ctl")
    expect(b"echo 'close 0' > /proc/$p/ctl && echo close-ok", b"close-ok")
    expect(b"echo closefiles > /proc/$p/ctl && echo closefiles-ok", b"closefiles-ok")
    output = expect(b"{ echo private >[1=3] && { cat /proc/$p/mem || echo private-mem-ok }; "
                    b"echo start > /proc/$p/ctl || echo private-ctl-ok; "
                    b"echo kill >[1=3] } >[3] /proc/$p/ctl; wait $p; echo $status", b"killed")
    if not {b"private-mem-ok", b"private-ctl-ok"}.issubset(output):
        raise RuntimeError(f"private process allowed a new open: {output!r}")
    expect(b"{ sleep 1 } & p=$apid; echo waitstop > /proc/$p/ctl || echo waitstop-exit; wait $p", b"waitstop-exit")
    expect(b"/bin/aux/procsmoke", b"proc-smoke-ok")
    shell.command(b"fn sigint { echo interrupt-note }; fn sigterm { echo term-note }")
    shell.command(b"{ while (! test -f /tmp/note-done) true } & p=$apid; echo stop > /proc/$p/ctl")
    output = expect(b"echo interrupt > /proc/$p/note && echo term > /proc/$p/notepg && "
                    b"echo start > /proc/$p/ctl && touch /tmp/note-done && wait $p && echo notes-ok", b"notes-ok")
    if output != [b"interrupt-note", b"term-note", b"notes-ok"]:
        raise RuntimeError(f"note delivery or resume failed: {output!r}")
    shell.command(b"fn sigint sigterm")
    output = expect(b"for (i in `{seq 1 270}) { true || echo failed-$i }; echo reaped", b"reaped")
    if output != [b"reaped"]:
        raise RuntimeError(f"child execution or reclamation failed: {output!r}")
    expect(b"mkdir /tmp/union /tmp/first /tmp/last; echo base > /tmp/union/item; "
           b"echo first > /tmp/first/item; echo last > /tmp/last/item; "
           b"bind -a /tmp/last /tmp/union && bind -bc /tmp/first /tmp/union && "
           b"cat /tmp/union/item && echo created > /tmp/union/new && cat /tmp/first/new", b"created")
    expect(b"cat /tmp/union/item", b"first")
    expect(b"@ { rfork N && cat /tmp/union/item }; cat /tmp/union/item", b"base")
    expect(b"unmount /tmp/first /tmp/union && cat /tmp/union/item", b"base")


def check_system_files(shell, arch):
    def lines(command):
        return shell.command(command).partition(b"\n")[2].splitlines()

    def expect(command, expected):
        output = lines(command)
        if expected not in output:
            raise RuntimeError(f"{command!r}: expected {expected!r}, got {output!r}")

    expect(b"pwd", b"/usr/root")
    for device in (b"console", b"cons", b"null", b"zero", b"sd", b"pipe"):
        expect(b"ls /dev", b"/dev/" + device)
    expect(b"cd /dev; ls -l cons", b"-666 0 cons")
    expect(b"ls -l null", b"-666 0 null")
    expect(b"cd /proc/1; ls", b"./status")
    status = shell.command(b"cat status").partition(b"\n")[2].splitlines()
    if not any(len(line) == 176 and line[:27].strip() == b"init" and line[28:55].strip() == b"root"
               for line in status):
        raise RuntimeError(f"unexpected Plan 9 init status: {status!r}")
    expect(b"cd ..; pwd", b"/proc")
    pids = lines(b"ls")
    if b"./1" not in pids or not any(line.startswith(b"./") and line[2:].isdigit()
                                     and int(line[2:]) > 1 for line in pids):
        raise RuntimeError(f"/proc did not list init and other processes: {pids!r}")
    processes = lines(b"ps")
    if not any(line.endswith(b" init") for line in processes) or not any(line.endswith(b" rc") for line in processes):
        raise RuntimeError(f"ps did not identify init and rc: {processes!r}")
    if any(b" Dead " in line for line in processes):
        raise RuntimeError(f"ps listed exited commands: {processes!r}")
    expect(b"cd ..; pwd", b"/")

    expect(b"cat /rc/lib/rcmain", b". /rc/bin/termrc")
    expect(b"cat $home/lib/profile", b"path=(. /bin)")
    if any(entry in lines(b"ls /etc") for entry in (b"/etc/profile", b"/etc/profile.d")):
        raise RuntimeError("Unix login profiles were unexpectedly installed")
    initial_env = lines(b"env")
    expected_env = {b"path=. /bin", b"user=root", b"home=/usr/root",
                    b"service=terminal", b"sysname=plan9"}
    if not expected_env.issubset(initial_env):
        raise RuntimeError(f"unexpected login environment: {initial_env!r}")
    expect(b"wc -c /env/path", b"7 /env/path")
    cputype = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch).encode()
    expect(b"echo $cputype $objtype", cputype + b" " + cputype)
    if cputype not in lines(b"cat '#ec/cputype'"):
        raise RuntimeError("#ec did not report the kernel architecture")
    lines(b"echo shared-config > '#ec/smoke'")
    if b"/env/smoke" in lines(b"ls /env"):
        raise RuntimeError("#ec leaked into the per-process environment")
    expect(b"sample=('two words' three); printf '<%s><%s>\\n' $sample", b"<two words><three>")
    expect(b"SMOKE_ENV='parent value'; echo $SMOKE_ENV", b"parent value")
    expect(b"echo shared > /env/SMOKE_ENV; cat /env/SMOKE_ENV", b"shared")
    lines(b"echo 'rfork e; echo $SMOKE_ENV; SMOKE_ENV=private; echo $SMOKE_ENV' > /tmp/env-test")
    output = [line for line in lines(b"rc /tmp/env-test") if line]
    if output != [b"shared", b"private"]:
        raise RuntimeError(f"copied environment test failed: {output!r}")
    expect(b"cat /env/SMOKE_ENV", b"shared")
    lines(b"echo 'rfork E; /bin/ls /env' > /tmp/env-test")
    if lines(b"rc /tmp/env-test"):
        raise RuntimeError("rfork E did not start with an empty /env")

    lines(b"cp /bin/echo /tmp/profile-echo; cp $home/lib/profile /tmp/profile.backup")
    lines(b"echo 'path=(/tmp /bin); service=custom; profile-echo profile-ran' > $home/lib/profile")
    output = lines(b"exit")
    if b"[init] rc exited with status 0" not in output or b"profile-ran" not in output:
        raise RuntimeError(f"restart did not run the account profile: {output!r}")
    expect(b"echo $service", b"custom")
    expect(b"profile-echo path-search", b"path-search")
    if b"SMOKE_ENV=shared" in lines(b"env"):
        raise RuntimeError("the previous login environment survived the shell restart")
    lines(b"cp /tmp/profile.backup $home/lib/profile")
    expect(b"exit", b"[init] rc exited with status 0")
    expect(b"echo $service", b"terminal")
    expect(b"echo $path", b". /bin")
    lines(b"su glenda")
    expect(b"echo $user $home", b"glenda /usr/glenda")
    expect(b"echo $cputype $objtype", cputype + b" " + cputype)
    expect(b"pwd", b"/usr/glenda")
    expect(b"cat '#ec/smoke'", b"shared-config")
    expect(b"echo forbidden > '#ec/smoke'", b"rc: can't open > file")
    lines(b"echo 'login=glenda' > $home/lib/profile")
    expect(b". $home/lib/profile; echo $login", b"glenda")
    lines(b"exit")
    expect(b"echo $user $home", b"root /usr/root")
    check_help(shell.command(b"help"))


def serve_9p(listener, factotum=False):
    def string(value):
        return struct.pack("<H", len(value)) + value

    def qid(name):
        kind = 0x80 if name in (b"", b"listing") else 0x08 if name == b"@auth" else 0
        path = 3 if name == b"listing" else 2 if name else 1
        return struct.pack("<BIQ", kind, 0, path)

    def stat(name, content):
        mode = modes.get(name, 0o666)
        if name in (b"", b"listing"):
            mode |= 0x80000000
        fields = (struct.pack("<HI", 0, 0) + qid(name)
                  + struct.pack("<IIIQ", mode, 0, 0, len(content))
                  + b"".join(map(string, (name, b"alice", b"staff", b"editor"))))
        return string(fields)

    files = {b"rpc": bytearray()} if factotum else {
        b"remote": bytearray(b"hello-9p\n"), b"flush": bytearray(b"after-flush\n"),
        b"flush-race": bytearray(b"completed\n"), b"listing": bytearray(),
    }
    modes = {}
    fids = {}
    requests = []
    auth_success = set()
    rpc_requests = iter((
        (b"start proto=p9any role=client user=root", b"ok"),
        (b"read", b"phase"),
        (b"write ", b"toosmall 9"),
        (b"write challenge", b"ok"),
        (b"read", b"ok response"),
        (b"read", b"done"),
        (b"authinfo", b"ok " + b"".join(map(string, (b"root", b"test", b"", b"secret")))),
    ))
    rpc_reply = b""
    canceled = None
    flushed = set()
    with listener.accept()[0] as connection:
        connection.settimeout(25)
        with connection.makefile("rb") as reader:
            while header := reader.read(7):
                size, kind, tag = struct.unpack("<IBH", header)
                body = reader.read(size - 7)
                requests.append(kind)
                reply = kind + 1
                payload = b""
                if kind == 100:
                    if requests.count(100) != 1:
                        raise RuntimeError("renegotiated version with live fids")
                    payload = body
                elif kind == 102 and not factotum:
                    fid = struct.unpack_from("<I", body)[0]
                    if body[4:] != string(b"root") + string(b"test-tree"):
                        raise RuntimeError(f"invalid auth request {body!r}")
                    fids[fid] = b"@auth"
                    payload = qid(b"@auth")
                elif kind == 104:
                    fid, auth = struct.unpack_from("<II", body)
                    if factotum and auth != 0xFFFFFFFF or not factotum and auth not in auth_success:
                        raise RuntimeError(f"invalid 9P attach auth fid {auth}")
                    fids[fid] = b""
                    payload = qid(b"")
                elif kind == 108:
                    if canceled is None or body != struct.pack("<H", canceled[0]):
                        raise RuntimeError(f"unexpected 9P flush {body!r}")
                    flushed.add(canceled[1])
                    if canceled[2]:
                        connection.sendall(canceled[2])
                    canceled = None
                elif kind == 110:
                    fid, newfid, count = struct.unpack_from("<IIH", body)
                    name = body[12:] if count else fids[fid]
                    if count and (fids[fid] or name not in files):
                        payload = b"\x00\x00"
                    else:
                        fids[newfid] = name
                        payload = struct.pack("<H", count) + (qid(name) if count else b"")
                elif kind == 112:
                    name = fids[struct.unpack_from("<I", body)[0]]
                    payload = qid(name) + struct.pack("<I", 64 if name == b"chunked" else 0)
                elif kind == 114:
                    fid, length = struct.unpack_from("<IH", body)
                    name = body[6:6 + length]
                    files[name] = bytearray()
                    fids[fid] = name
                    payload = qid(name) + struct.pack("<I", 64 if name == b"chunked" else 0)
                elif kind in (116, 118):
                    fid, offset, count = struct.unpack_from("<IQI", body)
                    name = fids[fid]
                    if name == b"chunked" and count > 64:
                        raise RuntimeError(f"request exceeds iounit: {count}")
                    if kind == 116:
                        if name in (b"flush", b"flush-race") and name not in flushed:
                            partial = b""
                            if name == b"flush-race":
                                data = files[name]
                                complete = struct.pack("<IBHI", 11 + len(data), 117, tag, len(data)) + data
                                connection.sendall(complete[:3])
                                partial = complete[3:]
                            canceled = (tag, name, partial)
                            continue
                        if name == b"listing":
                            first = stat(b"first", b"")
                            if offset == 0:
                                data = first
                            elif offset == len(first) and name not in flushed:
                                canceled = (tag, name, b"")
                                continue
                            elif offset == len(first):
                                data = stat(b"second", b"")
                            elif offset == len(first) + len(stat(b"second", b"")):
                                data = b""
                            else:
                                raise RuntimeError(f"unexpected directory offset {offset}")
                        elif name == b"rpc":
                            data, rpc_reply = rpc_reply, b""
                        else:
                            data = (b"challenge" if name == b"@auth" else files[name] if name else
                                    b"".join(stat(key, value) for key, value in files.items()))
                            data = data[offset:offset + count]
                        payload = struct.pack("<I", len(data)) + data
                    else:
                        if name == b"rpc":
                            expected, rpc_reply = next(rpc_requests, (None, None))
                            if body[16:] != expected:
                                raise RuntimeError(f"expected factotum RPC {expected!r}, got {body[16:]!r}")
                        elif name == b"@auth":
                            if offset != 9 or body[16:] != b"response":
                                raise RuntimeError(f"invalid auth reply {body!r}")
                            auth_success.add(fid)
                        else:
                            files[name][offset:offset + count] = body[16:]
                        payload = struct.pack("<I", count)
                elif kind in (120, 122):
                    name = fids.pop(struct.unpack_from("<I", body)[0])
                    if kind == 122:
                        del files[name]
                elif kind == 124:
                    name = fids[struct.unpack_from("<I", body)[0]]
                    payload = string(stat(name, files.get(name, b"")))
                elif kind == 126:
                    name = fids[struct.unpack_from("<I", body)[0]]
                    mode, _, _, length = struct.unpack_from("<IIIQ", body, 27)
                    if mode != 0xFFFFFFFF:
                        modes[name] = mode
                    if length != 0xFFFFFFFFFFFFFFFF:
                        del files[name][length:]
                else:
                    raise RuntimeError(f"unexpected 9P request {kind}")
                connection.sendall(struct.pack("<IBH", len(payload) + 7, reply, tag) + payload)
    required = {100, 104, 110, 112, 116, 118, 120}
    if not factotum:
        required.update({102, 108, 114, 122, 124, 126})
    if (fids or not required.issubset(requests) or not factotum
            and (modes.get(b"new") != 0o600 or flushed != {b"flush", b"flush-race", b"listing"})):
        raise RuntimeError(f"incomplete 9P exchange, live fids {fids}, requests {requests}")


def check_9p_mount(shell):
    def expect(command, expected):
        output = shell.command(command).partition(b"\n")[2]
        if expected not in output.splitlines():
            raise RuntimeError(f"{command!r}: expected {expected!r}, got {output!r}")

    def publish(listener, name):
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        port = str(listener.getsockname()[1]).encode()
        service = b"/srv/" + name
        expect(b"{ id=`{cat <[0=8]}; echo 'connect 10.0.2.2!" + port
               + b"' >[1=8] && { echo 9 > " + service + b" } <>[9]/net/tcp/$id/data } "
               b"<>[8]/net/tcp/clone; ls /srv", service)

    with socket.socket() as listener, socket.socket() as agent, ThreadPoolExecutor(max_workers=2) as workers:
        publish(agent, b"smokefactotum")
        factotum = workers.submit(serve_9p, agent, True)
        expect(b"mkdir /mnt/factotum; @ { cd /srv && mount -n ./smokefactotum /mnt/factotum } && echo factotum-mounted",
               b"factotum-mounted")
        expect(b"mkdir /tmp/mnt-factotum; @ { rfork nm && { mount -n smokefactotum /tmp/mnt-factotum || echo mount-blocked } }",
               b"mount-blocked")
        expect(b"mount -n smokefactotum /tmp/mnt-factotum && unmount /tmp/mnt-factotum && cat /mnt/factotum/rpc && echo session-reused",
               b"session-reused")
        publish(listener, b"smoke9p")
        expect(b"chmod 600 /srv/smoke9p && ls -l /srv/smoke9p", b"-600 0 /srv/smoke9p")
        peer = workers.submit(serve_9p, listener)
        expect(b"mkdir /tmp/mnt9p; mount -k 'user=root' smoke9p /tmp/mnt9p test-tree && ls /tmp/mnt9p", b"/tmp/mnt9p/remote")
        expect(b"cat /tmp/mnt9p/remote", b"hello-9p")
        expect(b"echo /tmp/mnt9p/rem*", b"/tmp/mnt9p/remote")
        expect(b"/bin/aux/procsmoke mount-io", b"mount-io-ok")
        expect(b"mkdir /tmp/local9p; touch /tmp/local9p/local; bind -b /tmp/local9p /tmp/mnt9p && "
               b"/bin/aux/procsmoke mount-union", b"mount-union-ok")
        expect(b"unmount /tmp/local9p /tmp/mnt9p && echo union-unmounted", b"union-unmounted")
        expect(b"echo from-client > /tmp/mnt9p/new; cat /tmp/mnt9p/new", b"from-client")
        expect(b"chmod 600 /tmp/mnt9p/new && rm /tmp/mnt9p/new && echo remote-wstat-remove", b"remote-wstat-remove")
        expect(b"{ unmount /srv/smoke9p /tmp/mnt9p; cat } < /tmp/mnt9p/remote", b"hello-9p")
        expect(b"rm /srv/smoke9p && echo service-removed", b"service-removed")
        peer.result(timeout=10)
        expect(b"unmount /mnt/factotum && rm /srv/smokefactotum && echo factotum-removed", b"factotum-removed")
        factotum.result(timeout=10)


def wait_for_dhcp(shell):
    deadline = time.monotonic() + 12
    while b"10.0.2.15/24" not in shell.command(b"ip/ipconfig"):
        if time.monotonic() >= deadline:
            raise RuntimeError("DHCP did not configure 10.0.2.15/24")
        time.sleep(0.1)
    if b"10.0.2.2" not in shell.command(b"ipconfig routes"):
        raise RuntimeError("DHCP did not install the IPv4 default route")


def check_network(shell, qmp):
    wait_for_dhcp(shell)
    check_9p_mount(shell)
    for command, expected in (
        (b"cat /net/ether0/addr", b"525400123456"),
        (b"ls /net", b"esp"),
        (b"ndb/dnsquery localhost", b"localhost ip 127.0.0.1"),
        (b"ndb/csquery tcp!127.0.0.1!http", b"/net/tcp/clone 127.0.0.1!80"),
        (b"echo 'sys=net-local ip=127.0.0.1' > /net/ndb; ping -n 1 net-local", b"reply from 127.0.0.1"),
        (b"echo 'tcp=plan9-test port=8123' > /net/ndb; ndb/csquery tcp!127.0.0.1!plan9-test", b"/net/tcp/clone 127.0.0.1!8123"),
        (b"ip/traceroute -6 -a 1 -t 1 ::1", b"  1  ::1 "),
    ):
        output = shell.command(command).partition(b"\n")[2]
        if expected not in output:
            raise RuntimeError(f"{command!r} failed: {output!r}")
    for address in (b"127.0.0.1", b"::1", b"10.0.2.2", b"fec0::2"):
        family = b"-6 " if b":" in address else b""
        output = shell.command(b"ip/ping " + family + b"-n 1 " + address)
        if b"reply from " + address not in output or b"1 sent, 1 received" not in output:
            raise RuntimeError(f"ping {address.decode()} failed: {output!r}")
    output = shell.command(b"ping -q -i 20 -c 2 127.0.0.1")
    if b"2 sent, 2 received" not in output or b"reply from" in output:
        raise RuntimeError(f"repeated ping failed: {output!r}")

    def echo(server, stream):
        if stream:
            with server.accept()[0] as client:
                client.settimeout(10)
                with client.makefile("rb") as reader:
                    client.sendall(b"echo:" + reader.read(len(b"plan9-net")))
        else:
            message, peer = server.recvfrom(128)
            server.sendto(b"echo:" + message, peer)

    for stream in (True, False):
        protocol = "TCP" if stream else "UDP"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if stream else socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(10)
            if stream:
                server.listen(1)
            option = b"" if stream else b"-u "
            port = str(server.getsockname()[1]).encode()
            with ThreadPoolExecutor(max_workers=1) as workers:
                reply = workers.submit(echo, server, stream)
                output = shell.command(b"netcat " + option + b"-m plan9-net 10.0.2.2 " + port)
                if b"echo:plan9-net" not in output:
                    raise RuntimeError(f"{protocol} echo failed: {output!r}")
                reply.result()

    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    result = qmp.call("human-monitor-command", **{
        "command-line": f"hostfwd_add net0 tcp:127.0.0.1:{port}-:8123",
    })
    if result.strip():
        raise RuntimeError(result.strip())
    shell.send(b"netcat -l -m accepted * 8123")
    deadline = time.monotonic() + 4
    data = b""
    while not data and time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                client.sendall(b"incoming")
                with client.makefile("rb") as reader:
                    data = reader.read(len(b"accepted"))
        except (ConnectionError, TimeoutError):
            time.sleep(0.05)
    if data != b"accepted" or b"incoming" not in shell.read_prompt(25):
        raise RuntimeError(f"TCP listen failed: {data!r}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    result = qmp.call("human-monitor-command", **{
        "command-line": f"hostfwd_add net0 udp:127.0.0.1:{port}-:8124",
    })
    if result.strip():
        raise RuntimeError(result.strip())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
        for client, message in ((first, b"udp-first"), (second, b"udp-second")):
            shell.send(b"netcat -u -l -m datagram * 8124")
            client.settimeout(0.15)
            deadline = time.monotonic() + 4
            data = b""
            while time.monotonic() < deadline:
                client.sendto(message, ("127.0.0.1", port))
                try:
                    data, _ = client.recvfrom(128)
                    break
                except TimeoutError:
                    pass
            output = shell.read_prompt(25).partition(b"\n")[2]
            if data != b"datagram" or output.strip() != message:
                raise RuntimeError(f"UDP listen or port reuse failed: {data!r}, {output!r}")
        shell.send(b"netcat -u -l -H -n 2 * 8124")
        shell.read_until(UDP_HEADERS_READY, 10, "UDP headers listener")
        datagrams = ((first, b"header-first"), (second, b"header-second"))
        for client, message in datagrams:
            client.settimeout(5)
            client.sendto(message, ("127.0.0.1", port))
        for client, message in datagrams:
            reply, _ = client.recvfrom(128)
            if reply != message:
                raise RuntimeError(f"UDP headers reply for {message!r}: {reply!r}")
        output = shell.read_prompt(25)
        if output not in (b"header-firstheader-second", b"header-secondheader-first"):
            raise RuntimeError(f"UDP headers listener output: {output!r}")

    shell.send(b"snoopy -n 1 -t 0x0800 ether0")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        for _ in range(5):
            client.sendto(b"capture", ("127.0.0.1", port))
            time.sleep(0.1)
    output = shell.read_prompt(25)
    if b"IPv4 0x0800" not in output or b"proto=17" not in output:
        raise RuntimeError(f"snoopy failed: {output!r}")
    output = shell.command(b"ping -c 1 10.0.2.222")
    if b"1 sent, 0 received" not in output or b"ping: no replies" not in output:
        raise RuntimeError(f"ping timeout failed: {output!r}")
    return port


def checksum(packet):
    if len(packet) % 2:
        packet += b"\0"
    total = sum(word for word, in struct.iter_unpack("!H", packet))
    while total > 0xffff:
        total = (total >> 16) + (total & 0xffff)
    return total ^ 0xffff


def ipv4_packet(source, destination, protocol, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64,
                         protocol, 0, source, destination)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ipv6_packet(source, destination, protocol, payload, hop_limit=64):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), protocol, hop_limit,
                       source, destination) + payload


def icmpv6_packet(source, destination, payload, hop_limit):
    pseudo = source + destination + struct.pack("!I3xB", len(payload), 58)
    digest = struct.pack("!H", checksum(pseudo + payload))
    return ipv6_packet(source, destination, 58, payload[:2] + digest + payload[4:], hop_limit)


def rudp_packet(source, destination, source_port, destination_port, sequence, generation, ack, ack_generation, data):
    body = struct.pack("!HHHHIIII", source_port, destination_port, 24 + len(data), 0,
                       sequence, generation, ack, ack_generation) + data
    digest = checksum(source + destination + struct.pack("!BBH", 0, 254, len(body)) + body)
    return ipv4_packet(source, destination, 254, body[:6] + struct.pack("!H", digest or 0xffff) + body[8:])


ESP_CIPHER_KEY = bytes(range(16))
ESP_AUTH_KEY = bytes(range(16, 32))
WIRE_MAC = bytes.fromhex("5254009a0001")
GUEST_MAC = bytes.fromhex("5254009a0002")
WIRE_V6 = "2001:db8:18::1"
GUEST_V6 = "2001:db8:18::2"


def aes(mode, key, data, iv=None, decrypt=False):
    command = ["openssl", "enc", f"-aes-128-{mode}", "-K", key.hex(), "-nopad"]
    if iv is not None:
        command += ["-iv", iv.hex()]
    if decrypt:
        command += ["-d"]
    result = subprocess.run(command, input=data, capture_output=True, timeout=5)
    if result.returncode:
        raise RuntimeError(f"OpenSSL AES failed: {result.stderr!r}")
    return result.stdout


def esp_tag(packet):
    derived = aes("ecb", ESP_AUTH_KEY, bytes([1]) * 16 + bytes([2]) * 16 + bytes([3]) * 16)
    working, complete, partial = derived[:16], derived[16:32], derived[32:]
    remainder = len(packet) % 16
    if remainder:
        packet += b"\x80" + bytes(15 - remainder)
    mask = partial if remainder else complete
    last = bytes(left ^ right for left, right in zip(packet[-16:], mask))
    return aes("cbc", working, packet[:-16] + last, bytes(16))[-16:-4]


def esp_packet(spi, sequence, data):
    padding = (-len(data) - 2) % 16
    plaintext = data + bytes(range(1, padding + 1)) + bytes([padding, 0])
    iv = os.urandom(16)
    packet = struct.pack("!II", spi, sequence) + iv + aes("cbc", ESP_CIPHER_KEY, plaintext, iv)
    return packet + esp_tag(packet)


def send_frame(link, lock, frame):
    with lock:
        link.sendall(struct.pack("!I", len(frame)) + frame)


def wire_peer(link, lock, esp_packets, raw_packets):
    mac = WIRE_MAC
    gateway = socket.inet_aton("198.18.0.1")
    target = socket.inet_aton("198.19.0.9")
    target_v6 = socket.inet_pton(socket.AF_INET6, WIRE_V6)
    reliable = set()
    with link.makefile("rb") as reader:
        while prefix := reader.read(4):
            if len(prefix) != 4:
                return
            length, = struct.unpack("!I", prefix)
            if length > 1518:
                raise RuntimeError(f"invalid QEMU frame length {length}")
            frame = reader.read(length)
            response = b""
            if len(frame) >= 42 and frame[12:14] == b"\x08\x06" and frame[20:22] == b"\0\1" and frame[38:42] == gateway:
                response = frame[6:12] + mac + b"\x08\x06" + frame[14:20] + b"\0\2" + mac + gateway + frame[22:32]
            if len(frame) >= 34 and frame[:6] == mac and frame[12:15] == b"\x08\x00\x45":
                packet = frame[14:14 + int.from_bytes(frame[16:18], "big")]
                source, destination = packet[12:16], packet[16:20]
                if packet[9] == 1 and len(packet) >= 28 and packet[20:22] == b"\x08\0":
                    if destination == target and packet[8] == 1:
                        sender = gateway
                        payload = b"\x0b\0\0\0\0\0\0\0" + packet[:28]
                    else:
                        sender = destination
                        payload = b"\0\0\0\0" + packet[24:]
                    payload = payload[:2] + struct.pack("!H", checksum(payload)) + payload[4:]
                    response = frame[6:12] + mac + b"\x08\x00" + ipv4_packet(sender, source, 1, payload)
                elif packet[9] == 17 and destination == gateway and packet[22:24] == b"\0\x35":
                    query = packet[28:]
                    question = query[12:]
                    record = question[-4:-2]
                    if question[:-4] == b"\x04wire\x07example\0" and record in (b"\0\1", b"\0\x1c"):
                        address = target if record == b"\0\1" else socket.inet_pton(socket.AF_INET6, "2001:db8::9")
                        body = query[:2] + b"\x81\x80\0\1\0\1\0\0\0\0" + question
                        body += b"\xc0\x0c" + record + struct.pack("!HIH", 1, 30, len(address)) + address
                        payload = b"\0\x35" + packet[20:22] + struct.pack("!HH", 8 + len(body), 0) + body
                        response = frame[6:12] + mac + b"\x08\x00" + ipv4_packet(gateway, source, 17, payload)
                elif packet[9] == 47 and packet[20:24] == b"\0\0\x08\x00" and destination == target:
                    payload = packet[20:24] + b"gre:" + packet[24:]
                    response = frame[6:12] + mac + b"\x08\x00" + ipv4_packet(target, source, 47, payload)
                elif packet[9] == 50 and destination == target:
                    esp_packets.put((4, packet[20:]))
                elif packet[9] == 253 and destination == target:
                    raw_packets.put(packet)
                elif packet[9] == 254 and destination == target and len(packet) >= 44:
                    sport, dport, length, _, seq, gen, _, _ = struct.unpack("!HHHHIIII", packet[20:44])
                    if length == len(packet) - 20 and dport == 8124 and seq == 1 and packet[44:] == b"plan9":
                        if checksum(source + destination + struct.pack("!BBH", 0, 254, length) + packet[20:]):
                            raise RuntimeError("RUDP request had an invalid checksum")
                        key = sport, gen
                        if key in reliable:
                            response = frame[6:12] + mac + b"\x08\x00" + rudp_packet(
                                target, source, dport, sport, 1, 123, seq, gen, b"rudp:retried")
                        reliable.add(key)
            if len(frame) >= 54 and frame[12:14] == b"\x86\xdd":
                source, destination = frame[22:38], frame[38:54]
                protocol = frame[20]
                payload = frame[54:54 + int.from_bytes(frame[18:20], "big")]
                if protocol == 58 and payload[:1] == b"\x87" and payload[8:24] == target_v6:
                    advertise = b"\x88\0\0\0\x60\0\0\0" + target_v6 + b"\x02\x01" + mac
                    response = frame[6:12] + mac + b"\x86\xdd" + icmpv6_packet(target_v6, source, advertise, 255)
                elif frame[:6] == mac and destination == target_v6:
                    if protocol == 58 and payload[:1] == b"\x80":
                        reply = b"\x81\0\0\0" + payload[4:]
                        response = frame[6:12] + mac + b"\x86\xdd" + icmpv6_packet(target_v6, source, reply, 64)
                    elif protocol == 50:
                        esp_packets.put((6, payload))
                    elif protocol == 253:
                        raw_packets.put(frame[14:54 + len(payload)])
                    elif protocol == 58 and payload[:2] == b"\x03\0":
                        raw_packets.put(frame[14:54 + len(payload)])
            if response:
                send_frame(link, lock, response)


def check_wire_network(shell, peer, lock, esp_packets, raw_packets, udp_port):
    for command, expected in (
        (b"cat /net/ether1/addr", b"5254009a0002"),
        (b"echo unbind > /net/ipifc/2/ctl; cat /net/ipifc/clone", b"2"),
        (b"echo bind ether /net/ether1 > /net/ipifc/2/ctl; cat /net/ipifc/2/status", b"mtu 1500 bound"),
        (b"echo static 198.18.0.2/24 > /net/ipifc/2/ctl; ipconfig", b"198.18.0.2/24"),
        (b"echo add 198.19.0.0/24 198.18.0.1 > /net/iproute; ipconfig routes", b"198.19.0.0/24 198.18.0.1 ether1"),
        (b"echo dns=198.18.0.1 > /net/ndb; ndb/dnsquery wire.example", b"wire.example ip 198.19.0.9"),
        (b"ndb/dnsquery wire.example ipv6", b"wire.example ipv6 2001:db8::9"),
        (b"ping -n 1 wire.example", b"reply from 198.19.0.9"),
        (b"ip/traceroute -a 1 -t 2 198.19.0.9", b"  1  198.18.0.1 "),
        (b"netcat -g -m plan9 198.19.0.9 2048", b"gre:plan9"),
        (b"netcat -r -m plan9 198.19.0.9 8124", b"rudp:retried"),
        (b"cat /net/arp", b"ether OK 198.18.0.1 5254009a0001"),
        (b"echo add ether 198.18.0.1 52:54:00:9a:00:11 > /net/arp; ping -n 1 198.18.0.1", b"1 sent, 0 received"),
        (b"echo add ether 198.18.0.1 5254009a0001 > /net/arp; ping -n 1 198.18.0.1", b"reply from 198.18.0.1"),
        (b"echo del 198.18.0.1 > /net/arp; ping -n 1 198.18.0.1", b"reply from 198.18.0.1"),
    ):
        output = shell.command(command).partition(b"\n")[2]
        if expected not in output or (b"traceroute" in command and b"  2  198.19.0.9 " not in output):
            raise RuntimeError(f"{command!r} failed: {output!r}")
    check_esp(shell, peer, lock, esp_packets)
    check_ipmux_output(shell, raw_packets, udp_port)
    if b"198.19.0.0/24" in shell.command(b"echo remove 198.19.0.0/24 > /net/iproute; ipconfig routes").partition(b"\n")[2]:
        raise RuntimeError("route removal left 198.19.0.0/24 installed")
    if b"ether OK" in shell.command(b"echo flush > /net/arp; cat /net/arp").partition(b"\n")[2]:
        raise RuntimeError("ARP flush left entries installed")

    def packet(destination, payload):
        return bytes.fromhex("5254009a00025254009a00010800") + ipv4_packet(
            socket.inet_aton("198.18.0.1"), socket.inet_aton(destination), 253, payload)

    shell.send(b"snoopy -n 1 -f 'proto=fd;data[0:1]=a000|ca00&ff00;iph[0]=45;ifc=198.18.0.2'")
    for _ in range(5):
        send_frame(peer, lock, packet("198.18.0.2", b"\xca\xfe"))
        time.sleep(0.1)
    output = shell.read_prompt(25)
    if b"ipmux 198.18.0.2 198.18.0.1 > 198.18.0.2 proto=253 ttl=64 22 bytes" not in output:
        raise RuntimeError(f"ipmux filter failed: {output!r}")

    shell.send(b"snoopy -n 1 -f 'proto=fd' -f 'proto=fd;data[0]=ca'")
    time.sleep(0.5)
    send_frame(peer, lock, packet("198.18.0.2", b"\xca\xfe"))
    time.sleep(0.1)
    send_frame(peer, lock, packet("198.18.0.2", b"any"))
    output = shell.read_prompt(25).partition(b"\n")[2]
    lengths = re.findall(rb"proto=253 ttl=64 (\d+) bytes", output)
    if lengths != [b"23", b"22"]:
        raise RuntimeError(f"overlapping ipmux filters chose the wrong conversation: {output!r}")

    output = shell.command(b"echo iprouting 1 > /net/ipifc/2/ctl; cat /net/ipifc/stats")
    if b"Forwarding: 1" not in output:
        raise RuntimeError(f"IPv4 forwarding could not be enabled: {output!r}")
    frame = packet("10.0.2.2", b"forward")
    shell.send(b"snoopy -n 1 -t 0x0800 ether0")
    for _ in range(5):
        send_frame(peer, lock, frame)
        time.sleep(0.1)
    output = shell.read_prompt(25)
    if b"198.18.0.1 > 10.0.2.2 proto=253 ttl=63" not in output:
        raise RuntimeError(f"IPv4 forwarding failed: {output!r}")
    check_ipv6_forwarding(shell, peer, lock, raw_packets)


def forwarded_count(shell):
    output = shell.command(b"cat /net/ipifc/stats").partition(b"\n")[2]
    match = re.search(rb"ForwDatagrams: (\d+)\n", output)
    if not match:
        raise RuntimeError(f"missing forwarding counter: {output!r}")
    return int(match[1])


def check_ipv6_forwarding(shell, peer, lock, raw_packets):
    source = socket.inet_pton(socket.AF_INET6, WIRE_V6)
    target = socket.inet_pton(socket.AF_INET6, "fec0::2")
    ethernet = GUEST_MAC + WIRE_MAC + b"\x86\xdd"
    packet = ipv6_packet(source, target, 253, b"ipv6 forward")
    before = forwarded_count(shell)
    send_frame(peer, lock, ethernet + packet)
    deadline = time.monotonic() + 5
    while forwarded_count(shell) == before:
        if time.monotonic() >= deadline:
            raise RuntimeError("IPv6 forwarding failed to resolve the next hop")
        time.sleep(0.1)

    shell.send(b"snoopy -n 1 -t 0x86dd ether0")
    for _ in range(5):
        send_frame(peer, lock, ethernet + packet)
        time.sleep(0.1)
    output = shell.read_prompt(25)
    if f"{WIRE_V6} > fec0::2 proto=253 hop=63".encode() not in output:
        raise RuntimeError(f"IPv6 forwarding hop limit failed: {output!r}")

    expired = ipv6_packet(source, target, 253, b"expired", hop_limit=1)
    send_frame(peer, lock, ethernet + expired)
    try:
        reply = raw_packets.get(timeout=5)
    except Empty as error:
        raise RuntimeError("IPv6 forwarding did not return Time Exceeded") from error
    pseudo = reply[8:40] + struct.pack("!I3xB", len(reply) - 40, 58)
    if reply[24:40] != source or reply[40:42] != b"\x03\0" or reply[48:] != expired or checksum(pseudo + reply[40:]):
        raise RuntimeError(f"invalid ICMPv6 Time Exceeded: {reply.hex()}")

    output = shell.command(b"echo iprouting 0 > /net/ipifc/2/ctl; cat /net/ipifc/stats")
    if b"Forwarding: 0" not in output:
        raise RuntimeError(f"forwarding could not be disabled: {output!r}")
    before = forwarded_count(shell)
    send_frame(peer, lock, ethernet + packet)
    time.sleep(0.3)
    if forwarded_count(shell) != before:
        raise RuntimeError("IPv6 forwarding continued after iprouting 0")


def check_ipmux_output(shell, raw_packets, udp_port):
    packets = (
        ipv4_packet(socket.inet_aton("198.18.0.2"), socket.inet_aton("198.19.0.9"), 253, b"ipmux4"),
        ipv6_packet(socket.inet_pton(socket.AF_INET6, GUEST_V6),
                    socket.inet_pton(socket.AF_INET6, WIRE_V6), 253, b"ipmux6"),
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        for packet in packets:
            shell.send(b"netcat -u -l -H * 8124 > /tmp/ipmux-packet")
            shell.read_until(UDP_HEADERS_READY, 10, "UDP packet upload listener")
            client.sendto(packet, ("127.0.0.1", udp_port))
            if client.recvfrom(1500)[0] != packet:
                raise RuntimeError("UDP packet upload echo mismatch")
            shell.read_prompt(25)
            output = shell.command(b"netcat -I /tmp/ipmux-packet")
            try:
                sent = raw_packets.get(timeout=5)
            except Empty as error:
                raise RuntimeError(f"no ipmux packet sent: {output!r}") from error
            if sent != packet:
                raise RuntimeError(f"ipmux packet mismatch: {sent.hex()} != {packet.hex()}")
    shell.command(b"rm /tmp/ipmux-packet")


def check_esp(shell, peer, lock, esp_packets):
    check_esp_family(shell, peer, lock, esp_packets, 4, "198.19.0.9", "198.18.0.2")
    command = f"echo add {GUEST_V6}/64 > /net/ipifc/2/ctl; ping -6 -n 1 {WIRE_V6}"
    output = shell.command(command.encode()).partition(b"\n")[2]
    if f"reply from {WIRE_V6}".encode() not in output:
        raise RuntimeError(f"ESP IPv6 peer did not answer Neighbor Discovery or ping: {output!r}")
    check_esp_family(shell, peer, lock, esp_packets, 6, WIRE_V6, GUEST_V6)


def check_esp_family(shell, peer, lock, esp_packets, family, target, guest):
    keys = f"'esp aes_128_cbc {ESP_CIPHER_KEY.hex()}' 'ah aes_xcbc_mac_96 {ESP_AUTH_KEY.hex()}'"
    settings = f"printf '%s\\n%s\\n%s\\n' {keys} 'ivseed {os.urandom(16).hex()}' > /tmp/espkeys"
    output = shell.command(settings.encode()).partition(b"\n")[2]
    if output.strip():
        raise RuntimeError(f"ESP key setup failed: {output!r}")
    command = f"netcat -E /tmp/espkeys -m esp:out {target} 270544960"
    output = shell.command(command.encode()).partition(b"\n")[2]
    if output.strip():
        raise RuntimeError(f"ESP send failed: {output!r}")
    try:
        version, packet = esp_packets.get(timeout=5)
    except Empty as error:
        raise RuntimeError("ESP packet not seen on the wire") from error
    if version != family or packet[:8] != struct.pack("!II", 270544960, 1) or packet[-12:] != esp_tag(packet[:-12]):
        raise RuntimeError("ESP outbound SPI, sequence or authentication tag is invalid")
    if aes("cbc", ESP_CIPHER_KEY, packet[24:-12], packet[8:24], decrypt=True) != b"esp:out\x01\x02\x03\x04\x05\x06\x07\x07\x00":
        raise RuntimeError("ESP ciphertext did not decrypt to the guest payload")

    shell.command(f"printf '%s\\n%s\\n' {keys} > /tmp/espkeys".encode())
    shell.send(f"netcat -E /tmp/espkeys -n 2 {target} '*'".encode())
    shell.read_until(re.compile(re.escape(f"ESP listening on {guest}!".encode())), 10, "ESP receive association")
    spi = int(shell.read_until(re.compile(rb"\n"), 5, "ESP receive SPI").strip())
    first = esp_packet(spi, 1, b"esp:first\n")
    invalid = esp_packet(spi, 2, b"esp:invalid\n")
    second = esp_packet(spi, 2, b"esp:second\n")
    wrong_spi = esp_packet(spi + 1, 1, b"esp:wrong-spi\n")
    for payload in (wrong_spi, invalid[:-1] + bytes([invalid[-1] ^ 1]), first, first, second):
        if family == 4:
            packet = b"\x08\x00" + ipv4_packet(socket.inet_aton(target), socket.inet_aton(guest), 50, payload)
        else:
            packet = b"\x86\xdd" + ipv6_packet(socket.inet_pton(socket.AF_INET6, target),
                                                socket.inet_pton(socket.AF_INET6, guest), 50, payload)
        send_frame(peer, lock, GUEST_MAC + WIRE_MAC + packet)
    output = shell.read_prompt(15)
    if output.splitlines() != [b"esp:first", b"esp:second"]:
        raise RuntimeError(f"ESP receive, integrity or replay filtering failed: {output!r}")
    shell.command(b"rm /tmp/espkeys")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--mount", action="store_true")
    parser.add_argument("arch")
    parser.add_argument("log")
    parser.add_argument("qemu", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    qemu = args.qemu[1:] if args.qemu[:1] == ["--"] else args.qemu
    if not qemu:
        parser.error("expected a QEMU command after --")

    try:
        with tempfile.TemporaryDirectory(prefix="plan9-qmp-") as tmp, \
                open(args.log, "wb", buffering=0) as log, selectors.DefaultSelector() as selector, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock, \
                ThreadPoolExecutor(max_workers=1) as workers:
            qmp_path = Path(tmp) / "qmp"
            peer, guest = socket.socketpair()
            with peer, guest:
                run_qemu(args, qemu, qmp_path, peer, guest, workers, log, selector, sock)
    except (OSError, RuntimeError) as error:
        print(f"{args.arch}: {error}; see {args.log}", file=sys.stderr)
        return 1
    checks = ("DHCP, IPv4/IPv6 ICMP, TCP/UDP echo and listeners, UDP headers, DNS/CS, GRE, RUDP, ESP, ARP, ipmux, capture, dual-stack forwarding and traceroute" if args.network else
              "9P mount, authentication, remote mutations and fid lifetime" if args.mount else
              "boot and shell, device/process listings, rc login profiles and environment groups")
    print(f"{args.arch}: {checks} passed")
    return 0


def run_qemu(args, qemu, qmp_path, peer, guest, workers, log, selector, sock):
    network = []
    fds = ()
    if args.network:
        nic = next(part.rsplit(",netdev=net0", 1)[0] for part in qemu if part.endswith(",netdev=net0"))
        fds = (guest.fileno(),)
        network = ["-netdev", f"socket,id=wire,fd={guest.fileno()}",
                   "-device", f"{nic},netdev=wire,mac=52:54:00:9a:00:02"]
    with subprocess.Popen(qemu + network + ["-qmp", f"unix:{qmp_path},server=on,wait=off"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, pass_fds=fds) as process:
        guest.close()
        lock = threading.Lock()
        esp_packets = Queue()
        raw_packets = Queue()
        wire = workers.submit(wire_peer, peer, lock, esp_packets, raw_packets) if args.network else None
        try:
            shell = SerialShell(process, selector, log)
            connect_qmp(sock, qmp_path, process)
            qmp = Qmp(sock)
            with qmp.stream:
                if args.network:
                    shell.read_prompt(90)
                    udp_port = check_network(shell, qmp)
                    check_wire_network(shell, peer, lock, esp_packets, raw_packets, udp_port)
                elif args.mount:
                    shell.read_prompt(90)
                    wait_for_dhcp(shell)
                    check_9p_mount(shell)
                else:
                    check_boot(args.arch, shell, qmp, Path(args.log).resolve().parent)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if wire:
                wire.result(timeout=5)


if __name__ == "__main__":
    sys.exit(main())

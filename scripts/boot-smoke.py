#!/usr/bin/env python3
"""Verify the GOP menu, kernel display and interactive shell in QEMU."""

import argparse
from contextlib import contextmanager
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import pty
from queue import Empty, Queue
import re
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tty
from concurrent.futures import ThreadPoolExecutor

from disk_image import MACHINES, PAGE, create_image, dump_info
from snap_to_acid import convert_snapshot

PROMPT = re.compile(rb"(?:root|glenda)@plan9:[^\r\n]*> ")
COMMANDS = b"""
basename bind cat chmod chown clear cmp cp cut date dc diff dirname du echo ed env expr
false fortune grep group head hostname id ipconfig kill ln ls mkdir more mount mv netcat nl passwd ping printf
ps pwd rc rm rmdir seq sleep snap snoopy sort stat su tail tee test time touch tr traceroute true tty uname
uniq units unmount uptime useradd usermod wc who whoami yes
""".split()
HELP_FOOTER = b"redirection: < > >>    pipelines: cmd | cmd    lists: cmd ; cmd"
MENU_MARKER = b"bootloader: GOP menu"
FRAMEBUFFER_MARKER = b"bootloader: GOP linear framebuffer found"
INTERACTIVE_SELECTION = b"bootloader: selected Boot Plan 9 (verbose)"
UDP_HEADERS_READY = re.compile(rb"netcat: UDP headers ready\r?\n")
P9SK1_TICKET_REQUEST_SIZE = 141
P9SK1_TICKET_PAIR_SIZE = 144


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

    def command(self, command, timeout=25):
        self.send(command)
        return self.read_prompt(timeout)


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


def check_panic(shell, qmp, arch, cpu_service, dump=False):
    shell.read_until(re.compile(MENU_MARKER), 90, "UEFI GOP menu")
    if cpu_service:
        qmp.key("down")
        qmp.key("down")
    qmp.key("ret")
    message = {
        "x86_64": rb"x86 kernel exception: vector=6 error=0x0 rip=0x[0-9a-f]+ cr2=0x[0-9a-f]+",
        "aarch64": rb"aarch64 kernel exception: ESR=0x(?:0|2000000) FAR=0x[0-9a-f]+ ELR=0x[0-9a-f]+",
        "riscv64": rb"RISC-V trap: scause=0x2 sepc=0x[0-9a-f]+ stval=0x[0-9a-f]+",
        "loongarch64": rb"LoongArch kernel fault: ecode=13 ESTAT=0x[0-9a-f]+ ERA=0x[0-9a-f]+ BADV=0x[0-9a-f]+",
    }[arch]
    shell.read_until(re.compile(rb"PANIC: [^\n]*\n\s*" + message), 45, "illegal kernel instruction panic")
    shell.read_until(re.compile(rb"Kernel backtrace .*\n\s*#0 0x[0-9a-f]+"), 5, "kernel backtrace")
    if dump:
        shell.read_until(re.compile(rb"Saved kernel memory dump\.|Kernel memory dump failed\."), 180, "panic dump result")
    if cpu_service:
        shell.read_until(re.compile(rb"CPU server: attempting reboot"), 5, "panic reboot decision")
        shell.read_until(re.compile(MENU_MARKER), 90, "UEFI menu after reset")
    else:
        shell.read_until(re.compile(rb"System halted\."), 5, "panic halt decision")
        try:
            shell.read_until(re.compile(MENU_MARKER), 2, "unexpected terminal reset")
        except TimeoutError:
            return
        raise RuntimeError("terminal mode restarted after announcing a halt")


RC_DIFF_CASES = {
    "comments and blank lines": "# comment\n\necho visible # trailing comment\n",
    "literal quotes": "echo 'a b' 'isn''t' '$x' '[a-z]*' ''",
    "utf8 literals": "echo '网络' 'é'",
    "adjacent quoted words": "echo un'quoted'^suffix",
    "concat broadcasting": "echo pre^(one two)^post; echo (a b)^(x y)",
    "concat length error": "echo (a b)^(x y z)",
    "list slices": "x=(a b c d); echo $x(2 3-4); echo $x(2-)",
    "subscript boundaries": "x=(a b c d); echo before $x(0 4 3-2 8 2-99) after",
    "empty and undefined values": "empty=(); echo $#empty $#missing; echo before $missing after",
    "indirect variable": "name=value; value=(red blue); echo $$name",
    "join variable": "value=(red blue); echo $\"value",
    "command-local assignment": "x=outer; x=inner rc -c 'echo $x'; echo $x",
    "assignment preserves status": "~ a b; x=ready; echo $x $status",
    "function parameters": "fn greet { echo $#* $1 $2 }; greet a b; greet c",
    "implicit for after shift": "fn args { shift; for (item) echo $item }; args one two three",
    "function aliases": "fn one two { echo $#* $* }; one a; two b c; fn one two",
    "remove function": "fn demo { echo yes }; demo; fn demo",
    "function definition and removal preserve status": "~ a b; fn demo { true }; echo $status; ~ a b; fn demo; echo $status",
    "if and if not": "if(~ a a) echo then\nif not echo impossible\nif(~ a b) echo impossible\nif not echo else\n",
    "for list": "for(x in a b c) echo $x",
    "while loop": "x=(a b c); while(! ~ $#x 0) { echo $x(1); x=$x(2-) }",
    "while final condition status": "while (~ yes no) echo wrong; echo 'status='^$status",
    "while condition runs in shell": "x=(a b); while (x=$x(2-); ! ~ $#x 0) echo $x; echo 'count='^$#x",
    "for variable restoration": "x=outer; for (x in a b) echo $x; echo $x",
    "empty list concatenation": "x=(); echo first $x^suffix last",
    "function scope restoration": "x=outer; fn change { x=$1 }; @ change inner; echo $x",
    "switch and patterns": "switch(blues) { case red; echo no; case bl* green; echo yes; case *; echo no }",
    "unmatched switch preserves status": "~ a b; switch (x) { case y; echo wrong }; echo $status",
    "pattern classes": "~ abc [ab]b? && echo matched; ~ abc [~a]* || echo not-matched",
    "conditional lists": "~ a a && echo yes; ~ a b && echo no; ~ a b || echo fallback; ! ~ a b",
    "errexit inside negation": "rc -e -c '! ~ a b; echo unreachable'",
    "negation can be tested with errexit": "rc -e -c '! ~ a b || echo fallback; echo continued'",
    "negation result does not trigger errexit": "rc -e -c '! ~ a a; echo continued'",
    "group scope": "x=a; { x=b; echo $x }; @ { x=c; echo $x }; echo $x",
    "pipeline": "echo 'pipe data' | cat",
    "multiline pipeline": "echo pipe |\ncat &&\necho after\n",
    "pipeline status": "echo pipe | rc -c 'exit failed'",
    "alternate pipe descriptors": "echo alternate >[1=2] |[2] cat",
    "command substitution": "ifs=:; x=`{echo 'one:two'}; echo $#x $x(1)",
    "empty ifs in command substitution": "ifs=(); x=`{echo 'one two'}; echo $#x $x",
    "nested substitution": "echo `{@ { echo `{echo nested} }}",
    "argument expansion order": "echo `{echo left >> trace; echo a} `{echo right >> trace; echo b}; cat trace; rm trace",
    "list expansion order": "echo (`{echo first >> trace; echo a} `{echo second >> trace; echo b}); cat trace; rm trace",
    "concatenation expansion order": "echo `{echo left >> trace; echo a}^`{echo right >> trace; echo b}; cat trace; rm trace",
    "match expansion order": "~ `{echo subject >> trace; echo a} `{echo pattern >> trace; echo a}; cat trace; rm trace",
    "process substitution": "cat <{echo process-substitution}",
    "process substitution quoting": "cat <{'echo' 'space and ''quotes'''}",
    "files and append redirection": "echo first >out; echo second >>out; cat <out; rm out",
    "redirection alone preserves status": "~ a b; >out; echo $status; cat out; rm out",
    "background launch preserves status": "~ a b; { true } & echo $status; wait; true",
    "fd duplication": "echo redirected >[1=2]",
    "here document": "x=expanded\ncat <<EOF\n$x\nEOF\n",
    "quoted here document": "x=expanded\ncat <<'EOF'\n$x\nEOF\n",
    "here document at pipeline boundary": "cat <<EOF | cat\npiped\nEOF\n",
    "multiple here documents": "cat <<ONE <<TWO\nfirst\nONE\nsecond\n\nTWO\n",
    "here document variable boundaries": "x=(one two)\ncat <<EOF\n$x! $x^suffix $$x $?\nEOF\n",
    "sigexit stays local": "rc -c 'fn sigexit { echo exit-trap }; exit'; rc -c 'exit ''custom status''' || echo failed",
    "failure after output": "echo before-failure; exit failure",
    "exit success": "exit ''",
    "exit failure": "exit 'error with spaces'",
    "syntax error": "echo unexpected )",
    "quoted variable name": "'with space'=present; echo $'with space'",
    "subscript expansion order": "x=(one two); echo $x(`{echo first >> trace; echo 1} `{echo second >> trace; echo 2}); cat trace; rm trace",
    "dynamic variable name followed by a separate list": "x=(one two); echo $`{echo name >> trace; echo x}(`{echo index >> trace; echo 2}); cat trace; rm trace",
    "subscript numeric prefixes": "x=(one two three); echo begin $x(2x 1-2x x2 2--1) end",
    "count and join with subscripts": 'x=(one two three); echo $#x(2) $"x(1 3)',
    "empty substitution with no separators": "ifs=(); echo before `{true} after; echo $#ifs",
    "substitution keeps selected separators": "ifs=:; echo `{echo ':one::two:'}",
    "nested lists": "echo (() ((one)) (two (three four)) ())",
    "white space subject matching": "~ (a b) 'a b' && echo match",
    "empty switch": "switch(x) {}; echo unexpected",
    "switch rejects newline before opening brace": "switch x\n{ case x; echo unexpected }",
    "switch accepts separators before the first case": "switch x { ; case x; echo matched }",
    "switch rejects a lone case with no commands": "switch x { case x; } && echo unexpected",
    "switch accepts a final case with no commands": "switch x { case y; echo unexpected; case x } && echo matched",
    "case without patterns": "switch(()) { case; echo unexpected; case ''; echo matched }",
    "case fallthrough is disabled": "switch(x) { case x; echo match; case *; echo unexpected }",
    "character class edge cases": "~ ']' []] && echo bracket; ~ - [-a] && echo leading; ~ b [z-a] && echo descending; ~ a [a-] && echo trailing; true",
    "quoted and unquoted wildcard": "~ 'a*bc' 'a*'^b* && echo matched; ~ 'axb' 'a*'^b* || echo literal",
    "glob sorts names and includes hidden files": "mkdir names; >names/z; >names/a; >names/.hidden; echo names/* names/.*; rm names/z names/a names/.hidden; rm names",
    "unmatched glob preserves spelling": "echo /tmp/rc-differential/nonexistent*/item",
    "explicit line continuation": "echo first\\\nsecond",
    "empty for preserves status": "~ a b; for(x in) echo unexpected; echo $status",
    "multiple scoped assignments": "x=outer; x=inner y=$x rc -c 'echo $x $y'; echo $x $#y",
    "assignment pipeline scope": "x=outer; x=inner echo $x | cat; echo $x",
    "three-stage pipeline and failure status": "echo input | cat | cat; rc -c 'exit left' | true | rc -c 'exit right' || echo failed",
    "tested pipeline with errexit": "rc -e -c 'rc -c ''exit failed'' | true || echo caught; echo continued'",
    "dangling if not": "echo before; if not echo unexpected; echo after",
    "if not cannot follow a grouped if": "{ if(~ a b) echo no }; if not echo unexpected",
    "if not cannot repeat": "if(~ a b) echo no; if not echo unused; if not echo unexpected",
    "if not follows blank lines": "if(~ a b) echo no\n\n# comment\nif not echo yes",
    "explicit empty if body": "if(~ a a) ; if not echo unexpected; echo after",
    "write-side process substitution": "echo `{echo input > >{cat}}",
    "literal followed by unspaced parentheses": "echo plain(one two)",
    "quoted literal followed by unspaced parentheses": "echo 'plain'(one two)",
    "adjacent parenthesized lists stay separate": "echo (a b)(c d)",
    "parenthesized list requires explicit concatenation": "echo (a b)tail; echo (a b)^tail",
    "command substitution requires explicit suffix concatenation": "echo `{echo word}suffix; echo `{echo word}^suffix",
    "subscript requires explicit suffix concatenation": "x=(one two); echo $x(1)suffix; echo $x(1)^suffix",
    "process substitution starts a new word after a literal": "fn fields { echo $#* }; fields x<{true}",
    "recursive functions restore positional parameters": "fn visit { echo start $1; if(! ~ $#* 1) visit $*(2-); echo end $1 }; visit a b c",
    "functions declared together and removed": "fn alpha beta { echo body $* }; alpha one; beta two; fn alpha beta; !! alpha >[2]/dev/null",
    "nested assignment and function scope": "value=outside; fn show { echo $value $* }; value=inside show one two; show three",
    "empty command group in boolean list": "true; {} && echo empty; ! {} || echo negated",
    "switch subject with several words": "switch(a b) { case 'a b'; echo joined; case a b; echo separate; case *; echo wildcard }",
    "for loop consumes its original word list": "items=(a b c); for (item in $items) { echo $item; items=z }; echo $items",
    "while condition controls exit": "x=(a b c); while(! ~ $#x 0) { echo $x(1); x=$x(2-) }; echo done",
    "nested if not binds in a command group": "if(~ a a) { if(~ b c) echo unexpected; if not echo inner }; if not echo unexpected",
    "subscript ranges and repeated indices": "x=(a b c d); echo $x(-2 4- 3 3 7 4-2)",
    "subscript and concatenation in a quoted list": "x=(red green blue); echo pre^$x(3 1)^post; echo $\"x(2-)",
    "keyword and metacharacter adjacency": "echo 'if'^not 'case'^')' 'a''b' a^'|'",
    "quoted wildcard after explicit concatenation": "~ 'prefix*tail' pre^fix^'*'^t* && echo matched",
    "glob matches across several directories": "mkdir first second; >first/z; >second/a; echo */[az]; rm first/z second/a; rm first second",
    "comments on continued syntax": "echo one # ignore this\necho two |\ncat # ignore this too\n",
    "literal blank lines inside a quoted word": "echo 'first\n\nthird'",
    "here document preserves a literal tab": "cat <<'END'\n\tindented\nEND\n",
    "here document redirected into a command group": "{ cat; echo after } <<EOF\nhello\nEOF\n",
    "here document inside a multiline group": "{ cat <<EOF\n echo after\n}\nhello\nEOF\n",
    "here document before a pipeline continuation": "cat <<EOF |\ncat\nhello\nEOF\n",
    "here document inside an if condition": "if(cat <<EOF)\necho yes\nhello\nEOF\n",
    "here document inside a command substitution": "echo `{cat <<EOF\n}\nhello\nEOF\n",
    "here documents share a complete command boundary": "{ cat <<ONE\ncat <<TWO\n}\nfirst\nONE\nsecond\nTWO\n",
    "descriptor swap survives a pipeline": "{ echo out; echo err >[1=2] } >[3=1] >[1=2] >[2=3] | cat",
    "pipeline combines with conditional and group": "{ echo first; echo second } | cat | cat && echo after",
    "background process and wait with redirection": "{ echo earlier } >bg & wait; cat bg; rm bg",
    "substitution uses a multi-character ifs list": "ifs=(: ,); x=`{echo 'one:two,three'}; echo $#x; echo $x(2)",
    "explicit backquote separator overrides ifs": "ifs=,; x=`: {printf '%s' 'one:two,three'}; echo $#x $x",
    "explicit Unicode separator in UTF-8 output": "sep='界'; x=`$sep {printf '%s' 'one界two界界three'}; echo $#x $x",
    "explicit empty separator retains whitespace": "x=`'' {printf '%s' 'a b'}; echo $#x; printf '[%s]\\n' $x",
    "empty backquote output produces an empty list": "x=`: {true}; echo $#x",
    "literal metacharacter as a separator": "x=`'^' {printf '%s' 'a^b'}; echo $#x $x",
    "two process substitutions are independent": "cat <{echo first} <{echo second}",
    "direct command execution uses expanded argv": "args=(echo hello world); $args",
    "empty function body preserves status": "fn nothing {}; true; nothing && echo preserved",
    "unclosed function definition is a syntax error": "fn unfinished { echo unexpected",
    "unclosed subscript is a syntax error": "x=(a b); echo $x(1",
    "dangling pipeline is a syntax error": "echo unexpected |",
    "non-numeric descriptor is a syntax error": "echo unexpected >[abc=1]",
}


def rc_quote(value):
    return b"'" + value.replace(b"'", b"''") + b"'"


def write_rc_line(line, mode, path):
    chunks = line.split(b"\t")
    template = b"\\t".join([b"%s"] * len(chunks)) + b"\\n"
    arguments = b" ".join(rc_quote(chunk) for chunk in chunks)
    return b"printf " + rc_quote(template) + b" " + arguments + b" " + mode + path


def run_rc_reference(reference, script, directory, environment, name, timeout=10):
    with subprocess.Popen([reference, "-Y", script], cwd=directory, env=environment, start_new_session=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise RuntimeError(f"reference rc timed out in {name!r}") from error
        return process.returncode, stdout, stderr


def check_rc_reference(shell, reference):
    reference = Path(reference).resolve(strict=True)
    environment = dict(os.environ, PLAN9=str(reference.parent.parent), LC_ALL="C",
                       PATH=f"{reference.parent}{os.pathsep}{os.defpath}")
    failures = []
    script_path = b"/tmp/rc-differential/test.rc"
    shell.command(b"mkdir /tmp/rc-differential")
    with tempfile.TemporaryDirectory(prefix="plan9-rc-differential-") as directory:
        script = Path(directory) / "test.rc"
        for name, source in RC_DIFF_CASES.items():
            script.write_text(source.rstrip("\n") + "\n", encoding="utf-8")
            exit_code, stdout, stderr = run_rc_reference(reference, script, directory, environment, name)
            lines = script.read_bytes().splitlines()
            for index, line in enumerate(lines[:-1]):
                mode = b">" if index == 0 else b">>"
                shell.command(write_rc_line(line, mode, script_path))
            mode = b">>" if len(lines) > 1 else b">"
            wrapped = (write_rc_line(lines[-1], mode, script_path) + b" && "
                       b"@ { cd /tmp/rc-differential && rc test.rc >[2]/dev/null } "
                       b"&& echo __RC_DIFF_OK__ || echo __RC_DIFF_FAILED__")
            guest = shell.command(wrapped).partition(b"\n")[2].splitlines()
            status = guest.pop() if guest else b""
            expected_status = b"__RC_DIFF_OK__" if exit_code == 0 else b"__RC_DIFF_FAILED__"
            if status != expected_status or stdout.splitlines() != guest:
                failures.append(f"{name}: reference={stdout!r} ({exit_code}), guest={guest!r} ({status!r}); "
                                f"reference stderr={stderr!r}")
    if failures:
        raise RuntimeError("rc differential failures:\n" + "\n".join(failures))
    print(f"Compared {len(RC_DIFF_CASES)} cases with {reference} -Y")


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
    expect(b"echo $values(0 3 2- 99 wrong)", b"three two three")
    expect(b"echo $(values)(0 3 2- 99 wrong)", b"one two three 0 3 2- 99 wrong")
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
    expect(b"{ while (! test -f /tmp/ctl-done) true; true } & p=$apid; "
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
    shell.command(b"{ while (! test -f /tmp/note-done) true; true } & p=$apid; echo stop > /proc/$p/ctl")
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


def serve_9p(listener, factotum=False, disconnect=False):
    def string(value):
        return struct.pack("<H", len(value)) + value

    directories = (b"", b"listing", b"dir-one", b"dir-two", b"list-one", b"list-two", b"list-cancel")

    def qid(name):
        kind = 0x80 if name in directories else 0x08 if name == b"@auth" else 0
        path = 4 + directories.index(name) if name in directories else 2
        return struct.pack("<BIQ", kind, 0, path)

    def stat(name, content):
        mode = modes.get(name, 0o666)
        if name in directories:
            mode |= 0x80000000
        fields = (struct.pack("<HI", 0, 0) + qid(name)
                  + struct.pack("<IIIQ", mode, 0, 0, len(content))
                  + b"".join(map(string, (name, b"alice", b"staff", b"editor"))))
        return string(fields)

    files = {b"rpc": bytearray()} if factotum else {
        b"remote": bytearray(b"hello-9p\n"), b"flush": bytearray(b"after-flush\n"),
        b"flush-race": bytearray(b"completed\n"), b"listing": bytearray(),
        b"dir-one": b"1", b"dir-two": b"2",
        b"parallel-one": b"1", b"parallel-two": b"2", b"cancel-one": b"1", b"cancel-two": b"2",
        b"shared-offset": b"12", b"killed": b"", b"kill-ready": b"r", b"kill-done": b"d",
        b"metadata-one": b"1", b"metadata-two": b"22", b"stat-cancel": b"cancel",
        b"path-one": b"1", b"path-two": b"22", b"path-cancel": b"cancel",
        b"clunk-hold": b"", b"clunk-ready": b"c", b"clunk-read": b"r",
        b"open-one": b"1", b"open-two": b"2", b"open-cancel": b"o",
        b"walk-cancel": b"w", b"union-arm": b"a", b"union-release": b"r",
        b"open-kill": b"", b"open-kill-ready": b"r", b"open-kill-done": b"d",
        b"clone-cancel": b"c", b"remove-cancel": b"", b"remove-kill": b"",
        b"remove-kill-ready": b"r",
        b"list-one": b"one", b"list-two": b"two", b"list-cancel": b"first",
    }
    if disconnect:
        files = {b"drop-one": b"", b"drop-two": b""}
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
    held = {}
    reversed_requests = False
    reversed_directories = False
    reversed_lists = False
    writes = {}
    reversed_writes = False
    metadata = {b"metadata": {}, b"path": {}}
    reversed_metadata = set()
    opened = set()
    open_pair = {}
    reversed_opens = False
    walk_pair = {}
    reversed_walks = False
    canceled_fid = None
    union_armed = False
    union_read = None
    union_release = None
    union_overlapped = False
    open_flush_tag = None
    open_kill_released = False
    clunk_tag = None
    completed_clunks = 0
    shared_offset = 0
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
                    if auth not in ({0xFFFFFFFF} if factotum or disconnect else auth_success):
                        raise RuntimeError(f"invalid 9P attach auth fid {auth}")
                    aname = b"" if factotum or disconnect else b"test-tree"
                    if body[8:] != string(b"root") + string(aname):
                        raise RuntimeError(f"invalid attach request {body!r}")
                    fids[fid] = b""
                    payload = qid(b"")
                elif kind == 108:
                    if canceled is None or body != struct.pack("<H", canceled[0]):
                        raise RuntimeError(f"unexpected 9P flush {body!r}")
                    flushed.add(canceled[1])
                    if canceled[2]:
                        connection.sendall(canceled[2])
                    if canceled[1] == b"cancel-one":
                        other = held.pop(b"cancel-two", None)
                        if other is None or other == canceled[0]:
                            raise RuntimeError("Tflush did not isolate two outstanding requests")
                        connection.sendall(struct.pack("<IBHIc", 12, 117, other, 1, b"2"))
                    if canceled[1] == b"open-kill":
                        open_flush_tag = tag
                        canceled = None
                        continue
                    canceled = None
                elif kind == 110:
                    fid, newfid, count = struct.unpack_from("<IIH", body)
                    name = body[12:] if count else fids[fid]
                    if count and (fids[fid] or name not in files):
                        payload = b"\x00\x00"
                    else:
                        fids[newfid] = name
                        payload = struct.pack("<H", count) + (qid(name) if count else b"")
                        if count and name in (b"open-one", b"open-two"):
                            walk_pair[name] = (tag, payload)
                            if len(walk_pair) == 2:
                                for pending_tag, data in reversed(walk_pair.values()):
                                    connection.sendall(struct.pack("<IBH", len(data) + 7, 111, pending_tag) + data)
                                walk_pair.clear()
                                reversed_walks = True
                            continue
                        if count and name == b"walk-cancel" and name not in flushed:
                            canceled_fid = newfid
                            canceled = (tag, name, b"")
                            continue
                        if not count and name == b"clone-cancel" and name not in flushed:
                            canceled_fid = newfid
                            canceled = (tag, name, b"")
                            continue
                elif kind == 112:
                    fid = struct.unpack_from("<I", body)[0]
                    name = fids[fid]
                    if name in (b"open-cancel", b"open-kill") and name not in flushed:
                        canceled = (tag, name, b"")
                        if name == b"open-kill" and (ready := held.pop(b"open-kill-ready", None)) is not None:
                            connection.sendall(struct.pack("<IBHIc", 12, 117, ready, 1, b"r"))
                        continue
                    opened.add(fid)
                    if body[4] & 0x10:
                        if not name:
                            raise RuntimeError("client tried to truncate the mount root")
                        files[name].clear()
                    payload = qid(name) + struct.pack("<I", 64 if name == b"chunked" else 0)
                    if name in (b"open-one", b"open-two"):
                        if name in open_pair or tag in (entry[0] for entry in open_pair.values()):
                            raise RuntimeError("invalid overlapping open requests")
                        open_pair[name] = (tag, payload)
                        if len(open_pair) == 2:
                            for pending_tag, data in reversed(open_pair.values()):
                                connection.sendall(struct.pack("<IBH", len(data) + 7, 113, pending_tag) + data)
                            open_pair.clear()
                            reversed_opens = True
                        continue
                elif kind == 114:
                    fid, length = struct.unpack_from("<IH", body)
                    name = body[6:6 + length]
                    if name == b"create-cancel" and name not in flushed:
                        canceled = (tag, name, b"")
                        continue
                    files[name] = bytearray()
                    fids[fid] = name
                    payload = qid(name) + struct.pack("<I", 64 if name == b"chunked" else 0)
                elif kind in (116, 118):
                    fid, offset, count = struct.unpack_from("<IQI", body)
                    name = fids[fid]
                    if name == b"chunked" and count > 64:
                        raise RuntimeError(f"request exceeds iounit: {count}")
                    if kind == 116:
                        if name == b"union-arm":
                            union_armed = True
                        if union_armed and name in (b"", b"union-release"):
                            if not name:
                                data = b"".join(stat(key, value) for key, value in files.items())[offset:offset + count]
                                union_read = (tag, data)
                            else:
                                union_release = tag
                            if union_read is not None and union_release is not None:
                                pending_tag, data = union_read
                                connection.sendall(struct.pack("<IBHIc", 12, 117, union_release, 1, b"r"))
                                connection.sendall(struct.pack("<IBHI", len(data) + 11, 117, pending_tag, len(data)) + data)
                                union_read = union_release = None
                                union_armed = False
                                union_overlapped = True
                            continue
                        if name in (b"list-one", b"list-two") and offset == 0:
                            if name in held or tag in held.values():
                                raise RuntimeError("invalid overlapping LIST reads")
                            held[name] = tag
                            if len(held) == 2:
                                for directory, pending_tag in reversed(held.items()):
                                    data = stat(files[directory], b"")
                                    connection.sendall(struct.pack("<IBHI", 11 + len(data), 117, pending_tag, len(data)) + data)
                                held.clear()
                                reversed_lists = True
                            continue
                        if name in (b"dir-one", b"dir-two"):
                            if offset != 0 or name in held or tag in held.values():
                                raise RuntimeError("invalid overlapping directory reads")
                            held[name] = tag
                            if len(held) == 2:
                                for directory, pending_tag in reversed(held.items()):
                                    data = stat(files[directory], b"")
                                    connection.sendall(struct.pack("<IBHI", 11 + len(data), 117, pending_tag, len(data)) + data)
                                held.clear()
                                reversed_directories = True
                            continue
                        if name.startswith((b"parallel-", b"drop-")):
                            if name in held or tag in held.values():
                                raise RuntimeError("duplicate in-flight 9P request")
                            held[name] = tag
                            if len(held) == 2:
                                if disconnect:
                                    return
                                for file_name, pending_tag in reversed(held.items()):
                                    connection.sendall(struct.pack("<IBHIc", 12, 117, pending_tag, 1, files[file_name]))
                                held.clear()
                                reversed_requests = True
                            continue
                        if name == b"cancel-one":
                            canceled = (tag, name, b"")
                            continue
                        if name == b"cancel-two":
                            held[name] = tag
                            continue
                        if name == b"killed":
                            canceled = (tag, name, b"")
                            if (ready := held.pop(b"kill-ready", None)) is not None:
                                connection.sendall(struct.pack("<IBHIc", 12, 117, ready, 1, b"r"))
                            continue
                        if name == b"kill-ready" and (canceled is None or canceled[1] != b"killed"):
                            held[name] = tag
                            continue
                        if name == b"kill-done" and b"killed" not in flushed:
                            raise RuntimeError("killing a blocked process did not flush its 9P request")
                        if name == b"remove-kill-ready" and (canceled is None or canceled[1] != b"remove-kill"):
                            held[name] = tag
                            continue
                        if name == b"open-kill-ready" and (canceled is None or canceled[1] != b"open-kill"):
                            held[name] = tag
                            continue
                        if name == b"open-kill-done":
                            if open_flush_tag is None:
                                raise RuntimeError("killing a blocked opener did not flush its Topen")
                            connection.sendall(struct.pack("<IBHIc", 12, 117, tag, 1, b"d"))
                            connection.sendall(struct.pack("<IBH", 7, 109, open_flush_tag))
                            open_flush_tag = None
                            open_kill_released = True
                            continue
                        if name == b"clunk-ready" and clunk_tag is None:
                            held[name] = tag
                            continue
                        if name == b"clunk-read":
                            if clunk_tag is None:
                                raise RuntimeError("read did not overlap a pending clunk")
                            connection.sendall(struct.pack("<IBHIc", 12, 117, tag, 1, b"r"))
                            connection.sendall(struct.pack("<IBH", 7, 121, clunk_tag))
                            clunk_tag = None
                            completed_clunks += 1
                            continue
                        if name == b"shared-offset":
                            if offset != shared_offset or count != 1:
                                raise RuntimeError(f"invalid shared fid read: offset={offset}, count={count}")
                            if offset == 0:
                                time.sleep(0.25)
                            shared_offset += offset < len(files[name])
                        if name in (b"flush", b"flush-race") and name not in flushed:
                            partial = b""
                            if name == b"flush-race":
                                data = files[name]
                                complete = struct.pack("<IBHI", 11 + len(data), 117, tag, len(data)) + data
                                connection.sendall(complete[:3])
                                partial = complete[3:]
                            canceled = (tag, name, partial)
                            continue
                        if name in (b"listing", b"list-one", b"list-two", b"list-cancel"):
                            first = stat(files[name] or b"first", b"")
                            if offset == 0:
                                data = first
                            elif offset == len(first) and name in (b"listing", b"list-cancel") and name not in flushed:
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
                        elif name in (b"write-one", b"write-two"):
                            expected = b"1" if name == b"write-one" else b"22"
                            if name in writes or tag in (entry[0] for entry in writes.values()) or (
                                    offset, count, body[16:]) != (0, len(expected), expected):
                                raise RuntimeError(f"invalid concurrent write to {name!r}")
                            files[name][:] = expected
                            writes[name] = (tag, count)
                            if len(writes) == 2:
                                for pending_tag, written in reversed(writes.values()):
                                    connection.sendall(struct.pack("<IBHI", 11, 119, pending_tag, written))
                                writes.clear()
                                reversed_writes = True
                            continue
                        else:
                            files[name][offset:offset + count] = body[16:]
                        payload = struct.pack("<I", count)
                elif kind in (120, 122):
                    fid = struct.unpack_from("<I", body)[0]
                    name = fids[fid]
                    if kind == 122 and name == b"remove-cancel" and name not in flushed:
                        canceled_fid = fid
                        canceled = (tag, name, b"")
                        continue
                    if kind == 122 and name == b"remove-kill":
                        del fids[fid]
                        error = string(b"permission denied")
                        canceled = (tag, name, struct.pack("<IBH", 7 + len(error), 107, tag) + error)
                        if (ready := held.pop(b"remove-kill-ready", None)) is not None:
                            connection.sendall(struct.pack("<IBHIc", 12, 117, ready, 1, b"r"))
                        continue
                    name = fids.pop(fid)
                    if fid == canceled_fid:
                        if name not in flushed:
                            raise RuntimeError("clunked a walk's destination before Rflush")
                        canceled_fid = None
                    was_opened = fid in opened
                    opened.discard(fid)
                    if name == b"open-kill" and not open_kill_released:
                        raise RuntimeError("clunked a killed opener's fid before Rflush")
                    if kind == 122:
                        del files[name]
                    elif name == b"clunk-hold" and was_opened:
                        if clunk_tag is not None:
                            raise RuntimeError("duplicate clunk while an Rclunk is withheld")
                        clunk_tag = tag
                        if (ready := held.pop(b"clunk-ready", None)) is not None:
                            connection.sendall(struct.pack("<IBHIc", 12, 117, ready, 1, b"c"))
                        continue
                elif kind == 124:
                    name = fids[struct.unpack_from("<I", body)[0]]
                    if name in (b"stat-cancel", b"path-cancel") and name not in flushed:
                        canceled = (tag, name, b"")
                        continue
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
                if kind in (124, 126):
                    prefix, _, suffix = name.partition(b"-")
                    expected = b"one" if kind == 124 else b"two"
                if kind in (124, 126) and prefix in metadata and suffix == expected and prefix not in reversed_metadata:
                    pair = metadata[prefix]
                    if kind in pair or tag in (entry[0] for entry in pair.values()):
                        raise RuntimeError("invalid overlapping metadata requests")
                    pair[kind] = (tag, reply, payload)
                    if len(pair) == 2:
                        for pending_tag, pending_reply, data in reversed(pair.values()):
                            connection.sendall(struct.pack("<IBH", len(data) + 7, pending_reply, pending_tag) + data)
                        pair.clear()
                        reversed_metadata.add(prefix)
                    continue
                connection.sendall(struct.pack("<IBH", len(payload) + 7, reply, tag) + payload)
    required = {100, 104, 110, 112, 116, 118, 120}
    if not factotum:
        required.update({102, 108, 114, 122, 124, 126})
    if (disconnect or fids or not required.issubset(requests) or not factotum
            and (not reversed_requests or not reversed_directories or not reversed_lists or held or not reversed_writes or writes
                 or not reversed_opens or open_pair or open_flush_tag is not None
                 or not reversed_walks or walk_pair or canceled_fid is not None or not union_overlapped
                 or reversed_metadata != metadata.keys() or any(metadata.values()) or completed_clunks != 2
                 or shared_offset != 2 or modes.get(b"metadata-two") != 0o640 or modes.get(b"path-two") != 0o620
                 or modes.get(b"new") != 0o600
                 or flushed != {b"flush", b"flush-race", b"listing", b"cancel-one", b"killed", b"stat-cancel",
                                b"path-cancel", b"list-cancel", b"open-cancel", b"open-kill", b"walk-cancel",
                                b"clone-cancel", b"create-cancel", b"remove-cancel", b"remove-kill"})):
        raise RuntimeError(f"incomplete 9P exchange, live fids {fids}, requests {requests}")


def expect_line(shell, command, expected, timeout=25):
    output = shell.command(command, timeout).partition(b"\n")[2]
    if expected not in output.splitlines():
        raise RuntimeError(f"{command!r}: expected {expected!r}, got {output!r}")


def publish_tcp(shell, port, service):
    path = b"/srv/" + service
    expect_line(shell, b"{ id=`{cat <[0=8]}; echo 'connect 10.0.2.2!" + str(port).encode()
                + b"' >[1=8] && { echo 9 > " + path + b" } <>[9]/net/tcp/$id/data } "
                b"<>[8]/net/tcp/clone; ls /srv", path)


def listen_local(listener):
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(25)
    return listener.getsockname()[1]


def check_acid_registers(output, pc, sp):
    match = re.search(rb"P9REG[ \t]+(0x[0-9a-f]+)[ \t]+(0x[0-9a-f]+)[ \t]+(0x[0-9a-f]+)", output, re.IGNORECASE)
    if not match or tuple(int(value, 16) for value in match.groups()) != (pc, sp, 0x37C11FC3B5E2A069):
        raise RuntimeError(f"acid could not recover the guest PC, SP and crash-stack marker: {output!r}")


def prepare_native_acid_iso(source, destination):
    replacements = {
        "/cfg/plan9.ini": b"cdboot=yes\nconsole=0\nvgasize=text\nbootfile=/amd64/9pc64\n",
        "/usr/glenda/lib/profile": (
            b"dossrv -r -f /dev/sdC0/data\n"
            b"mount /srv/dos /n/dos\n"
            b"acid -m amd64 -l /n/dos/crash.acid /n/dos/crash.core </n/dos/acid.in\n"
            b"echo P9NATIVE-END\n"
        ),
    }
    args = ["xorriso", "-indev", str(source)]
    for name in replacements:
        args += ["-find", name, "-exec", "report_lba", "--"]
    result = subprocess.run(args, capture_output=True, timeout=20, text=True)
    if result.returncode:
        raise RuntimeError(f"cannot read 9front ISO layout: {result.stderr.strip()}")
    layout = result.stdout
    image_size = source.stat().st_size
    shutil.copyfile(source, destination)
    with destination.open("r+b") as image:
        for name, contents in replacements.items():
            pattern = rf"^File data lba:\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'{re.escape(name)}'$"
            extents = re.findall(pattern, layout, re.MULTILINE)
            if len(extents) != 1:
                raise ValueError(f"expected one ISO extent for {name} in {source}")
            extent, block, blocks, size = map(int, extents[0])
            if extent != 0 or len(contents) > size or size > blocks * 2048 or block * 2048 + size > image_size:
                raise ValueError(f"cannot replace {name} in {source}")
            image.seek(block * 2048)
            image.write(contents.ljust(size, b"\n"))


def check_native_acid(source, core, module, pc, sp, marker_address, log_path):
    directory = core.parent
    iso = directory / "9front.iso"
    disk = directory / "payload.img"
    commands = directory / "acid.in"
    prepare_native_acid_iso(source, iso)
    commands.write_text(f'print("P9REG ", p9pc, " ", p9sp, " ", p9read64({marker_address:#x}), "\\n");\n')
    with disk.open("xb") as payload:
        payload.truncate(8 << 20)
    subprocess.run(["mformat", "-i", disk, "::"], check=True, timeout=20)
    subprocess.run(["mcopy", "-i", disk, core, "::crash.core"], check=True, timeout=20)
    subprocess.run(["mcopy", "-i", disk, module, commands, "::"], check=True, timeout=20)
    qemu = ["qemu-system-x86_64", "-cpu", "max", "-m", "512", "-boot", "d", "-cdrom", str(iso),
            "-drive", f"file={disk},format=raw,snapshot=on", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none"]
    try:
        with log_path.open("wb", buffering=0) as log, selectors.DefaultSelector() as selector, \
                subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT) as process:
            try:
                serial = SerialShell(process, selector, log)
                serial.read_until(re.compile(rb"bootargs is [^\r\n]+\] "), 90, "9front boot prompt")
                serial.send(b"")
                serial.read_until(re.compile(rb"user\[glenda\]: "), 60, "9front login prompt")
                serial.send(b"")
                output = serial.read_until(re.compile(rb"P9NATIVE-END\r?\n"), 90, "9front acid result")
                check_acid_registers(output, pc, sp)
            finally:
                process.kill()
    except (OSError, RuntimeError) as error:
        raise RuntimeError(f"9front acid failed: {error}; see {log_path}") from error


def check_acid(shell, acid, native_iso, native_log):
    acid = Path(acid).resolve(strict=True)
    result = shell.command(b"/bin/aux/procsmoke crash-snapshot", 90)
    match = re.search(rb"^crash registers (\d+) (\d+) (\d+)$", result, re.MULTILINE)
    if not match or b"crash snapshot verified" not in result.splitlines():
        raise RuntimeError(f"guest did not capture a crashed process: {result!r}")
    pc, sp, marker_address = map(int, match.groups())

    def receive_snapshot(listener, snapshot):
        with listener.accept()[0] as connection, snapshot.open("xb") as output:
            connection.settimeout(20)
            size = 0
            while chunk := connection.recv(65536):
                size += len(chunk)
                if size > 16 << 20:
                    raise RuntimeError("unexpectedly large crash snapshot")
                output.write(chunk)

    with tempfile.TemporaryDirectory(prefix="plan9-acid-") as directory:
        snapshot, text, core = (Path(directory) / name for name in ("crash.snap", "text", "core"))
        with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as workers:
            port = str(listen_local(listener)).encode()
            receiving = workers.submit(receive_snapshot, listener, snapshot)
            expect_line(shell, b"{ id=`{cat <[0=8]}; echo 'connect 10.0.2.2!" + port + b"' >[1=8] && "
                        b"cat /tmp/procsmoke.snap >/net/tcp/$id/data } <>[8]/net/tcp/clone && echo snapshot-sent",
                        b"snapshot-sent", 60)
            receiving.result(timeout=25)
        module = Path(directory) / "crash.acid" if native_iso else None
        convert_snapshot(snapshot, text, core, module)
        command = (f'print("P9REG ", fmt(*PC, \'Y\'), " ", fmt(*SP, \'Y\'), " ", *fmt({marker_address:#x}, \'Y\'), "\\n");\n'
                   'print("P9FN ", fnbound(*PC - 0x40000000), "\\n");\n')
        environment = dict(os.environ, PLAN9=str(acid.parent.parent), PATH=f"{acid.parent}{os.pathsep}{os.defpath}")
        result = subprocess.run([acid, core, text], input=command.encode(), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=environment, timeout=20)
        if result.returncode:
            raise RuntimeError(f"plan9port acid exited with {result.returncode}: {result.stdout!r}")
        check_acid_registers(result.stdout, pc, sp)
        bounds = re.search(rb"P9FN \{(0x[0-9a-f]+), (0x[0-9a-f]+)\}", result.stdout, re.IGNORECASE)
        if not bounds:
            raise RuntimeError(f"acid could not resolve the guest crash function: {result.stdout!r}")
        start, end = (int(value, 16) + 0x40000000 for value in bounds.groups())
        if not start <= pc < end or end - start > 64:
            raise RuntimeError(f"acid resolved incorrect crash function bounds: {result.stdout!r}")
        if native_iso:
            check_native_acid(native_iso, core, module, pc, sp, marker_address, native_log)
            print("x86_64: 9front acid reads crash registers and stack memory")


def check_9p_mount(shell):
    def expect(command, expected, timeout=25):
        expect_line(shell, command, expected, timeout)

    with socket.socket() as listener, socket.socket() as agent, ThreadPoolExecutor(max_workers=2) as workers:
        publish_tcp(shell, listen_local(agent), b"smokefactotum")
        factotum = workers.submit(serve_9p, agent, True)
        expect(b"mkdir /mnt/factotum; @ { cd /srv && mount -n ./smokefactotum /mnt/factotum } && echo factotum-mounted",
               b"factotum-mounted")
        expect(b"mkdir /tmp/mnt-factotum; @ { rfork nm && { mount -n smokefactotum /tmp/mnt-factotum || echo mount-blocked } }",
               b"mount-blocked")
        expect(b"mount -n smokefactotum /tmp/mnt-factotum && unmount /tmp/mnt-factotum && cat /mnt/factotum/rpc && echo session-reused",
               b"session-reused")
        publish_tcp(shell, listen_local(listener), b"smoke9p")
        expect(b"chmod 600 /srv/smoke9p && ls -l /srv/smoke9p", b"-600 0 /srv/smoke9p")
        peer = workers.submit(serve_9p, listener)
        expect(b"mkdir /tmp/mnt9p; mount -k 'user=root' smoke9p /tmp/mnt9p test-tree && ls /tmp/mnt9p", b"/tmp/mnt9p/remote")
        expect(b"cat /tmp/mnt9p/remote", b"hello-9p")
        expect(b"@ { cd /tmp/mnt9p && cat remote }", b"hello-9p")
        expect(b"touch /tmp/remotebind; bind /tmp/mnt9p/remote /tmp/remotebind && cat /tmp/remotebind", b"hello-9p")
        expect(b"unmount /tmp/remotebind && echo remote-bind-removed", b"remote-bind-removed")
        expect(b"echo /tmp/mnt9p/remot*", b"/tmp/mnt9p/remote")
        expect(b"/bin/aux/procsmoke mount-io", b"mount-io-ok")
        expect(b"touch /tmp/clone-cancel; /bin/aux/procsmoke mount-mutations", b"mount-mutations-ok")
        expect(b"/bin/aux/procsmoke mount-parallel", b"mount-parallel-ok")
        expect(b"mkdir /tmp/local9p; touch /tmp/local9p/local; bind -b /tmp/local9p /tmp/mnt9p && "
               b"/bin/aux/procsmoke mount-union", b"mount-union-ok")
        expect(b"unmount /tmp/local9p /tmp/mnt9p && echo union-unmounted", b"union-unmounted")
        expect(b"echo from-client > /tmp/mnt9p/new; cat /tmp/mnt9p/new", b"from-client")
        expect(b"echo shorter > /tmp/mnt9p/new; cat /tmp/mnt9p/new", b"shorter")
        expect(b"chmod 600 /tmp/mnt9p/new && rm /tmp/mnt9p/new && echo remote-wstat-remove", b"remote-wstat-remove")
        expect(b"{ unmount /srv/smoke9p /tmp/mnt9p; cat } < /tmp/mnt9p/remote", b"hello-9p")
        expect(b"rm /srv/smoke9p && echo service-removed", b"service-removed")
        peer.result(timeout=10)
        expect(b"unmount /mnt/factotum && rm /srv/smokefactotum && echo factotum-removed", b"factotum-removed")
        factotum.result(timeout=10)
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as workers:
        port = listen_local(listener)
        peer = workers.submit(serve_9p, listener, disconnect=True)
        publish_tcp(shell, port, b"drop9p")
        expect(b"mkdir /tmp/drop9p; mount -n drop9p /tmp/drop9p && /bin/aux/procsmoke mount-disconnect",
               b"mount-disconnect-ok")
        expect(b"unmount /tmp/drop9p && rm /srv/drop9p && echo drop-cleanup", b"drop-cleanup")
        peer.result(timeout=10)


def relay_factotum(listener, endpoint, log):
    with listener.accept()[0] as guest, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as host, \
            selectors.DefaultSelector() as selector:
        host.connect(str(endpoint))
        pending = {guest: bytearray(), host: bytearray()}
        for source, target in ((guest, host), (host, guest)):
            source.settimeout(5)
            selector.register(source, selectors.EVENT_READ, target)
        while selector.get_map():
            events = selector.select(90)
            if not events:
                raise RuntimeError("factotum relay timed out")
            for key, _ in events:
                data = key.fileobj.recv(8192)
                if data:
                    key.data.sendall(data)
                    frames = pending[key.fileobj]
                    frames.extend(data)
                    while len(frames) >= 7:
                        size, kind, tag = struct.unpack_from("<IBH", frames)
                        if not 7 <= size <= 1024 * 1024:
                            raise RuntimeError("invalid frame on factotum relay")
                        if size > len(frames):
                            break
                        log.write(f"factotum 9P type={kind} tag={tag} size={size}\n".encode())
                        if kind == 107:
                            log.write(b"factotum 9P error: " + frames[9:size] + b"\n")
                        elif kind == 117 and frames[11:size].startswith(b"error "):
                            log.write(b"factotum RPC error: " + frames[17:size] + b"\n")
                        del frames[:size]
                else:
                    selector.unregister(key.fileobj)
                    key.data.shutdown(socket.SHUT_WR)


def format_venti(binaries, environment, directory, log):
    arena = directory / "venti.arena"
    index = directory / "venti.index"
    config = directory / "venti.conf"
    for path, size in ((arena, 64), (index, 16)):
        with path.open("wb") as image:
            image.truncate(size * 1024 * 1024)
    config.write_text(f"index smoke\narenas {arena}\nisect {index}\n")
    for command in (("fmtarenas", "-a", "16m", "smoke", arena),
                    ("fmtisect", "smoke", index), ("fmtindex", config)):
        subprocess.run([binaries / "venti" / command[0], *command[1:]], env=environment,
                       stdout=log, stderr=log, timeout=20, check=True)
    return config


@contextmanager
def venti_server(binaries, environment, config, log, readonly=False):
    with socket.socket() as reserve, socket.socket() as http_reserve:
        reserve.bind(("127.0.0.1", 0))
        http_reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        http_port = http_reserve.getsockname()[1]
    address = f"tcp!127.0.0.1!{port}"
    argv = [binaries / "venti/venti", "-s", "-a", address, "-c", config]
    if readonly:
        argv.append("-r")
    else:
        argv.extend(("-h", f"tcp!127.0.0.1!{http_port}"))
    with subprocess.Popen(argv,
                          env=dict(environment, NOLIBTHREADDAEMONIZE="1"),
                          stdout=log, stderr=log, start_new_session=True) as server:
        try:
            deadline = time.monotonic() + 15
            while True:
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Venti did not start listening")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        break
                except OSError:
                    time.sleep(0.05)
            yield address, http_port
        finally:
            try:
                os.killpg(server.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            server.wait(timeout=5)


def sync_venti(binaries, environment, address, http_port, log):
    subprocess.run([binaries / "venti/sync", "-h", address], env=environment,
                   stdout=log, stderr=log, timeout=20, check=True)
    requests = (("/set?name=l0quantum&value=0", b"l0quantum = 0"),
                ("/flushicache", b"flushed icache"), ("/flushdcache", b"flushed dcache"))
    for endpoint, expected in requests:
        http = HTTPConnection("127.0.0.1", http_port, timeout=20)
        try:
            http.request("GET", endpoint, headers={"Connection": "close"})
            response = http.getresponse()
            result = response.read()
            if response.status != 200 or expected not in result:
                raise RuntimeError(f"Venti {endpoint} failed: {response.status} {result!r}")
        finally:
            http.close()


@contextmanager
def fossil_console(binaries, environment, disk, venti_address, log):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    master, slave = pty.openpty()
    tty.setraw(slave)
    commands = [f"fsys main config {disk}"]
    if venti_address:
        commands.append(f"fsys main venti {venti_address}")
    commands.extend(("fsys main open -P -c 1000", "uname root :root", f"listen tcp!127.0.0.1!{port}"))
    argv = ["setsid", "--ctty", binaries / "fossil/fossil", "-t"]
    for command in commands:
        argv.extend(("-c", command))
    try:
        with subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                              env=dict(environment, NOLIBTHREADDAEMONIZE="1")) as server, \
                selectors.DefaultSelector() as selector:
            try:
                selector.register(master, selectors.EVENT_READ)
                pending = b""

                def wait_output(pattern, timeout=20):
                    nonlocal pending
                    deadline = time.monotonic() + timeout
                    while not (match := re.search(pattern, pending)):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise RuntimeError(f"Fossil console timed out: {pending!r}")
                        chunk = os.read(master, 8192)
                        if not chunk:
                            raise RuntimeError("Fossil console closed unexpectedly")
                        log.write(chunk)
                        pending += chunk
                    output, pending = pending[:match.start()], pending[match.end():]
                    return output, match

                def console(command=None, expected=rb""):
                    if command is not None:
                        os.write(master, command + b"\n")
                    output, _ = wait_output(rb"prompt: ")
                    if command is not None:
                        _, echoed, result = output.replace(b"\r", b"").partition(command + b"\n")
                        match = re.fullmatch(expected, result.strip())
                        if not echoed or match is None:
                            raise RuntimeError(f"Fossil console rejected {command!r}: {output!r}")
                        return match

                console()
                yield port, console, wait_output
            finally:
                server.kill()
                server.wait(timeout=5)
                while selector.select(0):
                    chunk = os.read(master, 8192)
                    if not chunk:
                        break
                    log.write(chunk)
    finally:
        os.close(master)
        os.close(slave)


def check_fossil_recovery(shell, binaries, environment, disk, venti_address, log):
    with fossil_console(binaries, environment, disk, venti_address, log) as (port, console, _):
        publish_tcp(shell, port, b"fossil")
        expect_line(shell, b"mount -n fossil /tmp/fossil || echo auth-required", b"auth-required")
        expect_line(shell, b"mount -k 'user=root' fossil /tmp/fossil && "
                    b"echo before > /tmp/fossil/version && cat /tmp/fossil/version", b"before")
        expect_line(shell, b"/bin/aux/procsmoke crash-snapshot && cp /tmp/procsmoke.snap /tmp/fossil/crash.snap && "
                    b"chmod 600 /tmp/fossil/crash.snap && "
                    b"cmp /tmp/procsmoke.snap /tmp/fossil/crash.snap && echo crash-snapshot-copied",
                    b"crash-snapshot-copied", timeout=90)
        console(b"fsys main snap -s /active -d /snapshot/smoke")
        expect_line(shell, b"echo after > /tmp/fossil/version && cat /tmp/fossil/version", b"after")
        console(b"fsys main sync", rb"main sync: wrote [0-9]+ blocks")
        expect_line(shell, b"mkdir /tmp/fossil/in-flight && echo pending > /tmp/fossil/in-flight/draft && "
                    b"mv /tmp/fossil/in-flight/draft /tmp/fossil/in-flight/renamed && "
                    b"cat /tmp/fossil/in-flight/renamed", b"pending")
    expect_line(shell, b"cat /tmp/fossil/version || echo server-lost", b"server-lost")
    expect_line(shell, b"unmount /tmp/fossil && rm /srv/fossil && echo disconnected", b"disconnected")
    with fossil_console(binaries, environment, disk, venti_address, log) as (port, console, wait_output):
        publish_tcp(shell, port, b"fossil")
        expect_line(shell, b"mount -k 'user=root' fossil /tmp/fossil && cat /tmp/fossil/version", b"after")
        expect_line(shell, b"mount -k 'user=root' fossil /tmp/snapshot main/snapshot && "
                    b"cat /tmp/snapshot/smoke/version", b"before")
        expect_line(shell, b"cmp /tmp/procsmoke.snap /tmp/fossil/crash.snap && "
                    b"cmp /tmp/procsmoke.snap /tmp/snapshot/smoke/crash.snap && echo crash-snapshot-reopened",
                    b"crash-snapshot-reopened", timeout=90)
        expect_line(shell, b"echo forbidden > /tmp/snapshot/smoke/version || echo snapshot-read-only",
                    b"snapshot-read-only")
        expect_line(shell, b"echo writable > /tmp/fossil/recovered && cat /tmp/fossil/recovered", b"writable")
        expect_line(shell, b"unmount /tmp/snapshot && unmount /tmp/fossil && rm /srv/fossil && "
                    b"echo filesystem-cleanup", b"filesystem-cleanup")
        score_pattern = rb"archive vac:([0-9a-f]{40})"
        archive = console(b"fsys main snap -a", rb"(?:" + score_pattern + rb")?")
        if archive[1] is None:
            _, archive = wait_output(score_pattern + rb"\r?\n", timeout=60)
        return archive[1].decode()


def check_venti_restore(shell, binaries, environment, restored, venti_address, score, log):
    with restored.open("xb") as image:
        image.truncate(64 * 1024 * 1024)
    subprocess.run([binaries / "fossil/flfmt", "-y", "-h", venti_address, "-v", score, restored],
                   env=environment, stdout=log, stderr=log, timeout=25, check=True)
    with fossil_console(binaries, environment, restored, venti_address, log) as (port, _, _):
        publish_tcp(shell, port, b"fossil")
        expect_line(shell, b"mount -k 'user=root' fossil /tmp/fossil && echo venti-restored", b"venti-restored")
        expect_line(shell, b"cat /tmp/fossil/version", b"after")
        expect_line(shell, b"cat /tmp/fossil/recovered", b"writable")
        expect_line(shell, b"cmp /tmp/procsmoke.snap /tmp/fossil/crash.snap && echo crash-snapshot-restored",
                    b"crash-snapshot-restored", timeout=90)
        expect_line(shell, b"unmount /tmp/fossil && rm /srv/fossil /tmp/procsmoke.snap && echo archive-cleanup",
                    b"archive-cleanup")


@contextmanager
def native_factotum(binaries, environment, address, key, log):
    endpoint = Path(environment["NAMESPACE"]) / "factotum"
    with subprocess.Popen([binaries / "factotum", "-n", "-s", "factotum", "-a", address],
                          env=environment, stdout=log, stderr=log, start_new_session=True) as agent:
        try:
            deadline = time.monotonic() + 10
            while not endpoint.is_socket():
                if agent.poll() not in (None, 0) or time.monotonic() >= deadline:
                    raise RuntimeError("plan9port factotum did not publish its socket")
                time.sleep(0.05)
            subprocess.run([binaries / "9p", "write", "factotum/ctl"], env=environment,
                           input=(key + "\n").encode(), stdout=log, stderr=log, timeout=10, check=True)
            yield endpoint
        finally:
            children = subprocess.run(["ps", "-s", str(agent.pid), "-o", "pid="],
                                      capture_output=True, timeout=5, check=False)
            for pid in map(int, children.stdout.split()):
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            agent.wait(timeout=5)


@contextmanager
def mount_factotum(shell, endpoint, log):
    with socket.socket() as relay, ThreadPoolExecutor(max_workers=1) as worker:
        port = listen_local(relay)
        future = worker.submit(relay_factotum, relay, endpoint, log)
        try:
            publish_tcp(shell, port, b"nativefactotum")
            expect_line(shell, b"mkdir /mnt/factotum; "
                        b"mount -n nativefactotum /mnt/factotum && echo agent-ready", b"agent-ready")
            yield
        finally:
            shell.command(b"unmount /mnt/factotum; rm /srv/nativefactotum")
        future.result(timeout=10)


def ticket_relay(listener, server_port, enabled, finished, observed, log):
    listener.settimeout(0.25)
    while not finished.is_set():
        try:
            client, _ = listener.accept()
        except TimeoutError:
            continue
        with client:
            client.settimeout(5)
            with client.makefile("rb") as stream:
                request = stream.read(P9SK1_TICKET_REQUEST_SIZE)
            if len(request) != P9SK1_TICKET_REQUEST_SIZE or request[0] != 1:
                raise RuntimeError("expected a p9sk1 ticket request")
            identity = tuple(field.rstrip(b"\0") for field in (request[1:29], request[85:113], request[113:141]))
            if identity != (b"fossilhost", b"root", b"root"):
                raise RuntimeError(f"unexpected p9sk1 ticket identities: {identity!r}")
            if not enabled.is_set():
                observed.put("offline")
                continue
            with socket.create_connection(("127.0.0.1", server_port), timeout=5) as server:
                server.sendall(request)
                with server.makefile("rb") as stream:
                    status = stream.read(1)
                    if status != b"\x04":
                        raise RuntimeError(f"native authsrv did not return AuthOK: {status!r}")
                    tickets = stream.read(P9SK1_TICKET_PAIR_SIZE)
                    if len(tickets) != P9SK1_TICKET_PAIR_SIZE:
                        raise RuntimeError("native authsrv returned incomplete tickets")
            log.write(b"native authsrv: AuthOK for authid=fossilhost hostid=root uid=root\n")
            client.sendall(status + tickets)
            observed.put("native-ticket")


def check_native_tickets(shell, binaries, environment, directory, disk, ticket_port, log):
    client_password = os.environ.get("PLAN9_TEST_CLIENT_PASSWORD", "")
    server_password = os.environ.get("PLAN9_TEST_SERVER_PASSWORD", "")
    if (not all(re.fullmatch(r"[!-~]{8,27}", password) for password in (client_password, server_password))
            or client_password == server_password):
        raise RuntimeError("set distinct disposable PLAN9_TEST_CLIENT_PASSWORD and "
                           "PLAN9_TEST_SERVER_PASSWORD (8 to 27 printable nonspace ASCII characters)")
    server_namespace = directory / "fs-agent"
    server_namespace.mkdir(mode=0o700)
    server_environment = dict(environment, NAMESPACE=str(server_namespace))
    enabled = threading.Event()
    finished = threading.Event()
    observed = Queue()
    with socket.socket() as relay, ThreadPoolExecutor(max_workers=1) as worker:
        address = f"tcp!127.0.0.1!{listen_local(relay)}"
        future = worker.submit(ticket_relay, relay, ticket_port, enabled, finished, observed, log)
        try:
            key = f"key proto=p9sk1 dom={address}"
            client_password = client_password.replace("'", "''")
            server_password = server_password.replace("'", "''")
            server_key = f"{key} role=server user=fossilhost !password='{server_password}'"
            client_key = f"{key} user=root !password='{client_password}'"
            with native_factotum(binaries, server_environment, address, server_key, log), \
                    native_factotum(binaries, environment, address, client_key, log) as endpoint, \
                    mount_factotum(shell, endpoint, log), \
                    fossil_console(binaries, server_environment, disk, None, log) as (port, _, _):
                shell.command(b"mkdir /tmp/fossil")
                publish_tcp(shell, port, b"fossil")
                try:
                    expect_line(shell, b"mount -k 'user=root' fossil /tmp/fossil || echo auth-offline", b"auth-offline")
                    enabled.set()
                    expect_line(shell, b"mount -k 'user=root' fossil /tmp/fossil && "
                                b"echo ticket-authenticated > /tmp/fossil/proof && cat /tmp/fossil/proof",
                                b"ticket-authenticated")
                finally:
                    shell.command(b"unmount /tmp/fossil; rm /srv/fossil")
        finally:
            finished.set()
            future.result(timeout=10)
    if observed.qsize() != 2 or [observed.get_nowait() for _ in range(2)] != ["offline", "native-ticket"]:
        raise RuntimeError("did not observe both the offline request and native ticket exchange")


def check_native_9p(shell, plan9, log, ticket_port):
    plan9 = Path(plan9).resolve(strict=True)
    binaries = plan9 / "bin"
    with tempfile.TemporaryDirectory(prefix="plan9-native9p-") as directory, socket.socket() as offline:
        directory = Path(directory)
        offline.bind(("127.0.0.1", 0))
        offline_address = f"tcp!127.0.0.1!{offline.getsockname()[1]}"
        environment = dict(os.environ, PLAN9=str(plan9), NAMESPACE=str(directory),
                           PATH=f"{binaries}{os.pathsep}{os.defpath}")
        environment.pop("NOLIBTHREADDAEMONIZE", None)
        disk = directory / "fossil.disk"
        with disk.open("wb") as image:
            image.truncate(64 * 1024 * 1024)
        subprocess.run([binaries / "fossil/flfmt", "-y", disk], env=environment,
                       stdout=log, stderr=log, timeout=20, check=True)
        if ticket_port is not None:
            check_native_tickets(shell, binaries, environment, directory, disk, ticket_port, log)
            return
        venti_config = format_venti(binaries, environment, directory, log)
        key = f"key proto=p9sk1 dom={offline_address} user=root !password=disposable-smoke-key"
        with native_factotum(binaries, environment, offline_address, key, log) as endpoint, \
                mount_factotum(shell, endpoint, log):
            shell.command(b"mkdir /tmp/fossil /tmp/snapshot")
            with venti_server(binaries, environment, venti_config, log) as (venti_address, http_port):
                score = check_fossil_recovery(shell, binaries, environment, disk, venti_address, log)
                sync_venti(binaries, environment, venti_address, http_port, log)
            disk.unlink()
            with venti_server(binaries, environment, venti_config, log, readonly=True) as (venti_address, _):
                check_venti_restore(shell, binaries, environment, directory / "restored.disk",
                                    venti_address, score, log)


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
    shell.send(b"netcat -l -m accepted '*' 8123")
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
    output = shell.read_prompt(25)
    if data != b"accepted" or b"incoming" not in output:
        raise RuntimeError(f"TCP listen failed: {data!r}, guest output: {output!r}")

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
            shell.send(b"netcat -u -l -m datagram '*' 8124")
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
        shell.send(b"netcat -u -l -H -n 2 '*' 8124")
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
        (b"echo 'dns=198.18.0.1' > /net/ndb; ndb/dnsquery wire.example", b"wire.example ip 198.19.0.9"),
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
            shell.send(b"netcat -u -l -H '*' 8124 > /tmp/ipmux-packet")
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


def check_rootdisk(qemu, log, directory):
    block = 4096
    size = 64 * 1024 * 1024
    image = Path(directory) / "root.img"
    create_image(image, "root", size)
    command = qemu + ["-drive", f"if=none,id=p9root,file={image},format=raw,cache=writeback",
                      "-device", "nvme,drive=p9root,serial=plan9-root"]
    for phase in range(3):
        if phase == 2:
            second_slot = 1 + (size // block - 1) // 2
            with image.open("r+b") as disk:
                disk.seek((second_slot + 1) * block)
                original = disk.read(1)
                disk.seek(-1, os.SEEK_CUR)
                disk.write(bytes([original[0] ^ 0xff]))
        with selectors.DefaultSelector() as selector, subprocess.Popen(command, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
            try:
                shell = SerialShell(process, selector, log)
                shell.read_prompt(90)
                if phase == 0:
                    units = [unit for unit in re.findall(rb"/dev/sd/sd\d+", shell.command(b"ls /dev/sd"))]
                    if len(units) != 1:
                        raise RuntimeError(f"expected one local NVMe device, found {units!r}")
                    ctl = units[0] + b"/ctl"
                    expect_line(shell, b"echo previous > /usr/root/durable && chmod 600 /usr/root/durable && echo rootsync > " +
                                ctl + b" && echo synced", b"synced", 90)
                    expect_line(shell, b"echo current > /usr/root/durable && echo rootsync > " + ctl + b" && echo synced",
                                b"synced", 90)
                    expect_line(shell, b"echo unsynced > /usr/root/durable && echo volatile > /usr/root/volatile && echo dirty", b"dirty")
                else:
                    expect_line(shell, b"cat /usr/root/durable", b"current" if phase == 1 else b"previous")
                    expect_line(shell, b"ls -l /usr/root/durable", b"-600 " + (b"8" if phase == 1 else b"9") + b" /usr/root/durable")
                    expect_line(shell, b"! test -e /usr/root/volatile && echo recovered", b"recovered")
            finally:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--mount", action="store_true")
    parser.add_argument("--panic", action="store_true")
    parser.add_argument("--dump", action="store_true")
    parser.add_argument("--cpu-service", action="store_true")
    parser.add_argument("--rc-reference")
    parser.add_argument("--acid")
    parser.add_argument("--native-acid-iso", type=Path)
    parser.add_argument("--rootdisk", action="store_true")
    parser.add_argument("--plan9port")
    parser.add_argument("--ticket-port", type=int)
    parser.add_argument("arch")
    parser.add_argument("log")
    parser.add_argument("qemu", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.acid and args.arch != "x86_64":
        parser.error("--acid requires the x86_64 guest")
    if args.native_acid_iso and not args.acid:
        parser.error("--native-acid-iso requires --acid")
    if args.ticket_port is not None and (not args.plan9port or not 1 <= args.ticket_port <= 65535):
        parser.error("--ticket-port requires --plan9port and a valid loopback port")
    qemu = args.qemu[1:] if args.qemu[:1] == ["--"] else args.qemu
    if not qemu:
        parser.error("expected a QEMU command after --")

    try:
        with tempfile.TemporaryDirectory(prefix="plan9-qmp-") as tmp, \
                open(args.log, "wb", buffering=0) as log, selectors.DefaultSelector() as selector, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock, \
                ThreadPoolExecutor(max_workers=1) as workers:
            if args.rootdisk:
                check_rootdisk(qemu, log, tmp)
            else:
                qmp_path = Path(tmp) / "qmp"
                if args.dump:
                    dump_image = Path(tmp) / "dump.img"
                    create_image(dump_image, "dump", 2 * int(qemu[qemu.index("-m") + 1]) << 20)
                    qemu += ["-drive", f"if=none,id=p9dump,file={dump_image},format=raw,cache=writeback",
                             "-device", "nvme,drive=p9dump,serial=plan9-dump"]
                peer, guest = socket.socketpair()
                with peer, guest:
                    run_qemu(args, qemu, qmp_path, peer, guest, workers, log, selector, sock)
                if args.dump:
                    with dump_image.open("rb") as disk:
                        machine, _, segments, diagnostic = dump_info(disk)
                        if machine != MACHINES[args.arch] or sum(length for _, length, _ in segments) < 64 << 20:
                            raise RuntimeError("incomplete physical memory map in panic dump")
                        if not diagnostic or not diagnostic.startswith(b"PANIC: ") \
                                or not re.search(rb"Kernel backtrace \(return PCs, sp=0x[0-9a-f]+\)", diagnostic):
                            raise RuntimeError("panic diagnostic missing from ELF note")
                        marker = b"Plan9RustUEFI\0"
                        found = False
                        for _, length, offset in segments:
                            disk.seek(PAGE + offset)
                            tail = b""
                            while length and not found:
                                chunk = disk.read(min(length, 1024 * 1024))
                                found = marker in tail + chunk
                                tail = chunk[-len(marker):]
                                length -= len(chunk)
                        if not found:
                            raise RuntimeError("boot loader marker missing from physical memory dump")
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"{args.arch}: {error}; see {args.log}", file=sys.stderr)
        return 1
    checks = ("DHCP, IPv4/IPv6 ICMP, TCP/UDP echo and listeners, UDP headers, DNS/CS, GRE, RUDP, ESP, ARP, ipmux, capture, dual-stack forwarding and traceroute" if args.network else
              "9P mount, authentication, fid lifetime, reply multiplexing, cancellation and disconnect" if args.mount else
              "panic diagnostics and saved physical memory dump" if args.dump else
              "formatted panic, kernel backtrace and reboot" if args.panic and args.cpu_service else
              "formatted panic, kernel backtrace and halt" if args.panic else
              "rc differential tests" if args.rc_reference else
              "plan9port acid reads crash registers, stack memory and function bounds" if args.acid else
              "local root sync, abrupt shutdown recovery and corrupt checkpoint fallback" if args.rootdisk else
              "native authsrv tickets with distinct client and server keys" if args.ticket_port else
              "plan9port factotum, Fossil crash recovery and Venti archive restore" if args.plan9port else
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
                elif args.panic or args.dump:
                    check_panic(shell, qmp, args.arch, args.cpu_service, args.dump)
                elif args.rc_reference:
                    shell.read_prompt(90)
                    check_rc_reference(shell, args.rc_reference)
                elif args.acid:
                    shell.read_prompt(90)
                    wait_for_dhcp(shell)
                    check_acid(shell, args.acid, args.native_acid_iso, Path(args.log).with_name("native-acid-serial.log"))
                elif args.plan9port:
                    shell.read_prompt(90)
                    wait_for_dhcp(shell)
                    with open(Path(args.log).with_name("native-9p-host.log"), "wb", buffering=0) as host_log:
                        check_native_9p(shell, args.plan9port, host_log, args.ticket_port)
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

#!/usr/bin/env python3
"""Verify the GOP menu, kernel display and interactive shell in QEMU."""

import argparse
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import tempfile
import time


PROMPT = re.compile(rb"root@plan9:[^\r\n]*> ")
COMMANDS = b"""
basename cat chmod chown clear cmp cp cut date dc diff dirname du echo ed env expr
false fortune grep group head hostname id kill ln ls mkdir more mv nl passwd printf
ps pwd rc rm rmdir seq sleep sort stat su tail tee test time touch tr true tty uname
uniq units uptime useradd usermod wc who whoami yes
""".split()
HELP_FOOTER = b"redirection: < > >>    pipelines: cmd | cmd    lists: cmd ; cmd"
MENU_MARKER = b"bootloader: GOP menu"
FRAMEBUFFER_MARKER = b"bootloader: GOP linear framebuffer found"
INTERACTIVE_SELECTION = b"bootloader: selected Boot Plan 9 (verbose)"


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

    def command(self, command):
        self.process.stdin.write(command + b"\r")
        self.process.stdin.flush()
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
    header = b"builtins: cd exit help\n\ncommands:\n"
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
    if b"[init] rc exited with status 0" not in shell.command(b"exit").splitlines():
        raise RuntimeError("init did not reap and restart rc after exit")
    check_help(shell.command(b"help"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            qmp_path = Path(tmp) / "qmp"
            with subprocess.Popen(qemu + ["-qmp", f"unix:{qmp_path},server=on,wait=off"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT) as process:
                try:
                    shell = SerialShell(process, selector, log)
                    connect_qmp(sock, qmp_path, process)
                    qmp = Qmp(sock)
                    with qmp.stream:
                        check_boot(args.arch, shell, qmp, Path(args.log).resolve().parent)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    except (OSError, RuntimeError) as error:
        print(f"{args.arch}: {error}; see {args.log}", file=sys.stderr)
        return 1
    print(f"{args.arch}: GOP menu, graphical console and keyboard, full help, uname, echo and rc respawn passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

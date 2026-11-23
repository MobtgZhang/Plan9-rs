#!/usr/bin/env python3
"""Extract a Plan9-rs x86_64 process snapshot for plan9port or native 9front acid."""

import argparse
from pathlib import Path
import struct


ELF_PAGE = 4096
SNAP_PAGE = 1024
MAX_USER_ADDRESS = 1 << 47
MAX_CAPTURE = 1 << 30
AMD64_REGISTERS = (
    "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "bp", "di", "si", "dx", "cx",
    "bx", "ax", "pc", "cs", "flags", "sp", "ss",
)


def read_exact(source, size):
    data = source.read(size)
    if len(data) != size:
        raise ValueError("truncated process snapshot")
    return data


def read_number(source):
    digits = bytearray()
    for _ in range(21):
        char = read_exact(source, 1)
        if char == b" ":
            break
        if not char.isdigit():
            raise ValueError("invalid snapshot number")
        digits.extend(char)
    else:
        raise ValueError("invalid snapshot number")
    padding = max(11 - len(digits), 0)
    if not digits or read_exact(source, padding) != b" " * padding:
        raise ValueError("invalid snapshot number")
    return int(digits)


def read_region(source, output, length):
    for offset in range(0, length, SNAP_PAGE):
        size = min(length - offset, SNAP_PAGE)
        tag = read_exact(source, 1)
        if tag == b"z":
            output.seek(size, 1)
        elif tag == b"r":
            output.write(read_exact(source, size))
        else:
            raise ValueError("invalid snapshot page tag")
    output.truncate(output.tell())


def status_note(pid, registers):
    order = (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 8, 13, 11, 12, 14)
    gregset = struct.pack("<15Q16x5Q", *(registers[index] for index in order), *registers[15:])
    status = struct.pack("<I4x3Q3I4x", 1, 48 + len(gregset), len(gregset), 0, 0, 0, pid)
    return struct.pack("<III8s", 8, len(status) + len(gregset), 1, b"FreeBSD\0") + status + gregset


def write_core(source, core, note):
    count = read_number(source)
    if not 0 < count <= (ELF_PAGE - 64) // 56 - 1:
        raise ValueError("invalid snapshot segment count")
    ident = b"\x7fELF\x02\x01\x01\x09".ljust(16, b"\0")
    programs = bytearray(struct.pack("<II6Q", 4, 0, ELF_PAGE, 0, 0, len(note), len(note), 4))
    core.seek(ELF_PAGE)
    core.write(note)
    offset = 2 * ELF_PAGE
    ranges = []
    mappings = []
    total = 0
    for _ in range(count):
        base, length = read_number(source), read_number(source)
        if not length:
            continue
        end = base + length
        total += length
        if (end > MAX_USER_ADDRESS or total > MAX_CAPTURE
                or any(base < previous_end and start < end for start, previous_end in ranges)):
            raise ValueError(f"invalid snapshot memory segment {base:#x}..{end:#x}")
        ranges.append((base, end))
        offset += base % ELF_PAGE
        mappings.append((base, end, offset))
        programs.extend(struct.pack("<II6Q", 1, 7, offset, base, base, length, length, ELF_PAGE))
        core.seek(offset)
        read_region(source, core, length)
        offset = (offset + length + ELF_PAGE - 1) & -ELF_PAGE
    if not ranges:
        raise ValueError("snapshot has no process memory")
    header = struct.pack("<16sHHI3QI6H", ident, 4, 62, 1, 0, 64, 0, 0, 64, 56, len(ranges) + 1, 0, 0, 0)
    core.seek(0)
    core.write(header + programs)
    return mappings


def write_native_module(output, registers, mappings):
    output.write('objtype = "amd64";\n')
    for name, value in zip(AMD64_REGISTERS, registers):
        output.write(f"p9{name} = fmt({value:#x}, 'Y');\n")
    output.write("defn p9map(addr, width) {\n")
    for base, end, offset in mappings:
        output.write(f"\tif addr >= {base:#x} && addr < {end:#x} && width <= {end:#x} - addr then {{\n"
                     f'\t\tmap({{"binary", {base:#x}, {end:#x}, {offset:#x}}});\n'
                     "\t\treturn 1;\n\t}\n")
    output.write('\terror("address outside captured process memory");\n}\n'
                 "defn p9read64(addr) {\n\tp9map(addr, 8);\n\treturn *fmt(addr, 'Y');\n}\n")


def convert_snapshot(snapshot, executable, core, native_module=None):
    with snapshot.open("rb") as source:
        header = source.readline(256).split()
        if header[:2] != [b"process", b"snapshot"] or header[4:5] != [b"x86_64"] or header[6:] != [b'"Plan9-rs"']:
            raise ValueError("expected a Plan9-rs x86_64 process snapshot")
        pid = None
        registers = None
        while True:
            record = source.readline(96)
            if len(record) < 14 or not record.endswith(b"\n") or not record[:12].strip().isdigit():
                raise ValueError("invalid snapshot record header")
            record_pid = int(record[:12])
            if not 0 < record_pid <= 0x7fffffff or pid not in (None, record_pid):
                raise ValueError("inconsistent snapshot process ID")
            pid = record_pid
            name = record[12:-1]
            if name == b"text":
                break
            length = read_number(source)
            if name not in (b"status", b"segment", b"regs", b"fpregs", b"kregs", b"noteid") or length > 2048:
                raise ValueError("invalid snapshot metadata")
            payload = read_exact(source, length)
            if name == b"regs":
                if registers is not None:
                    raise ValueError("duplicate snapshot register record")
                registers = payload
        if registers is None or read_number(source) != 0:
            raise ValueError("snapshot is missing registers or executable")
        if len(registers) != len(AMD64_REGISTERS) * 8:
            raise ValueError("invalid Plan9-rs x86_64 register record")
        registers = struct.unpack("<20Q", registers)
        length = read_number(source)
        if not 64 <= length <= MAX_CAPTURE:
            raise ValueError("invalid snapshot executable length")
        created = []
        try:
            with executable.open("xb+") as text:
                created.append(executable)
                read_region(source, text, length)
                text.seek(0)
                elf = read_exact(text, 20)
                if elf[:7] != b"\x7fELF\x02\x01\x01" or elf[18:20] != b"\x3e\x00":
                    raise ValueError("expected an x86_64 ELF executable")
            if source.readline(96) != f"{pid:<11} mem\n".encode():
                raise ValueError("snapshot is missing its memory records")
            with core.open("xb") as output:
                created.append(core)
                mappings = write_core(source, output, status_note(pid, registers))
                if source.read(1):
                    raise ValueError("expected exactly one captured process")
            if native_module is not None:
                with native_module.open("x", encoding="ascii") as module:
                    created.append(native_module)
                    write_native_module(module, registers, mappings)
        except (OSError, ValueError):
            for path in created:
                path.unlink(missing_ok=True)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("executable", type=Path)
    parser.add_argument("core", type=Path)
    parser.add_argument("--native-module", type=Path, help="emit an offline module for 9front acid -m amd64")
    args = parser.parse_args()
    try:
        convert_snapshot(args.snapshot, args.executable, args.core, args.native_module)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()

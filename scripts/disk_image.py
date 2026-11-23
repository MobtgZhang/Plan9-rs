#!/usr/bin/env python3
"""Create Plan9-rs NVMe images or extract a completed panic core."""

import argparse
from pathlib import Path
import struct


PAGE = 4096
MAGIC = {"root": b"P9ROOT1\0", "dump": b"P9DUMP1\0"}
MACHINES = {"x86_64": 62, "aarch64": 183, "riscv64": 243, "loongarch64": 258}


def create_image(path, kind, size):
    if size < (64 << 20) or size % PAGE:
        raise ValueError("image must be at least 64 MiB and page aligned")
    with path.open("xb") as image:
        image.truncate(size)
        image.write(MAGIC[kind])


def dump_info(image):
    image.seek(0)
    if image.read(8) != MAGIC["dump"]:
        raise ValueError("not a Plan9-rs dump disk")
    image.seek(PAGE)
    header = image.read(PAGE)
    if len(header) != PAGE or header[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("no completed core on dump disk")
    kind, machine, version = struct.unpack_from("<HHI", header, 16)
    phoff = struct.unpack_from("<Q", header, 32)[0]
    header_size, entry_size, count = struct.unpack_from("<HHH", header, 52)
    if kind != 4 or machine not in MACHINES.values() or version != 1 or phoff != 64 or header_size != 64 \
            or entry_size != 56 or not 0 < count <= (PAGE - phoff) // entry_size:
        raise ValueError("invalid ELF core header")
    end = PAGE
    physical_end = 0
    segments = []
    diagnostic = None
    for index in range(count):
        entry = struct.unpack_from("<II6Q", header, phoff + index * entry_size)
        kind, _, offset, vaddr, paddr, filesz, memsz, align = entry
        if kind == 4:
            if diagnostic is not None or offset < phoff + count * entry_size or offset % 4 \
                    or not 20 <= filesz <= PAGE - offset or align != 4:
                raise ValueError("invalid panic diagnostic segment")
            namesz, descsz, note_type = struct.unpack_from("<III", header, offset)
            if namesz != 8 or note_type != 1 or header[offset + 12:offset + 20] != b"Plan9rs\0" \
                    or (20 + descsz + 3) & ~3 != filesz:
                raise ValueError("invalid Plan9-rs panic note")
            diagnostic = header[offset + 20:offset + 20 + descsz]
            continue
        if kind != 1 or offset != end or filesz == 0 or filesz % PAGE or align != PAGE \
                or paddr < physical_end or paddr % PAGE or vaddr != paddr or filesz != memsz:
            raise ValueError("invalid physical memory segment")
        physical_end = paddr + filesz
        end += filesz
        segments.append((paddr, filesz, offset))
    if not segments or PAGE + end > image.seek(0, 2):
        raise ValueError("truncated panic core")
    return machine, end, segments, diagnostic


def extract_dump(source, output):
    with source.open("rb") as disk:
        _, remaining, _, _ = dump_info(disk)
        disk.seek(PAGE)
        with output.open("xb") as core:
            while remaining:
                chunk = disk.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError("truncated panic core")
                if chunk.count(0) == len(chunk):
                    core.seek(len(chunk), 1)
                else:
                    core.write(chunk)
                remaining -= len(chunk)
            core.truncate(core.tell())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    init = sub.add_parser("create")
    init.add_argument("kind", choices=MAGIC)
    init.add_argument("image", type=Path)
    init.add_argument("size_mib", type=int)
    extract = sub.add_parser("extract")
    extract.add_argument("image", type=Path)
    extract.add_argument("core", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "create":
            create_image(args.image, args.kind, args.size_mib << 20)
        else:
            extract_dump(args.image, args.core)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()

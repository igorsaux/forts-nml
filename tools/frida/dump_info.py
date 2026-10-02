"""Minimal minidump reader: exception code/address + faulting module + thread RIP.

Enough to answer "did it crash inside DINPUT8.dll (the loader), the game, or a
system DLL?" without installing WinDbg.

    uv run python tools/frida/dump_info.py <file.dmp> [more.dmp ...]
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

THREAD_LIST = 3
MODULE_LIST = 4
EXCEPTION = 6
SYSTEM_INFO = 7

EXC_NAMES = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000094: "INT_DIVIDE_BY_ZERO",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000409: "STACK_BUFFER_OVERRUN / FASTFAIL",
    0x80000003: "BREAKPOINT",
    0xC0000374: "HEAP_CORRUPTION",
    0xE06D7363: "C++ EH (handled)",
    0xC000013A: "CONTROL_C_EXIT",
    0xC0000006: "IN_PAGE_ERROR",
}


def read_string(data: bytes, rva: int) -> str:
    (length,) = struct.unpack_from("<I", data, rva)
    raw = data[rva + 4 : rva + 4 + length]
    try:
        return raw.decode("utf-16-le")
    except Exception:
        return repr(raw)


def parse(path: Path) -> None:
    data = path.read_bytes()
    (sig,) = struct.unpack_from("<I", data, 0)
    if data[:4] != b"MDMP":
        print(f"{path.name}: not a minidump")
        return
    (nstreams,) = struct.unpack_from("<I", data, 8)
    (dir_rva,) = struct.unpack_from("<I", data, 12)

    streams: dict[int, tuple[int, int]] = {}
    for i in range(nstreams):
        st, size, rva = struct.unpack_from("<III", data, dir_rva + i * 12)
        streams.setdefault(st, (size, rva))

    modules: list[tuple[int, int, str]] = []
    if MODULE_LIST in streams:
        _, rva = streams[MODULE_LIST]
        (nmods,) = struct.unpack_from("<I", data, rva)
        for i in range(nmods):
            base = struct.unpack_from("<Q", data, rva + 4 + i * 108 + 0)[0]
            size = struct.unpack_from("<I", data, rva + 4 + i * 108 + 8)[0]
            name_rva = struct.unpack_from("<I", data, rva + 4 + i * 108 + 20)[0]
            modules.append((base, size, read_string(data, name_rva)))

    def locate(addr: int) -> str:
        for base, size, name in modules:
            if base <= addr < base + size:
                return f"{name}+0x{addr - base:x}"
        return f"0x{addr:x} (unmapped)"

    print(f"\n=== {path.name} ===")
    if EXCEPTION in streams:
        _, rva = streams[EXCEPTION]
        tid = struct.unpack_from("<I", data, rva)[0]
        exc_code = struct.unpack_from("<I", data, rva + 8)[0]
        exc_addr = struct.unpack_from("<Q", data, rva + 8 + 16)[0]
        nparams = struct.unpack_from("<I", data, rva + 8 + 24)[0]
        params = struct.unpack_from("<15Q", data, rva + 8 + 32)
        print(f"  thread    : {tid}")
        print(f"  exception : {EXC_NAMES.get(exc_code, '')} 0x{exc_code:08X}")
        print(f"  address   : 0x{exc_addr:x}  -> {locate(exc_addr)}")
        if exc_code == 0xC0000005 and nparams >= 2:
            kind = {0: "read", 1: "write", 8: "execute"}.get(params[0], str(params[0]))
            print(f"  access    : {kind} @ 0x{params[1]:x}")
        ctx_size, ctx_rva = struct.unpack_from("<II", data, rva + 8 + 32 + 15 * 8)
        # x64 CONTEXT: RIP is at offset 0xF8 from the start of CONTEXT.
        if ctx_size and ctx_rva:
            try:
                rip = struct.unpack_from("<Q", data, ctx_rva + 0xF8)[0]
                rsp = struct.unpack_from("<Q", data, ctx_rva + 0x98)[0]
                rcx = struct.unpack_from("<Q", data, ctx_rva + 0x80)[0]
                rdx = struct.unpack_from("<Q", data, ctx_rva + 0x88)[0]
                r8 = struct.unpack_from("<Q", data, ctx_rva + 0xB8)[0]
                print(f"  rip       : 0x{rip:x}  -> {locate(rip)}")
                print(f"  rcx=0x{rcx:x} rdx=0x{rdx:x} r8=0x{r8:x} rsp=0x{rsp:x}")
            except Exception as e:  # pragma: no cover
                print(f"  (context parse failed: {e})")
    else:
        print("  no exception stream")

    print(f"  modules containing DINPUT8:")
    for base, size, name in modules:
        if "dinput8" in name.lower():
            print(f"    {name} base=0x{base:x} size=0x{size:x}")


def main(argv: list[str]) -> int:
    for arg in argv:
        parse(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

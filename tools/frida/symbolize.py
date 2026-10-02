#!/usr/bin/env python3
"""Symbolize addresses in DINPUT8.dll using its PDB (through dbghelp.dll).

No WinDbg needed: dbghelp reads `DINPUT8.pdb` next to the DLL and resolves
symbol names and source lines for RVAs.

    uv run python tools/frida/symbolize.py --dll zig-out/bin/DINPUT8.dll 0x9ba3d 0x9bbb3
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import (
    POINTER,
    Structure,
    WINFUNCTYPE,
    byref,
    c_bool,
    c_char,
    c_char_p,
    c_int,
    c_ulong,
    c_ulonglong,
    c_void_p,
    sizeof,
)
from ctypes import wintypes
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
DWORD64 = c_ulonglong

dbghelp.SymSetOptions.argtypes = [DWORD]
dbghelp.SymSetOptions.restype = DWORD
dbghelp.SymInitialize.argtypes = [HANDLE, c_char_p, c_bool]
dbghelp.SymInitialize.restype = c_bool
dbghelp.SymCleanup.argtypes = [HANDLE]
dbghelp.SymCleanup.restype = c_bool
dbghelp.SymLoadModuleEx.argtypes = [HANDLE, HANDLE, c_char_p, c_char_p, DWORD64, DWORD, c_void_p, DWORD]
dbghelp.SymLoadModuleEx.restype = DWORD64
dbghelp.SymFromAddr.argtypes = [HANDLE, DWORD64, POINTER(DWORD64), c_void_p]
dbghelp.SymFromAddr.restype = c_bool
dbghelp.SymGetLineFromAddr64.argtypes = [HANDLE, DWORD64, POINTER(DWORD), c_void_p]
dbghelp.SymGetLineFromAddr64.restype = c_bool

SYMOPT_UNDNAME = 0x00000002
SYMOPT_LOAD_LINES = 0x00000010
PREFERRED_BASE = 0x180000000


class SYMBOL_INFO(Structure):
    _fields_ = [
        ("SizeOfStruct", c_ulong),
        ("TypeIndex", c_ulong),
        ("Reserved", c_ulonglong * 2),
        ("Index", c_ulong),
        ("Size", c_ulong),
        ("ModBase", c_ulonglong),
        ("Flags", c_ulong),
        ("Value", c_ulonglong),
        ("Address", c_ulonglong),
        ("Register", c_ulong),
        ("Scope", c_ulong),
        ("Tag", c_ulong),
        ("NameLen", c_ulong),
        ("MaxNameLen", c_ulong),
        ("Name", c_char * 4096),
    ]


class IMAGEHLP_LINE64(Structure):
    _fields_ = [
        ("SizeOfStruct", c_ulong),
        ("Key", c_void_p),
        ("LineNumber", c_ulong),
        ("FileName", c_char_p),
        ("Address", c_ulonglong),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Symbolize DINPUT8.dll RVAs via dbghelp")
    ap.add_argument("--dll", required=True, help="path to DINPUT8.dll")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=PREFERRED_BASE,
                    help="load base to use (default: PE preferred base)")
    ap.add_argument("rvas", nargs="+", help="RVAs, e.g. 0x9ba3d")
    args = ap.parse_args(argv)

    dll = Path(args.dll).resolve()
    process = kernel32.GetCurrentProcess()

    dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES)
    if not dbghelp.SymInitialize(process, str(dll.parent).encode(), False):
        print(f"SymInitialize failed: {ctypes.get_last_error()}")
        return 1

    size = dll.stat().st_size
    base = dbghelp.SymLoadModuleEx(
        process, None, str(dll).encode(), None, args.base, size, None, 0
    )
    if base == 0:
        print(f"SymLoadModuleEx failed: {ctypes.get_last_error()}")
        return 1
    print(f"loaded {dll.name} at {base:#x} (size {size})")

    for rva_s in args.rvas:
        rva = int(rva_s, 0)
        addr = base + rva
        buf = SYMBOL_INFO()
        buf.SizeOfStruct = sizeof(SYMBOL_INFO)
        buf.MaxNameLen = 4096
        disp = DWORD64(0)
        ok = dbghelp.SymFromAddr(process, DWORD64(addr), byref(disp), byref(buf))
        if not ok:
            print(f"  0x{rva:x}  no symbol (err {ctypes.get_last_error()})")
            continue
        name = buf.Name.decode(errors="replace")
        line = IMAGEHLP_LINE64()
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64)
        ldisp = DWORD(0)
        if dbghelp.SymGetLineFromAddr64(process, DWORD64(addr), byref(ldisp), byref(line)) and line.FileName:
            print(f"  0x{rva:x}  {name}+0x{disp.value:x}  {line.FileName.decode(errors='replace')}:{line.LineNumber}")
        else:
            print(f"  0x{rva:x}  {name}+0x{disp.value:x}")

    dbghelp.SymCleanup(process)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

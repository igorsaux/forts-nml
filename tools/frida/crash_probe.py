#!/usr/bin/env python3
"""Catch and report a native crash while the nml loader is active.

Arms a Frida exception handler and prints the faulting instruction and
backtrace. Use it to tell whether a crash is in the loader's relay/trampoline
or in the game's original code.

    uv run python tools/frida/crash_probe.py --exe <path> --spawn --seconds 300
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from forts import resolve_exe  # noqa: E402


def _load_frida():
    try:
        import frida  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise SystemExit(f"frida is not available: {exc}") from exc
    return frida


def _find_running(device, module: str):
    target = module.lower()
    for proc in device.enumerate_processes():
        name = proc.name.lower()
        if name == target or name == name.removesuffix(".exe"):
            return proc
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="nml crash catcher")
    ap.add_argument("--exe", required=True, help="path to Forts.exe")
    ap.add_argument("--spawn", action="store_true", help="spawn instead of attach")
    ap.add_argument("--pid", type=int, help="attach to a specific pid")
    ap.add_argument("--seconds", type=float, default=300.0, help="observation window")
    ap.add_argument("--keep-alive", action="store_true", help="leave a spawned game running")
    args = ap.parse_args(argv)

    exe = resolve_exe(args.exe)
    frida = _load_frida()
    device = frida.get_local_device()
    module = "Forts.exe"

    spawned_pid = None
    session = None
    try:
        if args.pid is not None:
            session = device.attach(args.pid)
            print(f"[live] attached to pid {args.pid}")
        else:
            running = None if args.spawn else _find_running(device, module)
            if running is not None:
                session = device.attach(running.pid)
                print(f"[live] attached to running {running.name} (pid {running.pid})")
            else:
                spawned_pid = device.spawn([str(exe)])
                session = device.attach(spawned_pid)
                device.resume(spawned_pid)
                print(f"[live] spawned {exe} (pid {spawned_pid})")

        script = session.create_script((HERE / "agent_diag.js").read_text(encoding="utf-8"))

        def on_message(message, data):
            if message.get("type") == "send":
                p = message.get("payload") or {}
                kind = p.get("type")
                if kind == "raise_exception" and p.get("name") == "C++ EH":
                    # normal C++ exception traffic; keep it to one line
                    print(f"[eh] C++ exception at {p.get('backtrace', [None])[0]}")
                elif kind in ("fault", "raise_exception"):
                    print(f"\n=== {kind.upper()} ===")
                    for k, v in p.items():
                        if k == "backtrace":
                            print("  backtrace:")
                            for frame in v or []:
                                print(f"    {frame}")
                        else:
                            print(f"  {k}: {v}")
                else:
                    print(f"[ev] {p}")
            else:
                print(f"[agent] {message}")

        script.on("message", on_message)
        script.load()

        def on_detached(reason, crash=None):
            print(f"\n[live] session detached: {reason}" + (f" crash={crash}" if crash else ""))

        session.on("detached", on_detached)
        print(f"[live] agent: {script.exports_sync.arm({})}; observing {args.seconds:g}s")
        print("[live] reproduce the crash now (e.g. click Sandbox)")

        end = time.monotonic() + args.seconds
        while time.monotonic() < end:
            time.sleep(0.25)
        return 0
    finally:
        if spawned_pid is not None and not args.keep_alive:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())

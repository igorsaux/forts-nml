#!/usr/bin/env python3
"""Live probe for the ObjectFactory -> World construction chain.

Answers one question: does `FrontEndFactoryStandard::Create` return the same
`World*` that `World_ctor` receives, and if not, where does it diverge?

Three independent observations are reported for every type-0x16 (World) call:

  * factory_enter / factory_leave : the value the *game* receives from the
                                    factory entry (with the nml loader this is
                                    the relay's RAX);
  * factory_original_ret          : RAX observed at the original function's own
                                    epilogue `ret` (RVA 0x1EAB17), i.e. what the
                                    original computed before any relay touches it;
  * world_ctor_* / sim_ctor_*     : the World pointer seen by the constructors.

Run it once WITH DINPUT8.dll (loader active) and once WITHOUT it:

    uv run python tools/frida/factory_probe.py --exe <path> --spawn --seconds 120

When the loader is absent the entry is not detoured: `factory_leave` is then the
true original return value, which makes the two runs directly comparable.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from forts import resolve_exe  # noqa: E402

# RVAs for Forts 1.38.2-r22447 (see targets/1.38.2-r22447.json).
FACTORY_RVA = 0x1EA7B0          # FrontEndFactoryStandard::Create (vtable slot 0)
FACTORY_VTABLE_RVA = 0x6E05C8   # the vtable slot that holds FACTORY_RVA
WORLD_CTOR_RVA = 0x1CFEB0
WORLD_SIM_CTOR_RVA = 0x2F9E90
WORLD_PTR_RVA = 0x7DE2E0
WORLD_PTR2_RVA = 0x7DC440


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


def _fmt(e: dict) -> str:
    order = ["type", "ty", "self", "engine", "setup", "world", "ret", "rax",
             "patched", "factory", "relay", "first_byte", "tid"]
    keys = [k for k in order if k in e] + [k for k in e if k not in order]
    return "  " + "  ".join(f"{k}={e[k]}" for k in keys)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live ObjectFactory probe")
    ap.add_argument("--exe", required=True, help="path to Forts.exe")
    ap.add_argument("--spawn", action="store_true", help="spawn instead of attach")
    ap.add_argument("--pid", type=int, help="attach to a specific pid")
    ap.add_argument("--seconds", type=float, default=120.0, help="observation window")
    ap.add_argument("--keep-alive", action="store_true", help="leave a spawned game running")
    args = ap.parse_args(argv)

    exe = resolve_exe(args.exe)
    frida = _load_frida()
    device = frida.get_local_device()
    module = "Forts.exe"

    spawned_pid = None
    session = None
    events: list[dict] = []
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

        script = session.create_script((HERE / "agent_factory.js").read_text(encoding="utf-8"))

        def on_message(message, data):
            if message.get("type") == "send":
                payload = message.get("payload") or {}
                events.append(payload)
                print(f"[ev] {_fmt(payload)}")
            else:
                print(f"[agent] {message}")

        script.on("message", on_message)
        script.load()

        cfg = {
            "module": module,
            "factory_rva": FACTORY_RVA,
            "vtable_rva": FACTORY_VTABLE_RVA,
            "world_ctor_rva": WORLD_CTOR_RVA,
            "world_sim_ctor_rva": WORLD_SIM_CTOR_RVA,
            "world_ptr_rva": WORLD_PTR_RVA,
            "world_ptr2_rva": WORLD_PTR2_RVA,
        }

        # Wait until the nml loader has installed its detour, otherwise our
        # hooks land before the patch and can be clobbered by it.
        deadline = time.monotonic() + 30
        st = None
        while time.monotonic() < deadline:
            st = script.exports_sync.state(cfg)
            if st.get("module") and st.get("patched"):
                break
            time.sleep(0.2)
        print(f"[live] loader state: {st}")

        started = script.exports_sync.start(cfg)
        print(f"[live] agent: {started}; observing {args.seconds:g}s "
              "(open/start a match to exercise the factory)")

        end = time.monotonic() + args.seconds
        while time.monotonic() < end:
            time.sleep(0.25)

        print(f"\n=== analysis ({len(events)} events) ===")
        enters22 = [e for e in events if e.get("type") == "factory_enter" and e.get("ty") == 0x16]
        leaves22 = [e for e in events if e.get("type") == "factory_leave" and e.get("ty") == 0x16]
        ctor_enters = [e for e in events if e.get("type") == "world_ctor_enter"]
        ctor_leaves = [e for e in events if e.get("type") == "world_ctor_leave"]
        setup = next((e for e in events if e.get("type") == "setup"), None)

        if setup:
            entry = setup.get("entry") or {}
            print(f"  module_base            : {setup.get('module_base')}")
            print(f"  entry patched (E9)     : {entry.get('patched')} "
                  f"(first byte {entry.get('first_byte')}, relay {entry.get('relay')})")
            print(f"  vtable slot value      : {setup.get('vtable_slot')} "
                  f"(expected original {setup.get('vtable_slot_expected')})")
            print(f"  World_ptr / World_ptr2 : {setup.get('world_ptr')} / {setup.get('world_ptr2')}")
            print(f"  DINPUT8 modules        : {setup.get('loader')}")
        print(f"  type-0x16 factory calls: {len(enters22)}")
        if enters22:
            le = enters22[-1].get("live_entry") or {}
            print(f"  entry state at call    : patched={le.get('patched')} relay={le.get('relay')}")
        print(f"  factory  -> game       : {[e['ret'] for e in leaves22]}")
        print(f"  World_ctor this        : {[e['self'] for e in ctor_enters]}")
        print(f"  World_ctor -> caller   : {[e['ret'] for e in ctor_leaves]}")

        if ctor_leaves and leaves22:
            world = int(ctor_leaves[-1]["ret"], 16)
            got = int(leaves22[-1]["ret"], 16)
            print(f"\n  World_ctor returns      : {world:#x}")
            print(f"  factory hands to game   : {got:#x}   (==world? {got == world})")
            if got == world:
                print("  VERDICT: factory return propagates correctly.")
            else:
                print("  VERDICT: factory value does NOT match the created World "
                      "(the loader's relay return is corrupted).")
        else:
            print("\n  (no type-0x16 sample captured; start a match and rerun)")
        return 0
    finally:
        if spawned_pid is not None and not args.keep_alive:
            try:
                device.kill(spawned_pid)
                print(f"[live] killed spawned pid {spawned_pid}")
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())

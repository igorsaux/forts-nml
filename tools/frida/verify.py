#!/usr/bin/env python3
"""Forts verification pipeline.

One command validates that the RVAs in tools/frida/targets.json still describe
the installed game:

    uv run python tools/frida/verify.py            # offline: hashes + PE layout
    uv run python tools/frida/verify.py --live     # + resolve targets in-process
    uv run python tools/frida/verify.py --live --hook 15
                                                   # + count app-frame/present/input/tick calls

The offline stage needs only the .exe file. The live stage attaches to a running
Forts.exe or spawns one, verifies function prologues / vtable slots / strings /
globals through agent_probe.js, and (with --hook) counts real tick invocations.

Exit code is non-zero if any offline check fails, or if a live run was requested
and could not be performed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import forts  # noqa: E402
from forts import (  # noqa: E402
    Check,
    PE,
    hexint,
    load_targets,
    payload_for_agent,
    print_report,
    resolve_exe,
)

VERSION = "0.1.0"


# --------------------------------------------------------------------------- #
# Stage 1: offline (PE file only)
# --------------------------------------------------------------------------- #
def run_static(pe: PE, targets: dict) -> list[Check]:
    checks: list[Check] = []

    if pe.image_base != hexint(targets["image_base"]):
        checks.append(
            Check(
                "file",
                "image_base",
                False,
                f"{pe.image_base:#x} != {hexint(targets['image_base']):#x}",
            )
        )
    else:
        checks.append(Check("file", "image_base", True, f"{pe.image_base:#x}"))

    actual = pe.sha256()
    expected = str(targets["sha256"]).lower()
    checks.append(
        Check(
            "hash",
            "sha256",
            actual == expected,
            "match" if actual == expected else f"{actual} != {expected}",
        )
    )

    checks.append(Check("file", "size", True, f"{len(pe.data)} bytes"))

    for name, f in targets["functions"].items():
        rva = hexint(f["rva"])
        expected = forts.prefix_bytes(f["prologue"])
        actual = pe.read(rva, len(expected))
        if actual is None:
            checks.append(Check("function", name, False, f"@ {rva:#x} unreadable"))
            continue
        ok = list(actual) == expected
        checks.append(
            Check(
                "function",
                name,
                ok,
                f"@ {rva:#x}  {actual.hex(' ')}" + ("" if ok else "  != expected"),
            )
        )

    for name, s in targets["strings"].items():
        rva = hexint(s["rva"])
        # Expected text may be a prefix of the real anchor (some anchors are
        # long log lines); read the whole C string and compare as a prefix.
        # Wide (UTF-16LE) anchors set "wide": true.
        wide = bool(s.get("wide"))
        actual = pe.read_wcstr(rva, 512) if wide else pe.read_cstr(rva, 512)
        ok = actual is not None and actual.startswith(s["text"])
        shown = actual if actual and len(actual) <= 64 else (actual[:61] + "..." if actual else actual)
        checks.append(
            Check(
                "string",
                name,
                ok,
                f"@ {rva:#x}  {shown!r}" + ("" if ok else f" != {s['text']!r}"),
            )
        )

    for vname, vt in targets["vtables"].items():
        vrva = hexint(vt["rva"])
        for slot in vt["slots"]:
            off = hexint(slot["offset"])
            if "function" in slot:
                want = hexint(targets["functions"][slot["function"]]["rva"])
            else:
                want = hexint(slot["rva"])
            got = pe.read_u64(vrva + off)
            ok = got == pe.image_base + want
            checks.append(
                Check(
                    "vtable",
                    f"{vname}+{off:#x}",
                    ok,
                    f"@ {vrva + off:#x}  "
                    + (f"-> {got - pe.image_base:#x}" if got else "null")
                    + ("" if ok else f" != {want:#x}"),
                )
            )

    for name, g in targets["globals"].items():
        rva = hexint(g["rva"])
        mapped = pe.rva_to_off(rva) is not None
        checks.append(
            Check("global", name, mapped, f"@ {rva:#x}  " + ("mapped" if mapped else "NOT MAPPED"))
        )

    # Struct layouts are data for the runtime (and the generated Zig manifest),
    # so the file alone cannot prove the offsets. Check what is verifiable:
    # bounds, alignment and non-overlap, which catch most copy/paste mistakes.
    # forts.resolve_struct_layouts() resolves `str` counts and `embedded`
    # sub-object sizes and reports the same problems it feeds to gen_zig.py.
    for group, st in forts.resolve_struct_layouts(targets).items():
        size = st["declared_size"]
        problems: list[str] = list(st["problems"])
        prev_end = 0
        for f in sorted(st["fields"], key=lambda x: x["offset"]):
            off = f["offset"]
            if off >= size:
                problems.append(f"{f['name']}@{off:#x} >= size")
            fsize = f["size"]
            if fsize is not None:
                if off < prev_end and f"{f['name']}@{off:#x} overlaps previous field" not in problems:
                    problems.append(f"{f['name']}@{off:#x} overlaps")
                prev_end = off + fsize
        checks.append(
            Check(
                "struct",
                group,
                not problems,
                f"{st['name']}, {len(st['fields'])} fields, size {size:#x}"
                + ("  " + "; ".join(problems) if problems else ""),
            )
        )

    return checks


# --------------------------------------------------------------------------- #
# Stage 2: live (Frida)
# --------------------------------------------------------------------------- #
def _load_frida():
    try:
        import frida  # type: ignore
    except Exception as exc:  # pragma: no cover - env dependent
        raise SystemExit(f"frida is not available: {exc}") from exc
    return frida


def _find_running(device, module: str):
    target = module.lower()
    for proc in device.enumerate_processes():
        name = proc.name.lower()
        if name == target or name == target.removesuffix(".exe"):
            return proc
    return None


def run_live(
    targets: dict,
    exe: Path,
    *,
    spawn: bool,
    pid: int | None,
    module_wait_ms: int = 20000,
    hook_seconds: float = 0.0,
    keep_alive: bool = False,
):
    """Attach/spawn and verify. Returns (checks, live_handle)."""
    frida = _load_frida()
    device = frida.get_local_device()
    module = targets["module"]

    spawned_pid: int | None = None
    session = None
    try:
        if pid is not None:
            session = device.attach(pid)
            print(f"[live] attached to pid {pid}")
        else:
            running = None if spawn else _find_running(device, module)
            if running is not None:
                session = device.attach(running.pid)
                print(f"[live] attached to running {running.name} (pid {running.pid})")
            else:
                spawned_pid = device.spawn([str(exe)])
                session = device.attach(spawned_pid)
                device.resume(spawned_pid)
                print(f"[live] spawned {exe} (pid {spawned_pid})")

        script = session.create_script(
            (HERE / "agent_probe.js").read_text(encoding="utf-8")
        )
        script.on("message", lambda m, d: print(f"[agent] {m}"))
        script.load()

        # Poll from Python: the agent runtime has no sleeps/timers.
        deadline = time.monotonic() + module_wait_ms / 1000.0
        base = None
        while time.monotonic() < deadline:
            base = script.exports_sync.modulebase(module)
            if base is not None:
                break
            time.sleep(0.05)
        if base is None:
            raise SystemExit(f"[live] module {module!r} not found after {module_wait_ms} ms")

        result = script.exports_sync.check(payload_for_agent(targets))
        checks = [
            Check(r["kind"], r["name"], bool(r["ok"]), str(r.get("detail", "")))
            for r in result["results"]
        ]

        handle = {
            "device": device,
            "session": session,
            "spawned_pid": spawned_pid,
            "module_base": result["module_base"],
        }

        if hook_seconds > 0:
            checks.extend(
                run_hook(handle, targets, seconds=hook_seconds, sample_every=60)
            )

        return checks, handle
    finally:
        # Stop the game we started so the pipeline is side-effect free, both on
        # success and on error. Leave it running with --keep-alive.
        if spawned_pid is not None and not keep_alive:
            try:
                device.kill(spawned_pid)
                print(f"[live] killed spawned pid {spawned_pid}")
            except Exception:
                pass


def run_hook(
    handle, targets: dict, *, seconds: float, sample_every: int
) -> list[Check]:
    session = handle["session"]
    module = targets["module"]
    sim = {
        f["name"]: hexint(f["offset"]) for f in targets["structs"]["sim"]["fields"]
    }
    inp = {
        f["name"]: hexint(f["offset"])
        for f in targets["structs"].get("input", {}).get("fields", [])
    }

    def rva_of(name: str) -> int:
        f = targets["functions"].get(name)
        return hexint(f["rva"]) if f else 0

    globals_ = targets.get("globals", {})
    cfg = {
        "module": module,
        "tick_rva": hexint(targets["functions"]["World_Sim_Update_Tick"]["rva"]),
        "dispatch_rva": hexint(targets["functions"]["Scripts_Update_Dispatch"]["rva"]),
        "frame_rva": rva_of("FortsShell_Execute"),
        "present_rva": rva_of("Renderer_Present"),
        "input_rva": rva_of("Input_Update"),
        "world_ptr_rva": hexint(targets["globals"]["World_ptr"]["rva"]),
        "input_ptr_rva": hexint(globals_["InputManager_ptr"]["rva"])
        if "InputManager_ptr" in globals_
        else 0,
        "offsets": {"sim": sim, "input": inp},
        "sample_every": sample_every,
    }

    script = session.create_script((HERE / "agent_tick.js").read_text(encoding="utf-8"))
    samples: list[dict] = []
    ctx_keys: list[str] = []

    def on_message(message, data):
        if message.get("type") != "send":
            print(f"[agent] {message}")
            return
        payload = message.get("payload") or {}
        if payload.get("type") == "ctxkeys":
            ctx_keys[:] = payload.get("keys", [])
        elif payload.get("type") == "tick":
            samples.append(payload["sample"])

    script.on("message", on_message)
    script.load()
    started = script.exports_sync.start(cfg)
    print(
        f"[hook] {started}; sampling {seconds:g}s "
        "(app frame = FortsShell::Execute, runs in menus and match; "
        "sim tick needs an active match)"
    )

    stats = script.exports_sync.stats()
    start = time.monotonic()
    deadline = start + seconds
    while time.monotonic() < deadline:
        time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        stats = script.exports_sync.stats()
        # Stop early once a match is running and we have data; give it a few
        # seconds so per-step Dispatch calls can show up too.
        if (
            stats.get("match_seen")
            and stats["tick"] > 0
            and (stats["dispatch"] > 0 or time.monotonic() - start >= 3.0)
        ):
            break

    match_seen = bool(stats.get("match_seen"))
    note = "" if match_seen else " (no active match; game was in the menu)"

    # Live input listen: read the InputManager keyboard/mouse state directly.
    # Advisory: it is only interesting if the user actually pressed something
    # during the window, and a headless run has no InputManager.
    try:
        live_input = script.exports_sync.input()
    except Exception:
        live_input = {"ok": False, "keys": [], "mouse": None}
    di_keys = {0x01: "Esc", 0x1C: "Enter", 0x39: "Space"}
    pressed = [
        di_keys.get(k, f"DIK 0x{k:02X}") for k in (live_input.get("keys") or [])
    ]
    mouse = live_input.get("mouse")
    mouse_txt = (
        f"dx={mouse['dx']} dy={mouse['dy']} wheel={mouse['wheel']}"
        if isinstance(mouse, dict)
        else "n/a"
    )

    # Only hard-require tick calls when a World actually existed during the
    # window; otherwise the hooks are simply untested, not broken.
    checks = [
        Check(
            "hook",
            "tick hook fired",
            stats["tick"] > 0,
            f"{stats['tick']} calls{note}",
            advisory=not match_seen,
        ),
        Check(
            "hook",
            "dispatch hook fired",
            stats["dispatch"] > 0,
            # Dispatch runs once per fixed step only once Lua scripts are
            # loaded, so it stays informational (a menu World has none).
            f"{stats['dispatch']} calls (needs loaded scripts)",
            advisory=True,
        ),
        Check(
            "hook",
            "World_ptr set (match active)",
            match_seen,
            str(stats.get("world_ptr")),
            advisory=False,
        ),
        Check(
            "hook",
            "app frame hook fired",
            stats.get("frame", 0) > 0,
            f"{stats.get('frame', 0)} FortsShell::Execute calls",
            # FortsShell::Execute backs the primary vtable slot 0 of the top
            # object and runs every frame in every state, so a running game
            # must always exercise it.
            advisory=False,
        ),
        Check(
            "hook",
            "renderer present hook fired",
            stats.get("present", 0) > 0,
            f"{stats.get('present', 0)} Renderer_Present (SwapBuffers) calls",
            # Swapping may be skipped while the window is occluded/minimised.
            advisory=True,
        ),
        Check(
            "hook",
            "input poll hook fired",
            stats.get("input", 0) > 0,
            f"{stats.get('input', 0)} Input_Update calls",
            # Same once-per-frame cadence as the app frame; 0 only if the
            # input manager is disabled (e.g. headless/no window).
            advisory=True,
        ),
        Check(
            "hook",
            "input listen (InputManager)",
            bool(live_input.get("ok")),
            f"keys=[{', '.join(pressed)}] mouse: {mouse_txt}",
            # ok=False only when no InputManager exists (menu/headless); an
            # empty key list just means no key was held at the sample instant.
            advisory=True,
        ),
        Check(
            "hook",
            "app frame vs sim tick",
            True,
            f"app frames={stats.get('frame', 0)}, "
            f"input={stats.get('input', 0)}, "
            f"sim ticks={stats.get('tick', 0)}, "
            f"dispatches={stats.get('dispatch', 0)}",
            advisory=True,
        ),
    ]

    delta_ok = any(s.get("delta") is not None for s in samples)
    checks.append(
        Check(
            "hook",
            "xmm1 delta readable",
            delta_ok,
            "delta readable" if delta_ok else f"context keys: {ctx_keys}",
            advisory=True,
        )
    )

    for s in samples[:3]:
        checks.append(
            Check(
                "sample",
                f"tick#{s['n']}",
                True,
                f"frame={s['frame']} dt_fixed={s['dt_fixed']} "
                f"acc={s['acc']} alpha={s['alpha']} "
                f"delta={s['delta']} ({s.get('delta_type')})",
                advisory=True,
            )
        )
    return checks


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forts RE verification pipeline")
    parser.add_argument("--exe", required=True, help="path to Forts.exe")
    parser.add_argument(
        "--targets",
        default=None,
        help="game version id (e.g. 1.38.2-r22447) or path to a targets JSON; "
        "defaults to auto-matching the exe by hash",
    )
    parser.add_argument("--live", action="store_true", help="also verify inside a live process")
    parser.add_argument("--spawn", action="store_true", help="force spawning instead of attaching")
    parser.add_argument("--pid", type=int, help="attach to a specific pid")
    parser.add_argument(
        "--hook",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="also count app-frame/present/input/tick calls for N seconds "
        "(implies --live)",
    )
    parser.add_argument(
        "--keep-alive",
        action="store_true",
        help="leave a spawned game running after checks",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    exe = resolve_exe(args.exe)
    pe = PE(exe)
    targets_path = forts.select_targets_for_pe(pe, args.targets)
    targets = load_targets(targets_path)
    print(f"game:    {targets['game']} {targets['version']}  ({exe})")
    print(f"targets: {targets_path}")

    checks = run_static(pe, targets)
    if not args.json:
        print_report(checks, "static (offline)")
    static_ok = forts.required_passed(checks)

    live_ok = True
    do_live = args.live or args.hook > 0
    if do_live:
        live_checks, _ = run_live(
            targets,
            exe,
            spawn=args.spawn,
            pid=args.pid,
            hook_seconds=args.hook,
            keep_alive=args.keep_alive,
        )
        if not args.json:
            print_report(live_checks, "live (frida)")
        live_ok = forts.required_passed(live_checks)
        checks += live_checks

    if args.json:
        print(
            json.dumps(
                {
                    "exe": str(exe),
                    "version": targets["version"],
                    "checks": [c.__dict__ for c in checks],
                },
                indent=2,
            )
        )

    ok = static_ok and live_ok
    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

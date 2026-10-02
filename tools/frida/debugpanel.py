"""Force the Forts DebugPanel overlay on a running game.

Forts only shows the DebugPanel — the top-left overlay with the live simulation
frame, ``mm:ss``, fps and the **current game speed as ``Nx``** — when
``PlayerController+0x47`` is nonzero. The game sets that byte from
``(World+0x1B64 == 2)``, i.e. spectator/observer mode, so the overlay is never
visible in a normal match. This tool attaches to a running game and rewrites the
byte every frame, so the overlay appears in any match.

It is read-only apart from that single flag and detaches cleanly on exit.

Usage:
    uv run python tools/frida/debugpanel.py             # attach; Ctrl-C to stop
    uv run python tools/frida/debugpanel.py --seconds 20
    uv run python tools/frida/debugpanel.py --pid 1234
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import frida

from forts import hexint, load_targets

AGENT = """
rpc.exports = {
  apply: function (cfg) {
    var m = Process.findModuleByName(cfg.module);
    if (m === null) return "no module";
    var base = m.base;
    var world_ptr = base.add(cfg.world_ptr_rva);
    // Force the DebugPanel gate every frame: the game recomputes it from the
    // game mode, so a one-shot write is overwritten. Writing it in HUD_Update /
    // HUD_DebugPanel onEnter lands just before the overlay reads it.
    Interceptor.attach(base.add(cfg.debugpanel_rva), {
      onEnter: function (args) {
        try {
          var world = world_ptr.readPointer();
          if (world.isNull()) return;
          var pc = world.add(cfg.pc_off).readPointer();
          if (pc.isNull()) return;
          pc.add(cfg.gate_off).writeU8(cfg.value & 0xff);
        } catch (e) {}
      },
    });
    return "hooked";
  },
  read: function (cfg) {
    var m = Process.findModuleByName(cfg.module);
    if (m === null) return null;
    var base = m.base;
    try {
      var world = base.add(cfg.world_ptr_rva).readPointer();
      if (world.isNull()) return null;
      var pc = world.add(cfg.pc_off).readPointer();
      if (pc.isNull()) return null;
      return pc.add(cfg.gate_off).readU8();
    } catch (e) {
      return null;
    }
  },
};
"""


def find_pid() -> int | None:
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() in ("forts.exe", "forts"):
            return p.pid
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Force the Forts DebugPanel overlay.")
    ap.add_argument("--seconds", type=float, default=0.0,
                    help="stop after N seconds (default: run until Ctrl-C)")
    ap.add_argument("--pid", type=int, default=None, help="attach to this pid")
    args = ap.parse_args()

    targets = load_targets()
    module = targets["module"]
    pc_field = targets["structs"]["world"]["fields"]
    pc_off = next(hexint(f["offset"]) for f in pc_field if f["name"] == "match_manager")
    cfg = {
        "module": module,
        "world_ptr_rva": hexint(targets["globals"]["World_ptr"]["rva"]),
        "debugpanel_rva": hexint(targets["functions"]["HUD_DebugPanel"]["rva"]),
        "pc_off": pc_off,
        "gate_off": 0x47,
        "value": 1,
    }

    pid = args.pid or find_pid()
    if pid is None:
        print("no running Forts.exe found (launch the game, then retry)")
        return 1

    session = frida.attach(pid)
    script = session.create_script(AGENT)
    script.load()
    print(f"attached to pid {pid}; {script.exports_sync.apply(cfg)}", flush=True)
    print("DebugPanel gate forced to 1 (should show 'Nx' speed + fps top-left)",
          flush=True)

    deadline = time.monotonic() + args.seconds if args.seconds else None
    try:
        while deadline is None or time.monotonic() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
    print("detached", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

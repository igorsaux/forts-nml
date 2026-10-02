"""List the Lua scripts loaded by a running Forts game and inspect their state.

Forts runs each script (mission, mod, AI) in its own Lua 5.1.1 state; they are
tracked in the global ``ScriptList`` vector as ``ScriptRecord`` entries
(``tools/frida/targets/*.json`` -> ``structs.script_record``). This tool attaches
to a running game and prints, per script: the ``active`` flag, its ``lua_State*``,
its source path and the global-table count snapshot the engine uses to warn about
state stored outside the ``data`` table (see ``strings.IllegalGlobals``).

Read-only: it only reads memory. Usage:
    uv run python tools/frida/scripts.py
    uv run python tools/frida/scripts.py --pid 1234
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import frida

from forts import hexint, load_targets

AGENT = """
rpc.exports = {
  dump: function (cfg) {
    var m = Process.findModuleByName(cfg.module);
    if (m === null) return { error: "no module" };
    var base = m.base;
    function ptr(a) { try { var p = a.readPointer(); return p.isNull() ? null : p; } catch (e) { return null; } }
    function hex(p) { return p ? p.toString() : null; }

    var vec = ptr(base.add(cfg.list_rva));   // std::vector<ScriptRecord>*
    var out = { script_list: hex(vec), count: 0, scripts: [] };
    if (vec === null) return out;
    var begin = ptr(vec);
    var end = ptr(vec.add(8));
    if (begin === null || end === null) return out;

    var n = end.sub(begin).toInt32() / cfg.rec_size;
    out.count = n;
    for (var i = 0; i < n; i++) {
      var rec = begin.add(i * cfg.rec_size);
      // MSVC std::string: SSO buffer at name_off, size at name_off+0x10.
      var size = 0;
      try { size = rec.add(cfg.name_off + 0x10).readU64().valueOf(); } catch (e) {}
      var name = null;
      try {
        var buf = size < 16 ? rec.add(cfg.name_off) : rec.add(cfg.name_off).readPointer();
        name = buf.readUtf8String(Math.min(size, 256));
      } catch (e) {}
      out.scripts.push({
        i: i,
        record: rec.toString(),
        active: rec.add(cfg.active_off).readU32(),
        state: hex(ptr(rec.add(cfg.state_off))),
        name: name,
        globalCount: rec.add(cfg.global_off).readS32(),
      });
    }
    return out;
  },
};
"""


def find_pid() -> int | None:
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() in ("forts.exe", "forts"):
            return p.pid
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="List loaded Forts Lua scripts.")
    ap.add_argument("--pid", type=int, default=None, help="attach to this pid")
    args = ap.parse_args()

    targets = load_targets()
    rec = targets["structs"]["script_record"]
    fields = {f["name"]: hexint(f["offset"]) for f in rec["fields"]}
    cfg = {
        "module": targets["module"],
        "list_rva": hexint(targets["globals"]["ScriptList"]["rva"]),
        "rec_size": hexint(rec["size"]),
        "active_off": fields["active"],
        "state_off": fields["state"],
        "name_off": fields["name"],
        "global_off": fields["global_count"],
    }

    pid = args.pid or find_pid()
    if pid is None:
        print("no running Forts.exe found (launch the game, then retry)")
        return 1

    session = frida.attach(pid)
    script = session.create_script(AGENT)
    script.load()
    out = script.exports_sync.dump(cfg)
    session.detach()

    if out.get("error"):
        print(f"error: {out['error']}")
        return 1
    print(f"ScriptList @ {out['script_list']}  ({out['count']} script(s))")
    for s in out["scripts"]:
        flag = "active" if s["active"] else "inactive"
        print(
            f"  [{s['i']}] {s['name']}  ({flag})  state={s['state']}  "
            f"globals={s['globalCount']}  rec={s['record']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

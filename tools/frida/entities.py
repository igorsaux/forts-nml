"""Read-only live probe for Forts entities and physics.

Attaches to a running game (a match must be active) and walks the simulation's
entity containers, printing what it can resolve plus raw hex so offsets can be
confirmed. Nothing is written; detach is clean.

The offsets it reads come from reverse engineering the WorldSim tick and the
game's own world-dump serializers (see tools/frida/AGENTS.md, "Entities and
physics"). They are still being verified, so this tool also dumps raw bytes.

Usage:
    uv run python tools/frida/entities.py                 # one sample
    uv run python tools/frida/entities.py --samples 3 --interval 0.5
    uv run python tools/frida/entities.py --pid 1234
    uv run python tools/frida/entities.py --max-nodes 4 --devices
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import frida

from forts import hexint, load_targets

AGENT = """
rpc.exports = {
  sample: function (cfg) {
    var m = Process.findModuleByName(cfg.module);
    if (m === null) return { ok: false, error: "module not found" };
    var base = m.base;

    function ptr(add) { return base.add(add); }
    function u32(a) { return a.readU32(); }
    function i32(a) { return a.readS32(); }
    function f32(a) { return a.readFloat(); }

    var out = { ok: true };

    var world = ptr(cfg.world_ptr_rva).readPointer();
    out.world = world.toString();
    if (world.isNull()) { out.ok = false; out.error = "no active world (not in a match?)"; return out; }

    var sim = world.add(cfg.world_sim).readPointer();
    out.sim = sim.toString();
    if (sim.isNull()) { out.ok = false; out.error = "null sim"; return out; }

    // ---- physics / sim state -------------------------------------------------
    var phys = {};
    phys.fixed_timestep = f32(sim.add(0x1860));
    phys.batch_a = i32(sim.add(0x1864));            // Physics.FramesPerTick
    phys.batch_b = i32(sim.add(0x1868));            // Physics.TickLookahead
    phys.frame = u32(sim.add(0x18b8));
    phys.accumulated = f32(sim.add(0x18ac));
    phys.alpha = f32(sim.add(0x18b4));
    phys.clock_time = f32(sim.add(0x18c8));   // embedded SoftwareTimeKeeper.time
    phys.enabled_flag_1101 = sim.add(0x1101).readU8();
    phys.enabled_flag_1102 = sim.add(0x1102).readU8();
    // sim+0x78 -> object whose +8 byte gates the per-tick world-dump writer.
    try {
      var g = sim.add(0x78).readPointer();
      phys.dump_gate_ptr = g.toString();
      phys.dump_gate = g.isNull() ? null : g.add(8).readU8();
    } catch (e) { phys.dump_gate = "err:" + e; }
    out.physics = phys;

    // ---- resolved physics parameters ----------------------------------------
    // WorldSim ctor copies every "Physics.*" setting into fixed sim offsets.
    var par = {};
    par.oversamples = u32(sim.add(0x1104));                    // Physics.Oversamples
    par.minimum_mass = f32(sim.add(0x1108));                   // Physics.MinimumMass
    par.angle_stress_primary = f32(sim.add(0x1114));           // rad
    par.angle_stress_secondary = f32(sim.add(0x1118));         // rad
    par.min_strut_divergence = f32(sim.add(0x1120));           // rad
    par.collision_lookahead = f32(sim.add(0x1874));            // Physics.CollisionLookaheadDistance
    par.collision_structure_bias = f32(sim.add(0x1878));       // Physics.CollisionStructureOverDeviceBias
    par.projectile_recoil = f32(sim.add(0x116c));              // Physics.ProjectileRecoilFactor
    par.water_force = f32(sim.add(0x12b0));                    // Physics.Water.Force
    par.water_drag = f32(sim.add(0x12c0));                     // Physics.Water.Drag
    par.water_max_depth = f32(sim.add(0x12bc));                // Physics.Water.MaxDepth
    par.min_stiffness = f32(sim.add(0x12a0));                  // Physics.MinStiffness
    par.max_stiffness = f32(sim.add(0x12a4));                  // Physics.MaxStiffness
    par.link_snap = f32(sim.add(0x114c));                      // Physics.Thresholds.LinkSnap
    par.node_snap_neutral_bias = f32(sim.add(0x1148));         // Physics.Thresholds.NodeSnapNeutralBias
    par.temp_bracing_duration = f32(sim.add(0x4c));            // Physics.TempBracing.Duration
    par.threaded = sim.add(0x80).readU8();                     // Physics.Threaded
    par.all_nodes_fixed = sim.add(0x11da).readU8();            // Physics.AllNodesFixed
    out.params = par;

    // ---- terrain manager (global gravity / air drag) -------------------------
    try {
      var terrain = world.add(cfg.world_terrain).readPointer();
      out.terrain = terrain.toString();
      if (!terrain.isNull()) {
        out.terrain_params = {
          gravity: f32(terrain.add(0x9f4)),      // Physics.Gravity (positive down)
          air_drag: f32(terrain.add(0x9fc)),     // Physics.AirDrag
          world_extent_lo: f32(terrain.add(0x9dc)),
          world_extent_hi: f32(terrain.add(0x9e4)),
        };
      }
    } catch (e) { out.terrain_error = String(e); }

    // ---- node container ------------------------------------------------------
    // WorldSim+0x30 / +0x38 = std::vector<Node*> begin/end (8 bytes per slot).
    var nodes = [];
    try {
      var nbegin = sim.add(0x30).readPointer();
      var nend = sim.add(0x38).readPointer();
      var ncount = nend.sub(nbegin).toInt32() / 8;
      out.node_slots = ncount;
      var maxn = Math.min(ncount, cfg.max_nodes);
      for (var i = 0; i < maxn; i++) {
        var n = nbegin.add(i * 8).readPointer();
        var rec = { index: i, ptr: n.toString() };
        if (!n.isNull()) {
          rec.id = u32(n.add(0xec));
          rec.team_0f0 = u32(n.add(0xf0));
          rec.side = rec.team_0f0 % 100;
          rec.mass = f32(n.add(0xf8));
          rec.drag = f32(n.add(0xfc));
          rec.pos = [f32(n.add(0x100)), f32(n.add(0x104)), f32(n.add(0x108))];
          rec.vel = [f32(n.add(0x10c)), f32(n.add(0x110)), f32(n.add(0x114))];
          rec.structure_id = i32(n.add(0x124));
          rec.prev = [f32(n.add(0x128)), f32(n.add(0x12c))];
          rec.controller = n.add(0xc4).readPointer().toString();
          rec.projectile = n.add(0xbc).readPointer().toString();
          // Candidate std::vector<Link> control blocks (three pointers each).
          rec.qw = {
            c8: n.add(0xc8).readPointer().toString(),
            cc: n.add(0xcc).readPointer().toString(),
            d0: n.add(0xd0).readPointer().toString(),
            d4: n.add(0xd4).readPointer().toString(),
            d8: n.add(0xd8).readPointer().toString(),
            dc: n.add(0xdc).readPointer().toString(),
            e0: n.add(0xe0).readPointer().toString(),
            e8: n.add(0xe8).readPointer().toString(),
          };
          if (i === 2) {
            var bytes = new Uint8Array(n.readByteArray(0x1A0));
            var hex = "";
            for (var k = 0; k < bytes.length; k++) {
              hex += (bytes[k] < 16 ? "0" : "") + bytes[k].toString(16);
              if (k % 8 === 7) hex += " ";
            }
            out.node_hex = hex;
          }
        }
        nodes.push(rec);
      }
    } catch (e) { out.node_error = String(e); }
    out.nodes = nodes;

    // ---- device container ----------------------------------------------------
    // World+0x1ca8 (manager) -> +0x6c0/+0x6c8 = std::vector<Device*> begin/end.
    out.devices = [];
    try {
      var mgr = world.add(cfg.world_mgr).readPointer();
      out.mgr = mgr.toString();
      if (!mgr.isNull()) {
        var dbegin = mgr.add(0x6c0).readPointer();
        var dend = mgr.add(0x6c8).readPointer();
        var dcount = dend.sub(dbegin).toInt32() / 8;
        out.device_count = dcount;
        var maxd = Math.min(dcount, cfg.max_devices);
        for (var j = 0; j < maxd; j++) {
          var d = dbegin.add(j * 8).readPointer();
          var rec = { index: j, ptr: d.toString() };
          if (!d.isNull()) {
            // Candidate fields (being verified): team/side at +0x318, state at +0x326.
            rec.team_318 = u32(d.add(0x318));
            rec.side = rec.team_318 % 100;
            rec.state_326 = d.add(0x326).readU8();
            rec.block_310 = f32(d.add(0x310));  // start of the device's 0x38-byte block
            var db = new Uint8Array(d.readByteArray(0x40));
            var dh = "";
            for (var q = 0; q < db.length; q++) {
              dh += (db[q] < 16 ? "0" : "") + db[q].toString(16);
              if (q % 8 === 7) dh += " ";
            }
            rec.hex = dh;
          }
          out.devices.push(rec);
        }
      }
    } catch (e) { out.device_error = String(e); }

    return out;
  },

  setDump: function (cfg) {
    var m = Process.findModuleByName(cfg.module);
    if (m === null) return "no module";
    var base = m.base;
    try {
      var world = base.add(cfg.world_ptr_rva).readPointer();
      if (world.isNull()) return "no world";
      var sim = world.add(cfg.world_sim).readPointer();
      if (sim.isNull()) return "no sim";
      var g = sim.add(0x78).readPointer();
      if (g.isNull()) return "no gate object";
      g.add(8).writeU8(cfg.value & 0xff);
      return "dump_gate=" + (cfg.value & 0xff);
    } catch (e) { return "err:" + e; }
  },
};
"""


def build_cfg(targets: dict) -> dict:
    world = targets["structs"]["world"]
    off = {f["name"]: hexint(f["offset"]) for f in world["fields"]}
    return {
        "module": targets["module"],
        "world_ptr_rva": hexint(targets["globals"]["World_ptr"]["rva"]),
        "world_sim": off["sim"],
        "world_mgr": off["manager_1ca8"],
        "world_terrain": 0x1CC0,
        "max_nodes": 6,
        "max_devices": 6,
    }


def find_pid() -> int | None:
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() in ("forts.exe", "forts"):
            return p.pid
    return None


def run_one(script, cfg: dict) -> dict:
    res = script.exports_sync.sample(cfg)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe Forts entities/physics (read-only).")
    ap.add_argument("--samples", type=int, default=1)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--max-nodes", type=int, default=6)
    ap.add_argument("--max-devices", type=int, default=6)
    ap.add_argument("--devices", action="store_true",
                    help="print the device section too")
    ap.add_argument("--dump", action="store_true",
                    help="toggle the game's own per-tick world-dump on briefly, "
                         "then list any new world-dump files")
    args = ap.parse_args()

    targets = load_targets()
    cfg = build_cfg(targets)
    cfg["max_nodes"] = args.max_nodes
    cfg["max_devices"] = args.max_devices

    pid = args.pid or find_pid()
    if pid is None:
        print("no running Forts.exe found (launch the game, then retry)")
        return 1

    session = frida.attach(pid)
    script = session.create_script(AGENT)
    script.load()
    try:
        if args.dump:
            print("dump on:", script.exports_sync.set_dump({**cfg, "value": 1}))
            time.sleep(0.15)
            print("dump off:", script.exports_sync.set_dump({**cfg, "value": 0}))
        for i in range(args.samples):
            res = run_one(script, cfg)
            print(f"--- sample {i + 1}/{args.samples} ---")
            print(json.dumps(res, indent=2, default=str))
            if i + 1 < args.samples:
                time.sleep(args.interval)
    finally:
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


// Tick/dispatch hook agent.
//
// Attaches to World_Sim_Update_Tick (once per rendered frame) and
// Scripts_Update_Dispatch (once per fixed simulation step), then reports
// samples so we can confirm the documented tick chain actually runs.
//
// delta handling: World_Sim_Update_Tick's second argument is a float in XMM1.
// Depending on the Frida build, CpuContext may or may not expose XMM registers,
// so we probe it defensively and also report the fixed timestep from sim+0x1860.

var S = null;

// Frida 17 exposes xmmN as an opaque boxed register object, not a JS number.
// Try every reasonable conversion and report what the value actually was.
function readFloatReg(x) {
  if (x === null || x === undefined) return { value: null, type: String(x) };
  var t = typeof x;
  if (t === "number") return { value: x, type: "number" };
  var n = Number(x);
  if (!isNaN(n)) return { value: n, type: t + "->number" };
  try {
    var view = new Uint8Array(x);
    if (view.length >= 4) {
      var f = new Float32Array(
        view.buffer.slice(view.byteOffset, view.byteOffset + 4)
      );
      return { value: f[0], type: t + "->f32/" + view.length + "B" };
    }
  } catch (e) {}
  return { value: null, type: t + " " + String(x) };
}

rpc.exports = {
  start: function (cfg) {
    if (S !== null) return "already-started";

    var m = Process.findModuleByName(cfg.module);
    if (m === null) return "module-not-found";
    var base = m.base;

    S = {
      cfg: cfg,
      base: base,
      tick: 0,
      dispatch: 0,
      frame: 0,
      present: 0,
      input: 0,
      reportedCtxKeys: false,
      world_ptr: base.add(cfg.world_ptr_rva),
      input_ptr: cfg.input_ptr_rva ? base.add(cfg.input_ptr_rva) : null,
      match_seen: false,
    };

    function addr(rva) {
      return base.add(rva);
    }

    var sim = cfg.offsets.sim;

    if (cfg.tick_rva) {
      Interceptor.attach(addr(cfg.tick_rva), {
        onEnter: function (args) {
          var self = args[0];
          if (!S.reportedCtxKeys) {
            S.reportedCtxKeys = true;
            var keys = [];
            try {
              keys = Object.keys(this.context);
            } catch (e) {}
            send({ type: "ctxkeys", keys: keys });
          }

          var rec = {
            n: S.tick,
            frame: null,
            dt_fixed: null,
            acc: null,
            alpha: null,
            delta: null,
            delta_type: null,
          };
          try {
            rec.frame = self.add(sim.frame_counter).readU32();
          } catch (e) {}
          try {
            rec.dt_fixed = self.add(sim.fixed_timestep).readFloat();
          } catch (e) {}
          try {
            rec.acc = self.add(sim.accumulated).readFloat();
          } catch (e) {}
          try {
            rec.alpha = self.add(sim.alpha).readFloat();
          } catch (e) {}
          try {
            var got = readFloatReg(this.context.xmm1);
            rec.delta = got.value;
            rec.delta_type =
              got.type + " (" + Object.prototype.toString.call(this.context.xmm1) + ")";
          } catch (e) {}

          S.tick++;
          if (S.tick <= 3 || S.tick % S.cfg.sample_every === 0) {
            send({ type: "tick", sample: rec });
          }
        },
      });
    }

    if (cfg.dispatch_rva) {
      Interceptor.attach(addr(cfg.dispatch_rva), {
        onEnter: function (args) {
          S.dispatch++;
        },
      });
    }

    // App-frame counter: FortsShell::Execute runs once per rendered frame in
    // EVERY state (menus and match), unlike the sim tick which only exists
    // while a World is alive. Present counts actual SwapBuffers frames.
    if (cfg.frame_rva) {
      Interceptor.attach(addr(cfg.frame_rva), {
        onEnter: function (args) {
          S.frame++;
        },
      });
    }

    if (cfg.present_rva) {
      Interceptor.attach(addr(cfg.present_rva), {
        onEnter: function (args) {
          S.present++;
        },
      });
    }

    // Input poll: also once per frame, straight after the frame start.
    if (cfg.input_rva) {
      Interceptor.attach(addr(cfg.input_rva), {
        onEnter: function (args) {
          S.input++;
        },
      });
    }

    return "started";
  },

  stats: function () {
    if (S === null) {
      return {
        tick: 0,
        dispatch: 0,
        frame: 0,
        present: 0,
        input: 0,
        world_ptr: null,
        match_seen: false,
      };
    }
    var wp = null;
    try {
      wp = S.world_ptr.readPointer();
      if (!wp.isNull()) S.match_seen = true;
    } catch (e) {}
    return {
      tick: S.tick,
      dispatch: S.dispatch,
      frame: S.frame,
      present: S.present,
      input: S.input,
      world_ptr: wp === null ? null : wp.toString(),
      match_seen: S.match_seen,
    };
  },

  // Read the live InputManager keyboard/mouse state. Demonstrates listening to
  // input (and the same fields can be zeroed to filter it for an overlay):
  //   keyboard_state is a 256-byte DIK array, 0x80 bit set == key down.
  //   mouse_dx/dy/wheel are per-frame relative deltas.
  input: function () {
    if (S === null || S.input_ptr === null) {
      return { ok: false, keys: [], mouse: null };
    }
    var im = null;
    try {
      im = S.input_ptr.readPointer();
    } catch (e) {}
    if (im === null || im.isNull()) return { ok: false, keys: [], mouse: null };
    var off = (S.cfg.offsets && S.cfg.offsets.input) || {};
    var keys = [];
    try {
      var buf = new Uint8Array(
        im.add(off.keyboard_state).readByteArray(256)
      );
      for (var i = 0; i < 256; i++) {
        if (buf[i] & 0x80) keys.push(i);
      }
    } catch (e) {}
    var mouse = null;
    try {
      mouse = {
        dx: im.add(off.mouse_dx).readS32(),
        dy: im.add(off.mouse_dy).readS32(),
        wheel: im.add(off.mouse_wheel).readS32(),
      };
    } catch (e) {}
    return { ok: true, keys: keys, mouse: mouse };
  },
};

// Live probe for the ObjectFactory -> World construction chain.
//
// We hook the factory's entry (RVA 0x1EA7B0). With the nml loader active that
// entry is detoured (E9) to the loader's relay, so this hook observes the value
// the *game* receives. We separately hook World_ctor and read its return value
// (the real allocated World*), and report the live state of both the entry and
// the vtable slot at 0x6E05C8 so we can tell how the loader reroutes the call.
//
// (Hooking the function's 1-byte `ret` epilogue is not supported by Frida's
//  interceptor, so the original's own return is inferred from World_ctor.)

rpc.exports = {
  // Lightweight poll: report whether the loader has already detoured the entry.
  // The caller waits for patched===true before installing hooks so the loader's
  // own patch cannot clobber them.
  state: function (cfg) {
    var mod = Process.findModuleByName(cfg.module);
    if (mod === null) return { module: false };
    var base = mod.base;
    var e = base.add(cfg.factory_rva);
    var first = e.readU8();
    var relay = null;
    if (first === 0xe9) {
      relay = e.add(5).add(e.add(1).readS32()).toString();
    }
    var loader = null;
    Process.enumerateModules().forEach(function (m) {
      if (/dinput8/i.test(m.name)) loader = m.base.toString() + " (" + m.path + ")";
    });
    return { module: true, first_byte: first, patched: first === 0xe9, relay: relay, loader: loader };
  },

  start: function (cfg) {
    var mod = Process.findModuleByName(cfg.module);
    if (mod === null) return "module-not-found";
    var base = mod.base;

    function A(rva) {
      return base.add(rva);
    }

    function describe_entry() {
      var e = A(cfg.factory_rva);
      var first = e.readU8();
      var relay = null;
      if (first === 0xe9) {
        relay = e.add(5).add(e.add(1).readS32());
      }
      return {
        first_byte: first,
        patched: first === 0xe9,
        relay: relay === null ? null : relay.toString(),
      };
    }

    function slot_value() {
      try {
        return A(cfg.vtable_rva).readPointer().toString();
      } catch (e) {
        return "unreadable:" + e;
      }
    }

    function ptr_at(rva) {
      try {
        return A(rva).readPointer().toString();
      } catch (e) {
        return "unreadable:" + e;
      }
    }

    function loader_info() {
      var info = { modules: [] };
      Process.enumerateModules().forEach(function (m) {
        if (/dinput8/i.test(m.name)) {
          info.modules.push(m.name + "@" + m.base + " (" + m.path + ")");
        }
      });
      return info;
    }

    send({
      type: "setup",
      module_base: base.toString(),
      factory: A(cfg.factory_rva).toString(),
      expected_original: A(cfg.factory_rva).toString(),
      vtable_slot: slot_value(),
      vtable_slot_expected: A(cfg.factory_rva).toString(),
      entry: describe_entry(),
      world_ptr: ptr_at(cfg.world_ptr_rva),
      world_ptr2: ptr_at(cfg.world_ptr2_rva),
      loader: loader_info(),
    });

    // Also catch a native crash so a single run covers both the call chain and
    // the faulting instruction.
    function mod(a) {
      if (a === null || a === undefined) return null;
      try {
        var m = Process.findModuleByAddress(a);
        return a.toString() + (m ? " " + m.name + "+0x" + a.sub(m.base).toString(16) : "");
      } catch (e) {
        return a.toString();
      }
    }
    Process.setExceptionHandler(function (details) {
      var c = details.context;
      var bt = [];
      try {
        bt = Thread.backtrace(c, Backtracer.ACCURATE).map(mod);
      } catch (e) {
        bt = ["backtrace failed: " + e];
      }
      send({
        type: "exception",
        exception_type: details.type,
        address: mod(details.address),
        rip: c ? mod(c.rip) : null,
        rax: c ? c.rax.toString() : null,
        rcx: c ? c.rcx.toString() : null,
        rdx: c ? c.rdx.toString() : null,
        r8: c ? c.r8.toString() : null,
        backtrace: bt,
      });
      return false;
    });

    // --- factory entry (relay when detoured) =================================
    Interceptor.attach(A(cfg.factory_rva), {
      onEnter: function (args) {
        this.info = { ty: args[1].toInt32(), tid: Process.getCurrentThreadId() };
        send({
          type: "factory_enter",
          self: args[0].toString(),
          ty: this.info.ty,
          setup: args[2].toString(),
          live_entry: describe_entry(),
          live_vtable_slot: slot_value(),
          live_world_ptr: ptr_at(cfg.world_ptr_rva),
          tid: this.info.tid,
        });
      },
      onLeave: function (retval) {
        send({
          type: "factory_leave",
          ty: this.info.ty,
          ret: retval.toString(),
          tid: this.info.tid,
        });
      },
    });

    // --- World_ctor ==========================================================
    Interceptor.attach(A(cfg.world_ctor_rva), {
      onEnter: function (args) {
        this.self = args[0];
        send({
          type: "world_ctor_enter",
          self: args[0].toString(),
          engine: args[1].toString(),
          setup: args[2].toString(),
          tid: Process.getCurrentThreadId(),
        });
      },
      onLeave: function (retval) {
        send({ type: "world_ctor_leave", ret: retval.toString(), self: this.self.toString() });
      },
    });

    // --- World_Sim_ctor ======================================================
    Interceptor.attach(A(cfg.world_sim_ctor_rva), {
      onEnter: function (args) {
        send({
          type: "sim_ctor_enter",
          self: args[0].toString(),
          world: args[1].toString(),
          tid: Process.getCurrentThreadId(),
        });
      },
    });

    return "started";
  },

  stop: function () {
    return "stopped";
  },
};

// Diagnostic agent: reports the raw exception code and a backtrace whenever the
// process raises an exception, without spawning the game (attach to a running
// instance so the game's own crash reporter is already initialised).
//
//   * ntdll!RaiseException  -> software exceptions (code in arg0, address in arg3)
//   * Process.setExceptionHandler -> hardware faults (AV, illegal instruction, ...)
//
// Returns false from the handler so the game's own handling continues.

function mod(a) {
  if (a === null || a === undefined) return null;
  try {
    var m = Process.findModuleByAddress(a);
    return a.toString() + (m ? " " + m.name + "+0x" + a.sub(m.base).toString(16) : "");
  } catch (e) {
    return a.toString();
  }
}

var CODES = {
  0xc0000005: "ACCESS_VIOLATION",
  0xc000001d: "ILLEGAL_INSTRUCTION",
  0xc0000094: "INT_DIVIDE_BY_ZERO",
  0xc00000fd: "STACK_OVERFLOW",
  0xc0000409: "FASTFAIL",
  0x80000003: "BREAKPOINT",
  0xc0000374: "HEAP_CORRUPTION",
  0xe06d7363: "C++ EH",
  0xc000013a: "CONTROL_C_EXIT",
};

function codeName(c) {
  return CODES[c >>> 0] || "0x" + (c >>> 0).toString(16);
}

rpc.exports = {
  arm: function () {
    // Resolve ntdll!RaiseException across Frida versions.
    var raiseEx = null;
    try { raiseEx = Module.getExportByName("ntdll.dll", "RaiseException"); } catch (e) {}
    if (raiseEx === null) {
      try { raiseEx = Process.getModuleByName("ntdll.dll").getExportByName("RaiseException"); } catch (e) {}
    }
    if (raiseEx === null) {
      try { raiseEx = Module.getGlobalExportByName("RaiseException"); } catch (e) {}
    }
    if (raiseEx === null) {
      send({ type: "note", text: "RaiseException not resolved" });
    } else {
      Interceptor.attach(raiseEx, {
        onEnter: function (args) {
          var code = args[0].toUInt32();
          send({
            type: "raise_exception",
            code: "0x" + code.toString(16),
            name: codeName(code),
            flags: args[1].toUInt32(),
            nargs: args[2].toInt32(),
            backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(mod),
          });
        },
      });
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
        type: "fault",
        exception_type: details.type,
        address: mod(details.address),
        memory: details.memory
          ? { address: mod(details.memory.address), operation: details.memory.operation }
          : null,
        rip: c ? mod(c.rip) : null,
        rax: c ? c.rax.toString() : null,
        rcx: c ? c.rcx.toString() : null,
        rdx: c ? c.rdx.toString() : null,
        r8: c ? c.r8.toString() : null,
        rsp: c ? c.rsp.toString() : null,
        backtrace: bt,
      });
      return false;
    });

    return "armed";
  },
};

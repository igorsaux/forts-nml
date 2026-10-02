// Crash catcher. Installs a native exception handler and reports the faulting
// instruction plus a backtrace, so a crash inside the loader relay/trampoline
// or the original code can be told apart. Returns `false` so the process still
// terminates normally after we have recorded the details.

rpc.exports = {
  arm: function (cfg) {
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
        code: details.code !== undefined ? "0x" + details.code.toString(16) : null,
        flags: details.flags !== undefined ? details.flags : null,
        parameters: details.parameters || null,
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
        rbp: c ? c.rbp.toString() : null,
        backtrace: bt,
      });
      return false;
    });

    return "armed";
  },
};

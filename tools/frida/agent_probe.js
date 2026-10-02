// Runtime verification agent.
//
// Receives an int-only payload built by forts.payload_for_agent() and checks
// that every target from targets.json resolves correctly in the live process:
// function prologues, vtable slots, anchor strings and global slots.
//
// The payload crosses the Python<->JS boundary as JSON, so all RVA values are
// plain integers; `base.add(rva)` turns them into live addresses.

function hex(ptr) {
  return ptr === null ? "null" : ptr.toString();
}

// Frida 17 removed Module.findBaseAddress; Process.findModuleByName is the
// replacement and returns {name, base, size, path} or null.
function findBase(name) {
  var m = Process.findModuleByName(name);
  return m === null ? null : m.base;
}

rpc.exports = {
  // Base address of a module, or null if it is not mapped yet. The caller
  // polls this from Python (Frida 17 agents have no Thread.sleep/setTimeout).
  modulebase: function (name) {
    var base = findBase(name);
    return base === null ? null : base.toString();
  },

  check: function (t) {
    var results = [];
    var base = findBase(t.module);
    if (base === null) {
      return { module_name: t.module, module_base: null, results: results };
    }
    var module_base = base.toString();

    function addr(rva) {
      return base.add(rva);
    }

    // --- function prologues -------------------------------------------------
    for (var fname in t.functions) {
      var f = t.functions[fname];
      var a = addr(f.rva);
      var ok = true;
      var detail = a.toString();
      if (f.prologue && f.prologue.length > 0) {
        try {
          var got = new Uint8Array(a.readByteArray(f.prologue.length));
          for (var i = 0; i < f.prologue.length; i++) {
            if (got[i] !== f.prologue[i]) {
              ok = false;
              break;
            }
          }
          var have = Array.prototype.map
            .call(got, function (x) {
              return ("0" + x.toString(16)).slice(-2);
            })
            .join(" ");
          detail = a + "  " + have + (ok ? "" : "  != expected");
        } catch (e) {
          ok = false;
          detail = a + "  unreadable: " + e;
        }
      }
      results.push({ kind: "function", name: fname, ok: ok, detail: detail });
    }

    // --- vtable slots -------------------------------------------------------
    for (var vname in t.vtables) {
      var vt = t.vtables[vname];
      for (var s = 0; s < vt.slots.length; s++) {
        var slot = vt.slots[s];
        var slot_addr = addr(vt.rva + slot.offset);
        var expected = addr(slot.rva);
        var got_ptr = null;
        var ok = false;
        try {
          got_ptr = slot_addr.readPointer();
          ok = got_ptr.equals(expected);
        } catch (e) {}
        results.push({
          kind: "vtable",
          name: vname + "+0x" + slot.offset.toString(16),
          ok: ok,
          detail: hex(got_ptr) + (ok ? "" : " != " + expected),
        });
      }
    }

    // --- anchor strings -----------------------------------------------------
    for (var sname in t.strings) {
      var str = t.strings[sname];
      var sa = addr(str.rva);
      var text = null;
      try {
        // Wide anchors are UTF-16LE (e.g. the debug-panel L"..." formats).
        text = str.wide
          ? sa.readUtf16String(str.text.length)
          : sa.readUtf8String(str.text.length);
      } catch (e) {}
      results.push({
        kind: "string",
        name: sname,
        ok: text === str.text,
        detail: JSON.stringify(text),
      });
    }

    // --- global slots (readability + current value) -------------------------
    for (var gname in t.globals) {
      var g = t.globals[gname];
      var ga = addr(g.rva);
      var val = null;
      var ok = false;
      try {
        val = ga.readPointer();
        ok = true;
      } catch (e) {}
      results.push({
        kind: "global",
        name: gname,
        ok: ok,
        detail: hex(val),
      });
    }

    return { module_name: t.module, module_base: module_base, results: results };
  },
};

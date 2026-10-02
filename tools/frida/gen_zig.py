#!/usr/bin/env python3
"""Generate a Zig manifest module from the versioned targets files.

Reads every ``tools/frida/targets/<version>.json`` (or the files selected with
``--only``), precomputes all derived values in Python (absolute VAs, prologue
byte arrays, resolved vtable slot targets) and writes one data-only Zig file
that embeds *all* supported game versions.

    uv run python tools/frida/gen_zig.py <output.zig>
    uv run python tools/frida/gen_zig.py <output.zig> --only 1.38.2-r22447
    uv run python tools/frida/gen_zig.py <output.zig> --targets-dir path/to/targets

The generated file contains only address/offset data plus a handful of lookup
and selection helpers. The runtime loader is expected to pick the matching
manifest itself (by file hash or by prologue fingerprint); no game or library
logic is emitted.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import forts  # noqa: E402
from forts import hexint, load_targets, prefix_bytes  # noqa: E402

GENERATED_BY = "tools/frida/gen_zig.py"

# A detour is a relative E9 jump (5 bytes) by default; an absolute 64-bit jump
# needs 14 bytes. The generator computes the instruction-aligned steal length.
DEFAULT_PATCH_SIZE = 5
RELOC_RIP = 0  # RIP-relative memory operand (disp32 at end of instruction)
RELOC_BRANCH = 1  # relative call/jmp immediate (rel8 or rel32)


# --------------------------------------------------------------------------- #
# Zig literal helpers
# --------------------------------------------------------------------------- #
def zig_hex(value: int) -> str:
    return f"0x{value:X}"


def zig_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def zig_bytes(values: list[int]) -> str:
    if not values:
        return "&[_]u8{}"
    body = ", ".join(f"0x{b:02X}" for b in values)
    return f"&[_]u8{{ {body} }}"


def zig_ident(name: str) -> str:
    ident = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not ident or ident[0].isdigit():
        ident = "_" + ident
    return ident


def version_ident(version: str) -> str:
    """Suffix for composed identifiers (always used after a prefix like
    `manifest_`), so a leading digit is fine: "1.38.2-r22447" -> "1_38_2_r22447"."""
    return re.sub(r"[^0-9A-Za-z_]", "_", version)


def display_path(path: Path) -> str:
    """Portable reference for generated headers: repo-relative when possible."""
    repo_root = HERE.parent.parent  # tools/frida -> tools -> repo root
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def emit_doc(out: list[str], text, indent: str = "", prefix: str = "///") -> None:
    """Emit `text` as doc (`///`) or plain (`//`) comment lines."""
    if not text:
        return
    for line in str(text).split("\n"):
        out.append(f"{indent}{prefix} {line}".rstrip())


def fn_alias_name(name: str) -> str:
    """Hook name -> generated signature alias: World_Sim_dtor -> FnWorldSimDtor."""
    parts = re.split(r"[^0-9A-Za-z]+", name)
    return "Fn" + "".join(p[:1].upper() + p[1:] for p in parts if p)


# --------------------------------------------------------------------------- #
# Precomputation
# --------------------------------------------------------------------------- #
def decode_patch(
    code: bytes, image_base: int, rva: int, patch_size: int, md: Cs
) -> dict:
    """Disassemble enough whole instructions to cover `patch_size` bytes.

    Returns the steal length, original bytes, resume RVA and a relocation table.
    Only relative displacements need relocation; their absolute target is
    resolved here (as an RVA) so the runtime never has to disassemble anything.
    Everything is RVA-based: the caller adds the runtime module base.
    """
    base_va = image_base + rva
    instructions: list[dict] = []
    relocs: list[dict] = []
    relocatable = True
    covered = 0

    for ins in md.disasm(code, base_va):
        if ins.size == 0:
            break
        ins_off = ins.address - base_va

        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                # Offset is relative to the whole stolen block, not the insn.
                relocs.append(
                    {
                        "offset": ins_off + ins.size - 4,
                        "width": 4,
                        "kind": RELOC_RIP,
                        "target_rva": ins.address + ins.size + op.mem.disp - image_base,
                    }
                )

        is_branch = CS_GRP_CALL in ins.groups or CS_GRP_JUMP in ins.groups
        if is_branch and any(op.type == X86_OP_IMM for op in ins.operands):
            first = ins.bytes[0]
            if first in (0xE8, 0xE9):  # call/jmp rel32
                disp = struct.unpack_from("<i", ins.bytes, ins.size - 4)[0]
                width = 4
            else:  # rel8 branch: not safely relocatable in place
                disp = struct.unpack_from("<b", ins.bytes, ins.size - 1)[0]
                width = 1
                relocatable = False
            relocs.append(
                {
                    "offset": ins_off + ins.size - width,
                    "width": width,
                    "kind": RELOC_BRANCH,
                    "target_rva": ins.address + ins.size + disp - image_base,
                }
            )

        instructions.append(
            {
                "offset": ins_off,
                "len": ins.size,
                "text": (ins.mnemonic + " " + ins.op_str).strip(),
            }
        )
        covered = ins_off + ins.size
        if covered >= patch_size:
            break

    if covered < patch_size:
        relocatable = False

    return {
        "len": covered,
        "original": list(code[:covered]),
        "resume_rva": rva + covered,
        "relocatable": relocatable,
        "relocs": relocs,
        "instructions": instructions,
    }


def build_functions(
    targets: dict, md: Cs, patch_size: int = DEFAULT_PATCH_SIZE
) -> list[dict]:
    image_base = hexint(targets["image_base"])
    out = []
    for name, f in targets["functions"].items():
        rva = hexint(f["rva"])
        prologue = bytes(prefix_bytes(f.get("prologue", "")))
        out.append(
            {
                "name": name,
                "rva": rva,
                "prologue": list(prologue),
                "patch": decode_patch(prologue, image_base, rva, patch_size, md),
                "doc": f.get("_doc"),
            }
        )
    return out


def build_vtables(targets: dict, functions: dict[str, dict]) -> list[dict]:
    out = []
    for name, vt in targets["vtables"].items():
        rva = hexint(vt["rva"])
        slots = []
        for slot in vt["slots"]:
            offset = hexint(slot["offset"])
            if "function" in slot:
                target_name = slot["function"]
                target_rva = functions[target_name]["rva"]
            else:
                target_name = ""
                target_rva = hexint(slot["rva"])
            slots.append(
                {
                    "offset": offset,
                    "name": target_name,
                    "target_rva": target_rva,
                    "doc": slot.get("_doc"),
                }
            )
        out.append({"name": name, "rva": rva, "slots": slots, "doc": vt.get("_doc")})
    return out


def variable_size_align(name: str, g: dict) -> tuple[int, int]:
    """(size, alignment) of a global variable, from its declared `type`.

    Uses the same JSON type vocabulary as struct fields (`ptr`, `bool`, the
    scalars, and `str` with an explicit `count`), so a variable's width is
    described identically to a field's.
    """
    t = g.get("type")
    if t is None:
        raise SystemExit(f"global {name!r} has no 'type'")
    if t == "bool":
        return (1, 1)
    if t == "ptr":
        return (8, 8)
    if t == "str":
        if "count" not in g:
            raise SystemExit(f"global {name!r} of type 'str' needs a 'count'")
        count = int(g["count"])
        return (count, 1)
    if t in SCALAR_TYPES:
        _, size, align = SCALAR_TYPES[t]
        return (size, align)
    raise SystemExit(f"global {name!r}: unknown type {t!r}")


def build_variables(targets: dict) -> list[dict]:
    """Normalise targets['globals'] into variables with a resolved size/align.

    A global is the build's global variable: a name, its RVA, and the size and
    natural alignment of the value stored there. This is the global-variable
    analogue of a struct field, and powers a VariableInterface
    (`exists`/`get_info`/`locate`).
    """
    out = []
    for name, g in targets.get("globals", {}).items():
        size, align = variable_size_align(name, g)
        out.append(
            {
                "name": name,
                "rva": hexint(g["rva"]),
                "size": size,
                "alignment": align,
                "doc": g.get("_doc"),
            }
        )
    return out


# --------------------------------------------------------------------------- #
# Struct layouts / field maps
# --------------------------------------------------------------------------- #
# JSON struct field vocabulary (see tools/frida/AGENTS.md, "Struct field types").
# JSON field type -> (zig layout type, size, alignment) for the scalar types.
# Every field is an inline member of the object at its declared offset:
#   u8/i8/u16/i16/u32/i32/u64/i64  little-endian integer of that width
#   f32/f64                        IEEE-754 float/double
# Types handled specially by zig_field_type():
#   bool        C++ bool: 1 byte, non-zero == true; layout u8 (read as != 0)
#   ptr         64-bit pointer to an opaque object; layout ?*anyopaque, may be null
#   str         inline NUL-terminated char[count]; layout [count]u8, size=count,
#               align 1. NOT std::string and NOT a pointer. Read is
#               strnlen(buf, count); write is <= count-1 bytes plus a trailing NUL.
#               `count` is optional in JSON and inferred by
#               forts.resolve_struct_layouts() when absent (next field offset,
#               else struct size minus offset).
#   std_vector  MSVC std::vector<T> control block {first,last,end-of-capacity};
#               layout StdVector (version-local), 24 bytes, align 8. The element
#               type is deliberately not described.
#   embedded    an inline sub-object (NOT a pointer): the referenced struct laid
#               out at this offset, whose first 8 bytes are usually a vptr. JSON
#               carries `"struct": "<group>"`; layout is that group's `*Layout`.
SCALAR_TYPES = {
    "u8": ("u8", 1, 1),
    "i8": ("i8", 1, 1),
    "u16": ("u16", 2, 2),
    "i16": ("i16", 2, 2),
    "u32": ("u32", 4, 4),
    "i32": ("i32", 4, 4),
    "u64": ("u64", 8, 8),
    "i64": ("i64", 8, 8),
    "f32": ("f32", 4, 4),
    "f64": ("f64", 8, 8),
}


def snake(name: str) -> str:
    """CamelCase struct name -> snake_case identifier (WorldSim -> world_sim)."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
    return re.sub(r"[^0-9A-Za-z_]", "_", s).lower()


def zig_field_type(f: dict) -> str:
    """Zig layout type for one resolved struct field.

    `f` comes from `forts.resolve_struct_layouts`, so `str` has a concrete
    `count` and `embedded` has a resolved `ref_name` (the referenced group's C++
    name). Size/alignment come from the same resolver; this only maps to Zig.
    """
    t = f["type"]
    if t == "bool":
        return "u8"  # read as bool via != 0 to avoid @bitCast UB
    if t == "ptr":
        return "?*anyopaque"
    if t == "str":
        return f"[{f['count']}]u8"
    if t == "std_vector":
        return "StdVector"
    if t == "embedded":
        return f"{zig_ident(f['ref_name'])}Layout"
    if t in SCALAR_TYPES:
        return SCALAR_TYPES[t][0]
    raise SystemExit(f"unknown field type {t!r} for {f['name']!r}")


def check_unique_struct_names(structs) -> None:
    """The per-version type map is keyed by struct name; duplicates would make
    ``StaticStringMap.initComptime`` fail at comptime with a cryptic error."""
    seen: dict[str, str] = {}
    for st in structs:
        if st["name"] in seen:
            raise SystemExit(
                f"two struct groups resolve to the same name {st['name']!r}: "
                f"{seen[st['name']]!r} and {st['group']!r}"
            )
        seen[st["name"]] = st["group"]


def emit_structs(targets: dict, out: list[str], ind: str) -> list[dict]:
    """Emit layouts, field locators, per-struct field maps and layout asserts
    for one version, nested in its namespace at `ind`. Names are local to the
    namespace (no version suffix). Returns the version's struct descriptors."""
    def a(line: str = "") -> None:
        out.append(ind + line if line else "")

    resolved = forts.resolve_struct_layouts(targets)
    check_unique_struct_names(resolved.values())
    for st in resolved.values():
        if st["problems"]:
            raise SystemExit(
                f"{st['name']}: " + "; ".join(st["problems"])
            )
        name = zig_ident(st["name"])
        gid = snake(st["name"])
        layout = f"{name}Layout"

        emit_doc(out, st.get("doc"), ind)
        a(f"const {layout} = extern struct {{")
        cur = 0
        for f in st["fields"]:
            off = f["offset"]
            ltype = zig_field_type(f)
            fsize = f["size"]
            pad = off - cur
            if pad:
                a(f"    _pad_{off:X}: [{pad}]u8,")
            emit_doc(out, f.get("doc"), ind + "    ")
            a(f"    {f['name']}: {ltype},")
            cur = off + fsize
        target = st["emitted_size"]
        if target > cur:
            a(f"    _pad_end: [{target - cur}]u8,")
        a("};")
        a("")

        # Locators: return the address of the field storage in a live object.
        W = f"@as(*{layout}, @ptrCast(@alignCast(o)))"
        for f in st["fields"]:
            fn_ = zig_ident(f["name"])
            a(
                f"fn a_{gid}_loc_{fn_}(o: *anyopaque) ?*anyopaque "
                f"{{ return @as(*anyopaque, @ptrCast(&{W}.{f['name']})); }}"
            )
        a("")

        # Field name -> {locate, size, align} for this struct.
        a(f"const {gid}_fields = FieldMap.initComptime(&.{{")
        for f in st["fields"]:
            fn_ = zig_ident(f["name"])
            a(
                f'    .{{ "{f["name"]}", FieldInfo{{ '
                f".locate = a_{gid}_loc_{fn_}, "
                f".size = {zig_hex(f['size'])}, .alignment = {zig_hex(f['align'])} }} }},"
            )
        a("});")
        a("")
        a("comptime {")
        for f in st["fields"]:
            a(
                f'    std.debug.assert(@offsetOf({layout}, "{f["name"]}") '
                f"== {zig_hex(f['offset'])});"
            )
        a(f"    std.debug.assert(@sizeOf({layout}) == {zig_hex(target)});")
        a("}")
        a("")
    return list(resolved.values())


# --------------------------------------------------------------------------- #
# Emission
# --------------------------------------------------------------------------- #
def emit_version(
    targets: dict, out: list[str], md: Cs, patch_size: int = DEFAULT_PATCH_SIZE
) -> None:
    """Emit one game version as `pub const v<vid> = struct { ... }`.

    Everything for the build lives here: the address data, `StdVector`, struct
    layouts and field maps, the game ABI (opaque types, enums, hook signatures,
    relays) and the `manifest` the loader selects. Only the schema types stay at
    file scope; this namespace provides the concrete instance."""
    version = str(targets["version"])
    vid = version_ident(version)
    ns = f"v{vid}"
    hashes = str(targets["sha256"]).lower()
    functions = build_functions(targets, md, patch_size)
    by_name = {f["name"]: f for f in functions}
    vtables = build_vtables(targets, by_name)
    variables = build_variables(targets)

    def a(line: str = "") -> None:
        out.append("    " + line if line else "")

    emit_doc(out, f"Everything for game build {version} ({targets['game']}): the")
    out.append("/// address data, struct layouts and accessors, the game ABI (opaque")
    out.append("/// types, enums, hook signatures, relays) and the manifest.")
    out.append(f"pub const {ns} = struct {{")

    # --- build identity ---
    a("pub const build = Build{")
    a(f"    .game = {zig_string(targets['game'])},")
    a(f"    .version = {zig_string(version)},")
    a(f"    .sha256 = {zig_string(hashes)},")
    a("};")
    a("")

    # --- per-function patch plans (private) ---
    for f in functions:
        fid = zig_ident(f["name"])
        patch = f["patch"]
        a(f"const relocs_{fid} = [_]Reloc{{")
        for r in patch["relocs"]:
            kind = "rip_relative" if r["kind"] == RELOC_RIP else "relative_branch"
            a(f"    .{{ .offset = {zig_hex(r['offset'])}, .width = {zig_hex(r['width'])}, "
              f".kind = .{kind}, .target_rva = {zig_hex(r['target_rva'])} }},")
        a("};")
        a(f"const insns_{fid} = [_]Instruction{{")
        for ins in patch["instructions"]:
            a(f"    .{{ .offset = {zig_hex(ins['offset'])}, .len = {zig_hex(ins['len'])}, "
              f".text = {zig_string(ins['text'])} }},")
        a("};")
        a(f"const patch_{fid} = Patch{{")
        a(f"    .len = {zig_hex(patch['len'])},")
        a(f"    .original = {zig_bytes(patch['original'])},")
        a(f"    .resume_rva = {zig_hex(patch['resume_rva'])},")
        a(f"    .relocatable = {'true' if patch['relocatable'] else 'false'},")
        a(f"    .relocs = &relocs_{fid},")
        a(f"    .instructions = &insns_{fid},")
        a("};")
        a("")

    # --- functions ---
    a("pub const functions = [_]Function{")
    for f in functions:
        emit_doc(out, f.get("doc"), "        ", prefix="//")
        a(f"    .{{ .name = {zig_string(f['name'])}, .rva = {zig_hex(f['rva'])}, "
          f".prologue = {zig_bytes(f['prologue'])}, .patch = patch_{zig_ident(f['name'])} }},")
    a("};")
    a("")

    # --- vtables ---
    for vt in vtables:
        vname = zig_ident(vt["name"])
        a(f"const vt_{vname}_slots = [_]VTableSlot{{")
        for s in vt["slots"]:
            emit_doc(out, s.get("doc"), "        ", prefix="//")
            a(f"    .{{ .offset = {zig_hex(s['offset'])}, "
              f".name = {zig_string(s['name'])}, .target_rva = {zig_hex(s['target_rva'])} }},")
        a("};")
        a("")
    a("pub const vtables = [_]VTable{")
    for vt in vtables:
        vname = zig_ident(vt["name"])
        emit_doc(out, vt.get("doc"), "        ", prefix="//")
        a(f"    .{{ .name = {zig_string(vt['name'])}, .rva = {zig_hex(vt['rva'])}, "
          f".slots = &vt_{vname}_slots }},")
    a("};")
    a("")

    # --- global variables (name -> rva/size/alignment) ---
    a("/// Global variables of this build, keyed by name. Powers a")
    a("/// VariableInterface: `exists` is `get(name) != null`, `get_info` returns")
    a("/// size/alignment, and `locate` is `module_base + rva`. Iterable via")
    a("/// `.keys()`/`.values()` for enumeration.")
    a("const variables = VariableMap.initComptime(&.{")
    for g in variables:
        emit_doc(out, g.get("doc"), "        ", prefix="//")
        a(f'    .{{ {zig_string(g["name"])}, VariableInfo{{ .rva = {zig_hex(g["rva"])}, '
          f'.size = {zig_hex(g["size"])}, .alignment = {zig_hex(g["alignment"])} }} }},')
    a("});")
    a("")

    # --- struct layouts, field locators and per-struct field maps ---
    a("/// MSVC std::vector: three pointers (first, last, end-of-capacity).")
    a("/// Layout is build-specific, so it lives in this version's namespace.")
    a("pub const StdVector = extern struct {")
    a("    begin: ?*anyopaque = null,")
    a("    end: ?*anyopaque = null,")
    a("    capacity: ?*anyopaque = null,")
    a("};")
    a("")
    structs = emit_structs(targets, out, "    ")

    # --- type-erased field access: type name -> field map ---
    a("/// Type name -> field map for this build. A type or field absent from the")
    a("/// targets file is absent here, so an existence check is a plain map lookup.")
    a("pub const accessors = std.StaticStringMap(*const FieldMap).initComptime(&.{")
    for st in structs:
        a(f'    .{{ "{st["name"]}", &{snake(st["name"])}_fields }},')
    a("});")
    a("")

    # --- game ABI: opaque types ---
    for ty in targets.get("types", []):
        emit_doc(out, ty.get("_doc"), "    ")
        a(f"pub const {zig_ident(ty['name'])} = anyopaque;")
    if targets.get("types"):
        a("")

    # --- game ABI: enums ---
    for e in targets.get("enums", []):
        emit_doc(out, e.get("_doc"), "    ")
        a(f"pub const {zig_ident(e['name'])} = enum({e.get('base', 'c_uint')}) {{")
        for v in e["values"]:
            emit_doc(out, v.get("_doc"), "        ")
            a(f"    {v['name']} = {v['value']},")
        a("    _,")
        a("};")
    if targets.get("enums"):
        a("")

    # --- game ABI: hook signatures ---
    signatures: dict = targets.get("signatures", {})
    fn_names = set(targets["functions"].keys())
    relay_names = [n for n in signatures if n in fn_names]
    for name, sig in signatures.items():
        emit_doc(out, sig.get("_doc"), "    ")
        params = ", ".join(f"{an}: {at}" for an, at in sig["args"])
        a(f"pub const {fn_alias_name(name)} = fn ({params}) callconv(.c) {sig['ret']};")
    if signatures:
        a("")

    # --- relays ---
    for name in relay_names:
        sig = signatures[name]
        params = ", ".join(f"{an}: {at}" for an, at in sig["args"])
        values = ", ".join(an for an, _ in sig["args"])
        a("")
        emit_doc(out, sig.get("_doc"), "    ")
        a(f"fn {name}({params}) callconv(.c) {sig['ret']} {{")
        a(f'    return root.lib.callHooks("{name}", {fn_alias_name(name)}, .{{ {values} }});')
        a("}")
    a("")
    a("/// Hook name -> relay function pointer. The loader installs a detour for")
    a("/// every function named here that is present in this manifest.")
    a("pub const relays = std.StaticStringMap(*const anyopaque).initComptime(&.{")
    for name in relay_names:
        a(f'    .{{ "{name}", &{name} }},')
    a("});")
    a("")

    # --- manifest ---
    a("pub const manifest = Manifest{")
    a("    .build = build,")
    a(f"    .image_base = {zig_hex(hexint(targets['image_base']))},")
    a("    .functions = &functions,")
    a("    .vtables = &vtables,")
    a("    .variables = &variables,")
    a("    .relays = &relays,")
    a("    .accessors = &accessors,")
    a("};")
    out.append("};")
    out.append("")



def emit(
    targets_by_version: list[dict],
    source_ref: str,
    patch_size: int = DEFAULT_PATCH_SIZE,
) -> str:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    L: list[str] = []
    a = L.append

    a("//! AUTO-GENERATED FILE - DO NOT EDIT.")
    a("//!")
    a(f"//! Generated by {GENERATED_BY} from {source_ref}.")
    a("//!")
    a("//! Each supported game version is one namespace (`v<version>`) holding its")
    a("//! addresses, struct layouts and field maps, game ABI (types, signatures,")
    a("//! relays) and manifest. The runtime loader picks the matching manifest via")
    a("//! selectByHash. All derived values are precomputed.")
    a("//!")
    a("//! Field access is type-erased and per-version: `Manifest.accessors` maps a")
    a("//! type name to a `FieldMap` (field name -> FieldInfo{locate,size,alignment});")
    a("//! `FieldInfo.locate` returns the field's address in a live object. Struct")
    a("//! layouts (and `StdVector`) are build-specific and live inside the version")
    a("//! namespace; only the schema types stay at file scope.")
    a("//!")
    a("//! Layout: schema types at file scope, a `v<version>` namespace per build,")
    a("//! then the `manifests` array and the shared lookup helpers.")
    a("")
    a('const std = @import("std");')
    a("")
    # The module is a root-module import, so `root` is the loader root. Relay
    # bodies reach the loader through its re-exports (lib.callHooks, utils.*).
    a('const root = @import("root");')
    a("")

    a("/// Build identity of a game version.")
    a("pub const Build = struct {")
    a("    game: []const u8,")
    a("    version: []const u8,")
    a("    /// SHA-256 of the executable; the single build identifier.")
    a("    sha256: []const u8,")
    a("};")
    a("")
    a("/// How a displacement inside stolen instructions must be fixed up.")
    a("pub const RelocKind = enum(u8) {")
    a("    /// RIP-relative memory operand; field is a 4-byte displacement.")
    a("    rip_relative,")
    a("    /// Relative call/jmp immediate; field is 1 or 4 bytes.")
    a("    relative_branch,")
    a("};")
    a("")
    a("/// One displacement in the stolen bytes that must be relocated when the")
    a("/// instructions are copied into a trampoline.")
    a("///")
    a("/// Fix-up at runtime: the field sits at `original + r.offset`; rewrite its")
    a("/// `r.width`-byte little-endian value to")
    a("///     r.target_rva - (trampoline_rva + r.offset + r.width)")
    a("/// where `trampoline_rva` is the trampoline address relative to the module")
    a("/// base (it may be negative or large when the trampoline is outside the")
    a("/// image, so compute it in signed arithmetic).")
    a("pub const Reloc = struct {")
    a("    /// Offset of the displacement field within the stolen bytes.")
    a("    offset: u8,")
    a("    /// Field width in bytes (1 or 4).")
    a("    width: u8,")
    a("    kind: RelocKind,")
    a("    /// Target address in the original image, as an RVA (already resolved).")
    a("    target_rva: usize,")
    a("};")
    a("")
    a("/// A decoded instruction in the stolen block (informational).")
    a("pub const Instruction = struct {")
    a("    /// Offset within the stolen bytes.")
    a("    offset: u8,")
    a("    /// Instruction length in bytes.")
    a("    len: u8,")
    a("    /// Disassembly text, e.g. \"mov rax, rsp\".")
    a("    text: []const u8,")
    a("};")
    a("")
    a("/// A ready-to-use inline-patch plan for one function.")
    a("pub const Patch = struct {")
    a("    /// Leading bytes to overwrite (whole instructions), >= requested size.")
    a("    len: u8,")
    a("    /// Original bytes of `len`; copy these into the trampoline.")
    a("    original: []const u8,")
    a("    /// Address to resume at after the stolen block (function rva + len).")
    a("    resume_rva: usize,")
    a("    /// True when every stolen instruction can be relocated safely.")
    a("    relocatable: bool,")
    a("    /// Displacements to fix up in the copied instructions.")
    a("    relocs: []const Reloc,")
    a("    /// Decoded stolen instructions.")
    a("    instructions: []const Instruction,")
    a("};")
    a("")
    a("/// A hookable function. All addresses are RVAs; resolve with")
    a("/// `module_base + f.rva` at runtime.")
    a("pub const Function = struct {")
    a("    /// Stable name from the targets file.")
    a("    name: []const u8,")
    a("    /// Image-relative virtual address.")
    a("    rva: usize,")
    a("    /// Original prologue bytes (build fingerprint).")
    a("    prologue: []const u8,")
    a("    /// Inline-patch plan (steal bytes + relocations).")
    a("    patch: Patch,")
    a("};")
    a("")
    a("/// One vtable slot. The slot itself is at `module_base + vtable_rva +")
    a("/// offset`; its current value points at `module_base + target_rva`.")
    a("pub const VTableSlot = struct {")
    a("    offset: usize,")
    a("    /// Target function name, or \"\" when only an RVA is known.")
    a("    name: []const u8,")
    a("    target_rva: usize,")
    a("};")
    a("")
    a("/// A virtual table and its slots (RVA only).")
    a("pub const VTable = struct {")
    a("    name: []const u8,")
    a("    rva: usize,")
    a("    slots: []const VTableSlot,")
    a("};")
    a("")
    a("/// A global variable in the game module: where it lives (`rva`), and the")
    a("/// size and natural alignment of the value stored there. Resolve the")
    a("/// variable's address with `module_base + rva`.")
    a("pub const VariableInfo = struct {")
    a("    /// Image-relative virtual address; resolve with `module_base + rva`.")
    a("    rva: usize,")
    a("    /// Width of the variable in bytes.")
    a("    size: usize,")
    a("    /// Natural alignment of the variable in bytes.")
    a("    alignment: usize,")
    a("};")
    a("")
    a("/// Variable name -> info for one build. The global-variable analogue of")
    a("/// `FieldMap`, and the backing store for a VariableInterface.")
    a("pub const VariableMap = std.StaticStringMap(VariableInfo);")
    a("")
    a("/// Locates a field inside a live object, returning its address (read/write")
    a("/// through the pointer), or null when this build has no such field.")
    a("pub const FieldLocator = *const fn (obj: *anyopaque) ?*anyopaque;")
    a("")
    a("/// One struct field: how to find it and how large/aligned it is. `size` and")
    a("/// `alignment` describe the field storage (e.g. `str` buffer length), not")
    a("/// the pointee: the caller still needs the per-version layout to read it.")
    a("pub const FieldInfo = struct {")
    a("    locate: FieldLocator,")
    a("    size: usize,")
    a("    alignment: usize,")
    a("};")
    a("")
    a("/// Field name -> info for one struct type.")
    a("pub const FieldMap = std.StaticStringMap(FieldInfo);")
    a("")
    a("/// Everything needed to use one game version. Runtime code should only use")
    a("/// the RVA fields; `image_base` is informational (sanity checks / docs).")
    a("pub const Manifest = struct {")
    a("    build: Build,")
    a("    image_base: usize,")
    a("    functions: []const Function,")
    a("    vtables: []const VTable,")
    a("    /// Global variable name -> rva/size/alignment for this version.")
    a("    variables: *const VariableMap,")
    a("    /// Hook name -> relay function pointer for this version.")
    a("    relays: *const std.StaticStringMap(*const anyopaque),")
    a("    /// Type name -> field map for this version (type-erased field access).")
    a("    accessors: *const std.StaticStringMap(*const FieldMap),")
    a("};")
    a("")

    for targets in targets_by_version:
        emit_version(targets, L, md, patch_size)

    a("/// Every embedded game version. Select one with selectByHash.")
    a("pub const manifests = [_]*const Manifest{")
    for targets in targets_by_version:
        a(f"    &v{version_ident(str(targets['version']))}.manifest,")
    a("};")
    a("")

    # ---- selection -------------------------------------------------------- #
    a("/// Pick a manifest by SHA-256 (case-insensitive).")
    a("pub inline fn selectByHash(sha256: []const u8) ?*const Manifest {")
    a("    for (manifests) |m| {")
    a("        if (std.ascii.eqlIgnoreCase(sha256, m.build.sha256)) return m;")
    a("    }")
    a("    return null;")
    a("}")
    a("")

    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Zig manifest module")
    parser.add_argument("output", help="path to the .zig file to write")
    parser.add_argument(
        "--targets-dir",
        default=str(forts.TARGETS_DIR),
        help="directory of <version>.json files (default: tools/frida/targets)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="VERSION",
        help="include only this version (repeatable); default: all",
    )
    parser.add_argument(
        "--patch-size",
        type=int,
        default=DEFAULT_PATCH_SIZE,
        metavar="BYTES",
        help="detour length to cover: 5 for a rel32 jump, 14 for an abs jump "
        f"(default: {DEFAULT_PATCH_SIZE})",
    )
    args = parser.parse_args(argv)

    targets_dir = Path(args.targets_dir)
    files = forts.list_targets(targets_dir)
    if args.only:
        wanted = set(args.only)
        files = [
            f
            for f in files
            if f.stem in wanted or f.name in wanted
        ]
        missing = wanted - {f.stem for f in files} - {f.name for f in files}
        if missing:
            raise SystemExit(
                f"unknown version(s) {sorted(missing)}; "
                f"available: {[f.stem for f in forts.list_targets(targets_dir)]}"
            )
    if not files:
        raise SystemExit(f"no targets files found in {targets_dir}")

    targets_by_version = [load_targets(f) for f in files]
    # Deterministic output ordering.
    targets_by_version.sort(key=lambda t: str(t["version"]))

    source_ref = display_path(targets_dir)
    text = emit(targets_by_version, source_ref, args.patch_size)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    versions = ", ".join(str(t["version"]) for t in targets_by_version)
    print(f"wrote {out} ({len(text)} bytes, {text.count(chr(10))} lines) for [{versions}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

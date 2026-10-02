"""Shared helpers for the Forts RE pipeline.

Everything here is read-only with respect to the game: PE parsing, target
loading and result formatting. Frida is imported lazily so that the static
checks work even without a working Frida runtime.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
# One targets file per game version, e.g. tools/frida/targets/1.38.2-r22447.json.
TARGETS_DIR = HERE / "targets"


class CheckError(Exception):
    pass


def hexint(value: int | str) -> int:
    return value if isinstance(value, int) else int(value, 16)


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int


class PE:
    """Minimal read-only PE64 reader (enough to map RVA -> file offset)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:2] != b"MZ":
            raise CheckError(f"{self.path} is not a PE file (bad MZ)")
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            raise CheckError(f"{self.path} has a bad PE signature")
        coff = e_lfanew + 4
        nsec = struct.unpack_from("<H", self.data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", self.data, coff + 16)[0]
        opt = coff + 20
        self.magic = struct.unpack_from("<H", self.data, opt)[0]
        self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
        self.sections: list[Section] = []
        sect = opt + opt_size
        for i in range(nsec):
            o = sect + i * 40
            name = self.data[o : o + 8].rstrip(b"\0").decode("latin1")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", self.data, o + 8)
            self.sections.append(Section(name, va, vsize, raw_ptr, raw_size))

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s.raw_ptr + (rva - s.va)
        return None

    def read(self, rva: int, size: int) -> bytes | None:
        off = self.rva_to_off(rva)
        if off is None:
            return None
        chunk = self.data[off : off + size]
        return chunk if len(chunk) == size else None

    def read_u64(self, rva: int) -> int | None:
        raw = self.read(rva, 8)
        return struct.unpack("<Q", raw)[0] if raw else None

    def read_cstr(self, rva: int, max_len: int = 256) -> str | None:
        off = self.rva_to_off(rva)
        if off is None:
            return None
        end = self.data.find(b"\0", off, off + max_len)
        if end < 0:
            return None
        return self.data[off:end].decode("latin1")

    def read_wcstr(self, rva: int, max_len: int = 512) -> str | None:
        """Read a NUL-terminated UTF-16LE wide (wchar_t) string."""
        off = self.rva_to_off(rva)
        if off is None:
            return None
        limit = off + max_len
        end = off
        while end + 1 < limit and self.data[end : end + 2] != b"\0\0":
            end += 2
        return self.data[off:end].decode("utf-16-le", "replace")

    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def list_targets(directory: Path = TARGETS_DIR) -> list[Path]:
    """All known version files, sorted. A legacy single targets.json also works."""
    if directory.is_dir():
        return sorted(directory.glob("*.json"))
    if directory.is_file():
        return [directory]
    return []


def resolve_targets(spec: str | Path | None, directory: Path = TARGETS_DIR) -> Path:
    """Resolve --targets, which may be a version id, a file, or a directory.

    - "1.38.2-r22447"      -> <directory>/1.38.2-r22447.json
    - "1.38.2-r22447.json" -> <directory>/1.38.2-r22447.json
    - a path        -> used as-is if it is a file
    - a directory   -> must contain exactly one version file
    - None          -> the only version file, if there is exactly one
    """
    if spec:
        p = Path(spec)
        if p.is_file():
            return p
        if p.is_dir():
            files = list_targets(p)
            if len(files) == 1:
                return files[0]
            raise CheckError(
                f"{p} contains {len(files)} version files; pick one explicitly"
            )
        for candidate in (directory / f"{spec}.json", directory / spec):
            if candidate.is_file():
                return candidate
        raise CheckError(
            f"targets {spec!r} not found in {directory}; "
            f"available: {[f.stem for f in list_targets(directory)]}"
        )

    files = list_targets(directory)
    if not files:
        raise CheckError(f"no game-version targets found in {directory}")
    if len(files) == 1:
        return files[0]
    raise CheckError(
        "several game versions are available; pass --targets <version|path>. "
        f"available: {[f.stem for f in files]}"
    )


def select_targets_for_pe(pe: "PE", spec: str | Path | None) -> Path:
    """Like resolve_targets, but with no explicit spec it auto-matches the exe.

    When several version files exist, the one whose sha256 matches the
    provided executable is chosen. This makes "which build is installed?"
    a one-liner even with many supported versions.
    """
    if spec:
        return resolve_targets(spec)
    files = list_targets()
    if len(files) <= 1:
        return resolve_targets(None)
    digest = pe.sha256().lower()
    matches = [
        f for f in files if str(load_targets(f).get("sha256", "")).lower() == digest
    ]
    if len(matches) == 1:
        return matches[0]
    available = ", ".join(f"{f.stem}" for f in files)
    if not matches:
        raise CheckError(
            f"no targets file matches {pe.path}; available versions: {available}"
        )
    raise CheckError(
        f"{pe.path} matches several version files ({[m.stem for m in matches]})"
    )


def load_targets(path: Path | str | None = None) -> dict:
    if path is None:
        path = resolve_targets(None)
    # utf-8-sig tolerates a BOM that Windows editors may add.
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def resolve_exe(explicit: str | Path | None) -> Path:
    """The game path is always supplied explicitly, never searched for."""
    if not explicit:
        raise CheckError("no game path given; pass --exe <path to Forts.exe>")
    p = Path(explicit)
    if not p.is_file():
        raise CheckError(f"--exe not found: {p}")
    return p


@dataclass
class Check:
    kind: str
    name: str
    ok: bool
    detail: str = ""
    # Advisory checks are informative and never fail the run (e.g. tick
    # counters while the game is still in the main menu).
    advisory: bool = False


def print_report(checks: list[Check], title: str = "checks") -> None:
    width = max((len(c.name) for c in checks), default=0)
    required = [c for c in checks if not c.advisory]
    passed = sum(1 for c in required if c.ok)
    print(f"\n=== {title} ===")
    for c in checks:
        if c.ok:
            mark = "OK  "
        elif c.advisory:
            mark = "WARN"
        else:
            mark = "FAIL"
        print(f"  [{mark}] {c.kind:<8} {c.name:<{width}}  {c.detail}")
    print(f"  -> {passed}/{len(required)} required checks passed")


def required_passed(checks: list[Check]) -> bool:
    return all(c.ok for c in checks if not c.advisory)


def prefix_bytes(value: str) -> list[int]:
    return [int(b, 16) for b in value.split()]


# JSON struct field type vocabulary (see tools/frida/AGENTS.md, "Struct field
# types"), mapped to (size, alignment) in bytes. Every field is an inline member
# of the object at its declared offset -- none is a pointer unless it says so:
#
#   u8/i8/u16/i16/u32/i32/u64/i64  little-endian integer of that width
#   f32/f64                        IEEE-754 float/double
#   bool                           C++ bool: 1 byte, non-zero == true
#   ptr                            64-bit pointer to an opaque object; may be null
#   std_vector                     MSVC std::vector<T> control block:
#                                  {first, last, end-of-capacity}, 24 bytes
#
# "str" is deliberately absent: it is an inline NUL-terminated char buffer whose
# size is the JSON "count" (bytes), not a fixed scalar. Use field_extent() to
# resolve it, including the count-inference rules. Reading is strnlen(buf,count);
# writing is at most count-1 bytes plus a trailing NUL.
TYPE_SIZE_ALIGN = {
    "u8": (1, 1),
    "i8": (1, 1),
    "u16": (2, 2),
    "i16": (2, 2),
    "u32": (4, 4),
    "i32": (4, 4),
    "u64": (8, 8),
    "i64": (8, 8),
    "f32": (4, 4),
    "f64": (8, 8),
    "bool": (1, 1),
    "ptr": (8, 8),
    "std_vector": (24, 8),
}


def field_extent(field: dict) -> tuple[int | None, int]:
    """(size, alignment) of one struct field; size is None when unknown.

    A ``str`` is an inline NUL-terminated ``char[count]`` and reports
    ``(count, 1)``. Unlike ``gen_zig.field_layout`` this does not infer a missing
    ``count`` from the neighbouring offsets, so an omitted ``count`` yields
    ``(None, 1)`` and the caller must skip size-based checks. Set ``count``
    explicitly to make the field verifiable.
    """
    ftype = field["type"].lower()
    if ftype == "str":
        count = field.get("count")
        return (int(count) if count is not None else None, 1)
    return TYPE_SIZE_ALIGN.get(ftype, (None, 1))


def resolve_struct_layouts(targets: dict) -> dict[str, dict]:
    """Resolve every ``targets['structs']`` group to a concrete layout.

    Returns ``{group: {group, name, declared_size, emitted_size, align, doc,
    fields, problems}}`` where each resolved field carries ``name``, ``offset``,
    ``type``, ``count``, ``ref`` (for ``embedded``), ``ref_name`` (the referenced
    group's C++ name), ``doc`` and the concrete ``size``/``align``.

    ``embedded`` fields are inline sub-objects: the field value is the referenced
    struct laid out at that offset (its first 8 bytes are typically a vptr), not a
    pointer. This is the one place that knows the whole vocabulary (including
    nesting), shared by ``gen_zig.py`` (codegen) and ``verify.py`` (checks).

    Structurally fatal problems (a cycle, or an ``embedded`` field naming an
    undefined group) raise ``SystemExit``; per-field layout problems (overlap,
    misalignment, exceeding the declared size) are collected in ``problems`` so a
    caller can fail the build or just report them.
    """
    raw = targets.get("structs", {})
    norm: dict[str, dict] = {}
    for group, s in raw.items():
        size = hexint(s["size"])
        src = s["fields"]
        fields = []
        for i, f in enumerate(src):
            off = hexint(f["offset"])
            ftype = f["type"].lower()
            count = None
            if ftype == "str":
                if "count" in f:
                    count = int(f["count"])
                elif i + 1 < len(src):
                    count = hexint(src[i + 1]["offset"]) - off
                else:
                    count = size - off
            fields.append(
                {
                    "name": f["name"],
                    "offset": off,
                    "type": ftype,
                    "count": count,
                    "ref": f.get("struct"),
                    "doc": f.get("_doc"),
                }
            )
        norm[group] = {
            "group": group,
            "name": s.get("name", group),
            "declared_size": size,
            "doc": s.get("_doc"),
            "fields": fields,
        }

    resolved: dict[str, dict] = {}

    def resolve(group: str, stack: list[str]) -> dict:
        if group in resolved:
            return resolved[group]
        if group in stack:
            raise SystemExit(
                "embedded struct cycle: " + " -> ".join(stack + [group])
            )
        if group not in norm:
            raise SystemExit(
                f"embedded struct {group!r} is not defined in 'structs'"
            )
        st = norm[group]
        fields = []
        problems: list[str] = []
        cur = 0
        max_align = 1
        for f in st["fields"]:
            off = f["offset"]
            ref_name = None
            if f["type"] == "embedded":
                child = resolve(f["ref"], stack + [group])
                fsize = child["emitted_size"]
                falign = child["align"]
                ref_name = child["name"]
            elif f["type"] == "str":
                fsize = f["count"]
                falign = 1
            else:
                ext = TYPE_SIZE_ALIGN.get(f["type"])
                fsize, falign = ext if ext is not None else (None, 1)
            if off < cur:
                problems.append(f"{f['name']}@{off:#x} overlaps previous field")
            if off % falign != 0:
                problems.append(f"{f['name']}@{off:#x} not {falign}-aligned")
            fields.append({**f, "size": fsize, "align": falign, "ref_name": ref_name})
            cur = off + (fsize if fsize is not None else 1)
            max_align = max(max_align, falign)
        emitted = (cur + max_align - 1) // max_align * max_align
        if cur > st["declared_size"]:
            problems.append(
                f"fields end at {cur:#x} beyond size {st['declared_size']:#x}"
            )
        res = {
            "group": group,
            "name": st["name"],
            "declared_size": st["declared_size"],
            "emitted_size": emitted,
            "align": max_align,
            "doc": st["doc"],
            "fields": fields,
            "problems": problems,
        }
        resolved[group] = res
        return res

    for g in norm:
        resolve(g, [])
    return {g: resolved[g] for g in norm}


def prologue_hex(value: str) -> str:
    return value.replace(" ", "").lower()


def payload_for_agent(targets: dict) -> dict:
    """Convert targets.json into an int-only payload for the Frida agent."""
    functions = {}
    for name, f in targets["functions"].items():
        functions[name] = {
            "rva": hexint(f["rva"]),
            "prologue": prefix_bytes(f["prologue"]) if f.get("prologue") else [],
        }

    vtables = {}
    for name, v in targets["vtables"].items():
        slots = []
        for slot in v["slots"]:
            if "function" in slot:
                target_rva = hexint(targets["functions"][slot["function"]]["rva"])
            else:
                target_rva = hexint(slot["rva"])
            slots.append({"offset": hexint(slot["offset"]), "rva": target_rva})
        vtables[name] = {"rva": hexint(v["rva"]), "slots": slots}

    strings = {
        name: {"rva": hexint(s["rva"]), "text": s["text"], "wide": bool(s.get("wide"))}
        for name, s in targets["strings"].items()
    }
    globals_ = {
        name: {"rva": hexint(g["rva"])} for name, g in targets["globals"].items()
    }
    structs = {
        group: {
            "name": s.get("name", group),
            "size": hexint(s["size"]),
            "fields": [
                {
                    "name": f["name"],
                    "offset": hexint(f["offset"]),
                    "type": f["type"].lower(),
                }
                for f in s["fields"]
            ],
        }
        for group, s in targets.get("structs", {}).items()
    }

    return {
        "module": targets["module"],
        "image_base": hexint(targets["image_base"]),
        "functions": functions,
        "vtables": vtables,
        "strings": strings,
        "globals": globals_,
        "structs": structs,
    }

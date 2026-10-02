# tools/frida — Forts version/address verification pipeline

A small, self-contained pipeline that answers one question fast: **do the
addresses in `targets/<version>.json` still describe the installed `Forts.exe`?**

It is read-only: the offline stage only reads the `.exe`; the live stage attaches
Frida to a running/spawned game, verifies addresses in memory, counts real tick
calls, and (when it spawned the game itself) closes it afterwards.

## Files

| File                     | Purpose                                                                                                                                                                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `targets/<version>.json` | One source-of-truth file **per game version**: sha256, every RVA, 32-byte prologue fingerprint, vtable slot, anchor string, global, and per-struct field layouts (turned into per-version field maps by `gen_zig.py`). Add a file to support a new version.                     |
| `forts.py`               | Shared helpers: PE reader (RVA→file offset), version resolution/auto-match, `Check`/report types.                                                                                                                                                                               |
| `verify.py`              | The pipeline CLI (offline + live). Auto-selects the targets file matching the exe.                                                                                                                                                                                              |
| `gen_zig.py`             | Emits a Zig manifest module embedding **all** versions plus runtime selection helpers and type-erased, per-version struct field maps.                                                                                                                                           |
| `agent_probe.js`         | Frida agent that resolves prologues / vtable slots / strings / globals.                                                                                                                                                                                                         |
| `agent_tick.js`          | Frida agent that hooks the sim tick/dispatch plus the app frame (`FortsShell::Execute`), the renderer present (`Renderer_Present`) and the per-frame input poll (`Input_Update`), and samples state.                                                                            |
| `debugpanel.py`          | Attaches to a running game and forces the `DebugPanel` overlay on (writes `PlayerController+0x47=1` every frame); Ctrl-C to detach.                                                                                                                                             |
| `scripts.py`             | Attaches and lists the loaded Lua scripts (`ScriptList` → `ScriptRecord`): active flag, `lua_State*`, path, short name, global-count. Read-only.                                                                                                                                |
| `entities.py`            | Attaches to a running match and reads the live simulation: node list (id/team/mass/drag/position/velocity/structure), the device list, the resolved `Physics.*` parameters and the TerrainManager gravity/air-drag. Also toggles the game's own per-tick world-dump. Read-only. |

## Usage

```sh
# Offline: hashes, prologues, strings, vtables, globals — no game running.
uv run python tools/frida/verify.py --exe "C:\path\to\Forts.exe"

# Live: attach to a running game and verify everything in memory.
uv run python tools/frida/verify.py --exe "C:\path\to\Forts.exe" --live

# Live + count tick/dispatch calls for 30 s (spawns the game, then closes it).
uv run python tools/frida/verify.py --exe "C:\path\to\Forts.exe" --spawn --hook 30
```

`--exe` is always required; there is no path guessing. Put the path in a shell
alias or pass it explicitly. The repo keeps no machine-specific paths anywhere;
the VS Code launch config likewise reads `FORTS_EXE` / `FORTS_EXE_DIR` from the
environment.

`--targets` selects the version: a version id (`1.38.2-r22447`), a path to a JSON, or
omitted to auto-match the exe by sha256 across `targets/`.

Flags: `--pid N` attach to a specific process, `--keep-alive` leave a spawned
game running, `--json` machine-readable output.

Exit code is `0` only when every required check passes.

## Generating the Zig manifest module

```sh
# build.zig runs this automatically and imports the output as root.manifests
# (an anonymous module `manifests.zig`); there is no checked-in copy. Run it
# by hand only to inspect the output or to target a file explicitly.
uv run python tools/frida/gen_zig.py out.zig

# Restrict to specific versions / a different targets directory.
uv run python tools/frida/gen_zig.py out.zig --only 1.38.2-r22447
uv run python tools/frida/gen_zig.py out.zig --targets-dir path/to/targets

# Size of the patch block: 5 (rel32 detour, default) or 14 (abs64 detour).
uv run python tools/frida/gen_zig.py out.zig --patch-size 14
```

Generation uses `capstone` (a normal project dependency) to decode prologues and
bake in relocation tables. Capstone is only needed to _generate_; the runtime
loader needs nothing beyond the emitted data.

The output is data-only: one `Manifest` per version plus the `manifests`
array and a single `selectByHash(hash)` selector. The loader consumes it
directly (`build.zig` generates it and imports it as `root.manifests`); the
per-version namespace holds three target kinds and the ABI:

| JSON key                                     | Manifest field                | Shape                                                                 | How a consumer uses it                                                                                                                                           |
| -------------------------------------------- | ----------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `functions` (free functions **and** methods) | `functions` (array, iterated) | `Function{ name, rva, prologue, patch }`                              | The loader walks it to install detours; `manifest.relays` maps a name to that function's relay.                                                                  |
| `globals` (global variables)                 | `variables` (map)             | `VariableMap = StaticStringMap(VariableInfo{ rva, size, alignment })` | `variables.get(name)` -> `locate = module_base + rva`; `get_info` = size/alignment; absent = not supported. This is the global-variable analogue of `accessors`. |
| `vtables` (methods)                          | `vtables` (array, iterated)   | `VTable{ name, rva, slots[] }`                                        | Slot cell is at `module_base + vt.rva + slot.offset`; its value points at `module_base + slot.target_rva`.                                                       |

It also generates, **per version**, a struct field map keyed by type and field
name. Each entry is a `FieldInfo { locate, size, alignment }` where `locate` is a
function returning the address of the field in a live object (or null when the
build lacks the field); a field absent from a version's JSON is absent from its
map, so existence checks reduce to a map lookup. The selected `Manifest` exposes
this as `Manifest.accessors` (`type name -> *const FieldMap`), which backs a
FieldInterface (`has_field`/`get_info`/`locate`). Because struct
layouts are build-specific, `StdVector` and the private layouts (guarded by
`@offsetOf` / `@sizeOf` asserts so a bad offset fails the build) live inside the
version namespace, not at file scope. There is no typed `get_<field>`/`set_<field>`
ABI: callers read/write through the pointer from `locate` and need the layout to
interpret it.
It contains no game or library logic. The runtime loader picks the matching
manifest by sha256 and uses its addresses.

**All addresses are RVAs.** The generator never emits absolute VAs, so the
runtime has exactly one formula — `module_base + rva`. `Manifest.image_base` is
informational only (docs / sanity checks); `verify.py` uses the same RVA data to
cross-check the file.

### Descriptor schema (the targets JSON)

The targets file is the single documented source of truth. Besides the address
data it declares the **ABI** the generator compiles into Zig:

| Key          | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `_doc`       | Human-readable doc for the node it sits on (top level, a function, a field, a vtable slot, a type, a signature, an enum value). Emitted as a Zig `///` doc comment on the corresponding declaration, or a `//` comment on data-array entries.                                                                                                                                                                                                                                                                                                    |
| `types`      | Opaque game pointer types (`World`, `WorldSim`, ...) emitted into each version's generated namespace.                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `enums`      | Non-exhaustive enums (`ObjectFactoryType`) emitted into the namespace; each value carries its own `_doc`.                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `signatures` | Hook signatures keyed by function name: `ret`, ordered `args` as `[name, type]`, and `_doc`. `gen_zig.py` derives each `Fn<Name>` alias and, per version, a relay function that forwards to the loader (`root.lib.callHooks`) plus the version's `manifest.relays` map. The hooked set is exactly the signatures that also appear in `functions`; anything else is left unpatched.                                                                                                                                                               |
| `structs`    | C++ object layouts keyed by group (`world`, `sim`, ...): `{ "name": "<C++ type>", "size": <hex>, "fields": [ { "name", "offset": <hex>, "type", ["count"], ["struct"], "_doc" } ] }`. `type` may be `embedded` (an inline sub-object), which additionally needs `"struct": "<group>"`. `gen_zig.py` emits an `extern struct` layout (`@offsetOf`/`@sizeOf` asserts) and a per-field locator into the version's `FieldMap`; `verify.py` checks bounds, alignment and non-overlap. `offset` is always a hex string of bytes from the object start. |
| `globals`    | Global variables keyed by name: `{ "rva": <hex>, "type": <field type>, ["count"], "_doc" }`. `type` uses the **same vocabulary as struct fields** (`ptr`, `bool`, the scalars, `str` with `count`) and fixes the emitted `VariableInfo.size`/`alignment`; it is required. `gen_zig.py` emits `Manifest.variables` (`name -> VariableInfo{ rva, size, alignment }`), the backing store for a VariableInterface.                                                                                                                                   |

Types referenced from a signature are written bare (`*World`, `?*MatchSetup`).

#### Struct field types (`structs[].fields[].type`)

Every field is an **inline** member of the object at its declared `offset`; none
of them is a pointer unless the type says so. The complete vocabulary, with the
Zig layout `gen_zig.py` emits for it:

| `type`       | Meaning                                                                                                                                                               | Zig layout                  | Size                 | Align         |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | -------------------- | ------------- |
| `u8`, `i8`   | unsigned / signed 8-bit integer                                                                                                                                       | `u8` / `i8`                 | 1                    | 1             |
| `u16`, `i16` | unsigned / signed 16-bit integer                                                                                                                                      | `u16` / `i16`               | 2                    | 2             |
| `u32`, `i32` | unsigned / signed 32-bit integer                                                                                                                                      | `u32` / `i32`               | 4                    | 4             |
| `u64`, `i64` | unsigned / signed 64-bit integer                                                                                                                                      | `u64` / `i64`               | 8                    | 8             |
| `f32`        | IEEE-754 single-precision float                                                                                                                                       | `f32`                       | 4                    | 4             |
| `f64`        | IEEE-754 double-precision float                                                                                                                                       | `f64`                       | 8                    | 8             |
| `bool`       | C++ `bool`: 1 byte, **non-zero means true**                                                                                                                           | `u8` (read as `!= 0`)       | 1                    | 1             |
| `ptr`        | 64-bit pointer to an opaque game object; may be null                                                                                                                  | `?*anyopaque`               | 8                    | 8             |
| `str`        | **Inline fixed-size NUL-terminated char buffer**, i.e. a C `char[N]` embedded in the object. **Not** `std::string`, **not** a pointer, **not** heap-allocated.        | `[count]u8`                 | `count`              | 1             |
| `std_vector` | MSVC `std::vector<T>` control block: three pointers (first, last, end-of-capacity)                                                                                    | `StdVector` (version-local) | 24                   | 8             |
| `embedded`   | An **inline sub-object**: the referenced struct laid out at this offset, **not** a pointer. Its first 8 bytes are usually a vptr. JSON carries `"struct": "<group>"`. | `<Ref>Layout`               | child `emitted_size` | child `align` |

Rules:

- All integers and floats are **little-endian**, native x64; no packing beyond
  the declared alignment.
- `count` is **only** valid for `str` and is the buffer length in **bytes**
  (`"count": 255` -> `char[255]`, so at most 254 characters + NUL). It is
  optional: when omitted, `gen_zig.py` infers it as the next field's `offset`
  minus this field's `offset`, or `size - offset` when the field is last.
  `verify.py` cannot infer it and skips the overlap check for a `str` without
  `count`. **Set it explicitly.**
- Reading a `str` means bytes up to the first NUL, bounded by `count`
  (equivalent to `strnlen(buf, count)`); there is no separate length. Writing it
  means copying at most `count - 1` bytes and writing a trailing NUL.
- `embedded` requires `"struct": "<group>"`, naming another group in `structs`.
  That group is emitted as its own type and field map, so a consumer walks in
  with two lookups: locate the parent field, then use the child type's field map
  on the returned pointer (e.g. `WorldSim.clock` -> `SoftwareTimeKeeper.time`).
  The child must fit inside the parent (`offset + child emitted_size <= size`);
  a self-referential or cyclic `embedded` chain is rejected.
- The generated `FieldInfo.size` equals `count` for a `str`, `24` for a
  `std_vector`, the child `emitted_size` for an `embedded`, and the scalar width
  otherwise; `FieldInfo.alignment` is the `Align` column. `std_vector` element
  type and pointee layouts are deliberately **not** described: a mod that walks
  one must know the game's `T` for that build.

**Where to put a vptr.** An `embedded` field's own `vptr` is a normal `ptr` field
in the child struct (offset `0x0`); `embedded` only means the bytes live inside
the parent. Do **not** model an inline object as a `ptr` in the parent — that is
the bug the type exists to prevent.

**Generated layout.** The file has three parts, in order:

1. schema types at file scope (`Build`, `Function`, `Manifest`,
   `FieldLocator`/`FieldInfo`/`FieldMap`, `VariableInfo`/`VariableMap`, ...);
2. one namespace per version, `pub const v<version> = struct { ... }` (dots and
   dashes become underscores: `v1_38_2_r22447`), containing that build's
   `build`, `functions`, `vtables`, `variables`, `StdVector`, struct layouts +
   field maps, the `accessors` type map, the game ABI (`Engine`/`World`/...,
   `ObjectFactoryType`, all `Fn*` aliases, the relay functions and `relays`
   map), and its `manifest`;
3. `manifests` (the `&v<version>.manifest` array) plus the shared `inline`
   helper `selectByHash`.

Everything per-version lives inside its namespace, so `src/game.zig` and
`src/relays.zig` are gone — all per-version ABI and relay code is generated.

### Inline-patch data

Every `Function` carries a `Patch` with everything needed to install a detour,
so the loader never has to disassemble at runtime:

- `len` / `original` — whole instructions to overwrite (>= `--patch-size`,
  default 5) and their bytes, to copy into a trampoline;
- `resume_rva` — where execution continues after the stolen block (`rva + len`,
  resolve with `addr`);
- `relocatable` — false if the block holds a rel8 branch or was too short;
- `relocs` — relative displacements to fix up when relocating the stolen bytes.
  For each, write the field at `original + reloc.offset` (width `reloc.width`)
  as `reloc.target_rva - (trampoline_rva + reloc.offset + reloc.width)`, where
  `trampoline_rva = trampoline_addr - module_base` (signed; it is large or
  negative when the trampoline lives outside the image). The target is resolved
  here (RIP-relative operands and `call`/`jmp rel32`), so no runtime decoding is
  required;
- `instructions` — the decoded stolen instructions (informational).

`--patch-size 14` produces a block long enough for an absolute 64-bit jump.
Regenerating is deterministic; the exe is never read at generation time (the
32-byte prologue fingerprints in the targets file are the byte source).

**Choosing the size:** `5` is the intended default for a MinHook-style loader
that allocates its trampoline within ±2 GB of the target (a 5-byte `E9 rel32`
detour then always fits). On 1.38.2-r22447 every function needs 5–7 stolen bytes and
**zero** relocations at size 5; at size 14 the block grows to 14–20 bytes and two
functions gain a RIP-relative relocation. Use `14` only when the trampoline
cannot be placed near the target (it works from any distance but touches more
bytes). For purely vtable-dispatched methods, swapping the vtable slot
(`module_base + vtables[i].rva + slot.offset`) is an even lighter
alternative.

### Notes on the live stage

- If the game is in the **main menu**, `World` does not exist yet, so the tick
  never runs. The hook stage reports a `WARN` (advisory) instead of failing, and
  `World_ptr set (match active)` tells you whether a real match was seen.
- **Enter an actual match** to exercise the tick. Storing the game on a fast SSD
  and starting a match quickly lets a short `--hook` window catch it; otherwise
  raise the seconds.
- `Tick` fires once per rendered frame; `Dispatch` fires once per fixed physics
  step (only once Lua scripts are loaded), so it stays advisory.
- The **app frame** (`FortsShell::Execute`) and the per-frame **input poll**
  (`Input_Update`) run in _every_ state, so they are already exercised in the
  menu; `Renderer_Present` runs whenever a frame is actually swapped. That is
  why `--hook` reports `app frame`, `input` and `renderer present` counts even
  without a match, and only the tick/`World_ptr` checks need one.

### Direct launch hands off to Steam

`Forts.exe` started as a bare process (including `verify.py --spawn`) exits
almost immediately with code **53**: the Steamworks restart check asks the Steam
client to relaunch it. To run the live stage, start the game through Steam
(`steam://rungameid/410900`) and attach with `--hook`/`--live` **without**
`--spawn`; the attach path never kills the game. The same single-instance guard
(`FindWindowW("Forts","Forts")`) makes a second spawned copy exit at once, so
make sure no other instance is running before spawning.

## Updating / adding a game version

1. Copy `targets/1.38.2-r22447.json` to `targets/<new-version>.json`, then set `game`,
   `version` and `sha256`.
2. Re-run the re-location order below (string anchors are stable across builds;
   raw addresses are not) and replace the affected RVAs (and `prologue`
   fingerprints) in the new file. Keep each `prologue` at 32 bytes — it doubles
   as the byte source for the inline-patch plan.
3. Run `verify.py --exe <path> --targets <new-version>`. Every required check
   must pass before trusting the addresses; the failures point at what moved.
4. Regenerate `gen_zig.py`: the new version is embedded automatically and the
   loader can select it at runtime.

## Re-locating addresses on a new version

All raw addresses move between builds; the string anchors in `targets/*.json`
under `strings` are stable and are the fastest way back. Anchor every search on a
string, then follow xrefs and vtables:

1. **Lua binding cluster** — search strings for exported API names
   (`GetConstant`, `EnableAI`, …). The pair-of-strings table
   (`_Name` / `Name`) sits around `0x1406F3000`; xref a name to reach its C++
   implementation.
2. **Script layer** — xref `"SystemUpdate"` / `"Update"` → `Scripts_Update_Dispatch`;
   xref `"OnUpdate"` → `Scripts_OnUpdate_Event`; xref
   `"%d EXECTIME UpdateScript %s %f"` → `Scripts_Update_Dispatch`.
3. **The tick** — the caller of `Scripts_Update_Dispatch` is `World_Sim_Update_Tick`.
   The illegal-globals string confirms the script `data`-table handling inside the
   dispatch. `Scripts_Update_Dispatch` is called once per fixed step,
   `World_Sim_Update_Tick` once per rendered frame.
4. **World / simulation objects** — the object at `World + 0x1CB0` has a primary
   vtable whose slot 2 is the tick; it is installed by `World_ctor` (and by
   `World_Sim_ctor`). `World`'s own vtable slot 3 is `World_Execute`.
5. **Field offsets** — read them straight from the decompiler at the consuming
   function (e.g. `World_ctor` / the command applier) and record them under
   `structs`; the generated `@offsetOf`/`@sizeOf` asserts then guard them.
6. **App frame loop** — xref the string `"--------------------- Start Main
Loop"` → `App_MainLoop` (the real `WinMain` body; `WinMainCRTStartup` →
   `FUN_140049510` → `FUN_140079e60`). The loop pumps
   `PeekMessageW`/`GetMessageW`/`DispatchMessageW` and calls
   `(**(code**)*Shell_ptr)(Shell_ptr)`. `Shell_ptr` is the global `FortsShell`,
   built by `FUN_140067e60`, whose primary vtable is `FortsShell_Primary`; its
   slot 0 is `FortsShell_Execute`, the once-per-frame, works-in-menus app frame.
7. **Renderer** — Forts is **OpenGL fixed-function** (`OPENGL32.DLL` +
   `SwapBuffers` from `GDI32.DLL`; no D3D/DXGI). `SwapBuffers` has a single
   caller, `Renderer_Present` (`glFlush` + `GetDC`/`SwapBuffers`/`ReleaseDC` +
   `glClear`). The renderer vtable is built at runtime into `Renderer_vtable`;
   slot `+0x8` is `Renderer_Present`. Anchor on `"Creating context"` /
   `"video card model: %s"` (renderer init) and the `wglCreateContext` /
   `wglMakeCurrent` / `glGetString` imports.
8. **Input** — `DirectInput8Create` is called from `Input_Init`
   (`FUN_1405142f0`); the global `InputManager_ptr` is polled once per frame by
   `Input_Update` (`IDirectInputDevice8::GetDeviceState` at device vtable
   `+0x48`, `SetDataFormat` `+0x58`, `Acquire` `+0x38`, plus `GetKeyState` for
   mouse buttons). Detect it by xrefing `DirectInput8Create` and `GetKeyState`.
9. **Window / WndProc** — the WndProc is the in-binary function that calls both
   `DefWindowProcA` and `DefWindowProcW` (`WndProc`); it is registered by
   `FUN_140075700` (which calls `RegisterClassExW`/`RegisterClassA` +
   `CreateWindowExW`). The `WH_KEYBOARD_LL` hook proc is the `SetWindowsHookExA`
   callback (`LowLevelKeyboardProc`, installed by `FUN_140071ee0`). Anchor on the
   `"WM_CLOSE"` and `"intercepted WM_SYSKEYUP - VK_MENU"` strings.
10. **Debug overlay / console** — xref the control names `"DebugPanel"`
    (`0x707A60`) and `"DebugListBox"` (`0x707A48`): both are looked up in
    `PlayerController_CreateHud` (`0x189E10`), reached from
    `PlayerController_ctor` (`0x289E00`) via `World_ctor`, and shown by
    `HUD_DebugPanel` (`0x19C260`) which is called from `HUD_Update` (`0x190210`).
    Anchor the `HUD_Update` caller on the wide format `L"%d %d:%02d %.0f fps %S"`.
    The console is `Console_BindKeys` (`0x545A80`, xref `"ToggleConsole"`). The
    `TimeSpeedUp`/`TimeSpeedDown` action names drive the game speed; see
    "Debug overlay" above for how it is displayed.
11. **Lua scripting layer** — xref the `_Name`/`Name` binding strings (e.g.
    `_EnableAI`/`EnableAI`, `_CallScript`/`CallScript`) to reach
    `Lua_RegisterApi`; its installer is `Lua_InstallBinding`. The script list is
    the global `ScriptList` (xref `strings.IllegalGlobals` and `"SystemUpdate"` →
    `Scripts_Update_Dispatch`); each record is 0x90 bytes with the `lua_State` at
    `+0x08` and two `std::string`s at `+0x10`/`+0x30`. `Script_Dofile` is reached
    from the `scripts/forts.lua` string; `Script_ContextPush` from
    `strings.ScriptCtxMaxDepth`. The whole C API is registered by name, so
    `search_strings` for any exported name is a reliable anchor.
12. **UI toolkit** — the widget factory is the function that `_strnicmp`s a
    `Type` string against `"control"`/`"button"`/`"graph"`/`"static"`/
    `"staticwindow"`/`"text"`/`"textbutton"`/`"editbox"`/`"window"`/
    `"windowframe"`/`"listbox"`/`"tabbedpanel"`/`"sliderbar"`/`"dropdownmenu"`
    (`Ui_WidgetFactory`, anchor on the pooled literals at `0x6A4DE8..0x6A4E68`).
    The Lua UI bindings sit in the binding cluster (`_Name`/`Name` pairs) around
    `0x6F43C8..0x6F4A80`; xref a name (e.g. `LoadControl`) to its C
    implementation. Control names are `std::string`s at `Control+0x128` with the
    child vector at `+0xD0`, so xref the helper that walks `+0xD8`→`+0xD0`
    (`Ui_FindControl`). The screen builder and file loader are reached from the
    `ui/screens/*.lua` string writes; `UiActiveScreen`/`UiFlags`/`UiManager_ptr`
    are the globals every UI binding reads.

## Frame / render / input layer (1.38.2-r22447)

The once-per-frame layer, in call order, is:

```
App_MainLoop (0x79E60)              pump Win32 messages
  -> (*Shell_ptr->vtable[0])()      FortsShell_Execute (0x7A2A0)   [app frame, menus + match]
       -> (*Renderer_vtable[1])(1)  Renderer_Present  (0x517A60)   [glFlush + SwapBuffers]
       -> Input_Update              (0x5149A0)                     [DirectInput8 + GetKeyState]
  -> (*Shell_ptr->vtable[1])(...)   Shell_StateFrame (0x7A750)     [active-state frame + present]
       -> World_Execute             (0x1C67D0)                     [match only]
            -> World_Sim_Update_Tick(0x2A9030)                     [match only]
```

Counters observed live in the main menu: `FortsShell::Execute` and
`Input_Update` at the same rate, `Renderer_Present` within one frame of them;
the World-derived ticks are zero until a match starts. `Shell_StateFrame` is
the present used inside each state's `Execute`; `Renderer_Present` wraps every
actual swap, so it is the most robust frame counter.

### Window and input

- The window class is `"Forts"`. Its procedure is `WndProc` (`0x7EA60`); it
  handles `WM_CLOSE`, `WM_DESTROY`, `WM_SIZE`, `WM_ACTIVATE`, `WM_SYSKEYUP`,
  `WM_MOUSEWHEEL` (-> `InputManager+0xB54`), `WM_IME_*`, `WM_SIZING`/`WM_MOVING`
  and `WM_TIMER` (which itself calls `FortsShell::Execute`), and it forwards
  `WM_CHAR`/`WM_IME_CHAR` text to the InputManager (`FUN_140514750`). Everything
  else goes to `DefWindowProc`. The HWND is the global `Forts_hwnd`.
- Keyboard/mouse gameplay input does **not** come from `WM_KEYDOWN`: it comes
  from **DirectInput8** polled in `Input_Update`, plus `GetKeyState` for the
  mouse buttons inside `WndProc`. `LowLevelKeyboardProc` (`0x71E80`, installed as
  a `WH_KEYBOARD_LL` hook) is a second, OS-level keyboard interception point.
- `structs.input` (`InputManager`, global `InputManager_ptr`) exposes the polled
  state: `keyboard_state`/`keyboard_prev` at `+0x40`/`+0x140` (256-byte DIK
  scancode arrays, `0x80` = down), and `mouse_dx`/`mouse_dy`/`mouse_wheel` at
  `+0x240`/`+0x244`/`+0x248`.

**Listening** — hook `Input_Update` and read `InputManager+0x40` (the Frida
hook agent's `input` export does exactly this; `verify.py --hook` prints the
held keys and mouse deltas).

**Filtering (e.g. while a custom overlay wants the mouse/keyboard)** — zero
`InputManager+0x40` (and the mouse fields) at `Input_Update` `onEnter`, before
the game consumes them, or swallow the relevant `WM_*` in `WndProc`.

`Input_Update`, `Renderer_Present`, `WndProc` and `FortsShell_Execute` are all
declared under `signatures`, so `gen_zig.py` emits `Fn*` aliases, per-version
relays and `manifest.relays` entries for them — a loader hook (Frida
`Interceptor` today, the Zig relay loader for a shipping mod) can install them
without any further RE.

### Vulkan (not modelled)

The game can optionally use Vulkan, but it is **interop, not a separate
renderer**: it loads `vulkan-1.dll` on demand ("Check for and load vulkan-1.dll")
and presents through OpenGL using `GL_NV_draw_vulkan_image`. `Renderer_Present`
stays the single present hook in that mode too. Only the probe string is
anchored (`strings.Vulkan_check`); the Vulkan path is intentionally out of
scope. When Vulkan is off the process maps `nvoglv64.dll` and no
`vulkan-1.dll`; `d3d11`/`dxgi` in the process are Steam/DevIL, not renderers.

### Debug overlay (DebugPanel) and the in-game console

There are **two** debug UIs, and neither is a hotkey for the DebugPanel:

- **Console** — the real `Console` subsystem. `Console_BindKeys` (`0x545A80`)
  binds `ToggleConsole` to `~` (DIK 0x29), `ToggleConsoleFullscreen` to
  `~`+Shift, plus Enter/Backspace/Paste/AutoComplete. It prints the mod-load log
  and takes commands. (`~` observed opening it live.)
- **DebugPanel** — a HUD overlay that shows the live debug line
  `"%d %d:%02d %.0f fps %S"`: simulation frame, `mm:ss`, fps, and the **current
  game speed as `Nx`** (the `%S` is the time-keeper speed slot). This is the
  only place the speed is shown in the UI. It is a `Static` (`0x707A60`) plus a
  `DebugListBox` (`0x707A48`, RTTI `ListBox`) that lists mod activation etc.

**Opening DebugPanel.** `HUD_DebugPanel` (`0x19C260`) shows it only when
`PlayerController+0x47` is nonzero; the ctor sets that to
`(World+0x1B64 == 2)`, i.e. **spectator/observer mode only** — which is why it
never appears in a normal match. The byte is re-evaluated every frame, so writing
it once is not enough; force it on every frame:

```js
// on entry to HUD_Update (0x190210) or HUD_DebugPanel (0x19C260):
var pc = World_ptr.readPointer().add(0x1ce0).readPointer(); // PlayerController
pc.add(0x47).writeU8(1); // debug_overlay = 1
```

Verified live: forcing `PC+0x47=1` each frame made the `26465 17:32 200 fps 2x`
line appear at the top-left. The DebugPanel/ListBox controls live on the **HUD
sub-object at `PlayerController+0xE10`** (`structs.hud.debug_panel` `+0x1218`,
`debug_list` `+0x1220`), not on the 0xF50 `PlayerController` itself.

**Game speed.** The mechanics live in the simulation/time keeper, not in the
DebugPanel: `WorldSim` steps **25 Hz** (`World_Sim_Update_Tick` computes
`steps = (now - accumulated) / fixed_timestep`, `fixed_timestep` = 0.04 at
`sim+0x1860`). There are `TimeSpeedUp`/`TimeSpeedDown` actions and the observer
"Speed" control. Measured live: writing the `RealTimeKeeper` `shift` (`+0x0C`)
or `scale` (`+0x14`) is overwritten every frame and `shift` breaks the sim;
`sim+0x160..0x164` (speed slots/index) is the engine's speed state. The reliable
lever is the fixed timestep: `sim+0x1860 = 0.04 / speed` gave an exact 2× live
(100 steps/s vs 50) and restored cleanly. Changing the timestep alters physics
and would desync replays/MP; the engine's own speed path changes the time flow
instead. The displayed `Nx` comes from the time-keeper speed slot
(`sim+((idx*3+0x5b)*4)`).

### Simulation clock (embedded `SoftwareTimeKeeper`)

`WorldSim+0x18C0` is **not** a clock pointer — it is an **inline** `SoftwareTimeKeeper`
object (`structs.software_time_keeper`): the object starts at that offset and its
first 8 bytes are the vptr `SoftwareTimeKeeper::vftable` (`0x14069F1F8`,
modelled as vtable `SoftwareTimeKeeper_Primary`). The WorldSim ctor
(`World_Sim_ctor`, `0x2F9E90`) calls `SoftwareTimeKeeper_ctor` (`0x50DE10`) with
`&sim->clock`; that ctor stores the vtable at `+0x0` and `0.0f` at `+0x8`:

```c
*this = SoftwareTimeKeeper::vftable;   // vptr at WorldSim+0x18C0
this->time = 0.0f;                     // WorldSim+0x18C8
```

The tick (`World_Sim_Update_Tick`) drives it through the vtable:
`(*(sim+0x18C0)->vtable[1])(sim+0x18C0, 0)` is `SoftwareTimeKeeper_Get`
(`0x2769F0`, `MOVSS xmm0,[rcx+8]`) and the post-step write uses slot `+0x0`,
`SoftwareTimeKeeper_Set` (`0x3FDFA0`, `MOVSS [rcx+8],xmm1`). Both are modelled,
so they can be hooked to observe or override the per-step sim time.

This is the case that motivated the `embedded` field type: modelling the clock as
a `ptr` was wrong (there is no pointee; the object is the storage). The sibling
sub-objects at `WorldSim+0x1908` and `+0x1948` (ctor `FUN_14050dc70`) are the same
pattern and can be documented the same way when identified. The class family is
`TimeKeeper` -> `SoftwareTimeKeeper` / `HardwareTimeKeeper` / `PhysicsTimeKeeper` /
`UnpausedTimeKeeper` / `RealTimeKeeper` (all with RTTI); the global sync clocks
`DAT_1407dec30` / `DAT_1407debd8` are configured from `Network.SyncClock.*`.

Strings may be **narrow or wide**: a `strings` entry with `"wide": true` is read
as UTF-16LE by `verify.py` (`PE.read_wcstr`), for anchors like the debug-panel
format `L"%d %d:%02d %.0f fps %S"`.

### Lua scripting layer

Forts links **Lua 5.1.1** (PUC-Rio) statically and gives **each script its own
`lua_State`**. A "script" is a mission file (`maps/<map>/<map>.lua`), a mod file
(`mods/<mod>/script.lua`) or an AI file; `scripts/forts.lua` is the shared
bootstrap that every script `dofile()`s.

**How the C API is registered.** `Lua_RegisterApi` (`0xB1290`) installs the whole
API — **594 C functions** — into a script manager's state
(`FUN_140066d00(manager)` = `*(manager+0x228)`). It is a fully unrolled block per
function of _(public name, `_Name`, C function pointer, arity flag)_; the actual
install is `Lua_InstallBinding` (`0x4E3D00`), which is `lua_pushcclosure` +
`lua_setfield` with the real C pointer carried as the closure's single upvalue
(the per-signature trampolines, e.g. `FUN_1400e3510`, convert args). The global
byte `DAT_1407dd684` selects the mode: `0` binds each name directly, nonzero binds
`_Name` and also auto-generates a Lua `LogCall` wrapper via `LogWrapperTemplate`.

**Registering your own function.**

- _Lua level (intended way for mods)_ — a `script.lua`/mission script defines any
  global Lua function and any `On*` event handler; the game dispatches events by
  name, so declaring `function OnWeaponFired(...)` is "registering" a callback.
  `ScheduleCall` and the other helpers live in `scripts/forts.lua`.
- _Native level_ — get a `lua_State*` (`ScriptRecord+0x08`, or the global
  `LuaCurrentState`) and call `Lua_InstallBinding` with your `lua_CFunction`
  (wrap the pointer as the upvalue exactly as the engine does), or hook
  `Lua_RegisterApi`/`Lua_InstallBinding` to observe or extend registration.

**Scripts and state.** `ScriptList` (`0x7DE2E8`) points at a
`std::vector<ScriptRecord>`; each record is **0x90 bytes** (`structs.script_record`):
`active` (`+0x00`), `lua_State*` (`+0x08`), path (`std::string`, `+0x10`), short
name (`std::string`, `+0x30`), and the global-table count (`+0x60`). Live in a
match this reads e.g. `mods/dlc_harpoon/script.lua` and `mods/dlc3/script.lua`,
each with its own state. State must be kept in each script's **`data` table**,
which the engine serialises for late join / replay seek; writing state elsewhere
is caught by the guard in `Scripts_Update_Dispatch`, which logs
`strings.IllegalGlobals` ("...state should only be stored in the 'data' table to
avoid desyncs"). The `data` table is not created by the C registrar — it is a
plain Lua table the script builds.

**Dispatch.**

- Per fixed physics step — `Scripts_Update_Dispatch` (`0xC6320`), called only
  from `World_Sim_Update_Tick` (`0x2A9030`): for each active record it calls
  `SystemUpdate(frame)` then `Update(frame)`, runs the global-count/desync guard,
  and times the pair (`"%d EXECTIME UpdateScript %s %f"`).
- Per rendered frame — `Scripts_OnUpdate_Event` (`0xC69C0`) dispatches `OnUpdate`.
- Event context — every event dispatcher first calls `Script_ContextPush`
  (`0x900F0`), which sets `CurrentScriptName` (`0x7DD5C0`) and appends to
  `ScriptContextQueue` (`0x7DE2F0`, max depth 10); this is what backs
  `GetCurrentScript`/`GetCurrentCall`.

**Loading & cross-script calls.** `Script_Dofile` (`0x3E3E70`) is the engine
`dofile()`: it `lua_load`s and `lua_pcall`s in `LuaCurrentState` (only at
initialisation), and after `scripts/forts.lua` also loads `scripts/forts_dlc3.lua`.
Script→script bridges are the bindings `Lua_CallScript` (`0x92180`),
`Lua_ExecuteInScript` (`0x91180`), `Lua_SendScriptEvent` (`0x91370`),
`Lua_GetScriptValue` (`0x915F0`) and `Lua_SetScriptValue` (`0x91F80`).

Use `uv run python tools/frida/scripts.py` to list the live scripts, their states
and global counts.

## Entities and physics (1.38.2-r22447)

Forts is a **custom physics engine**: a fort is a graph of `Node`s joined by
`Link`s (struts), with `Device`/`Weapon` objects attached to node pairs and
`Projectile`s that are themselves nodes. The Lua API (`Forts Scripting API`, the `Functions\Structure`,
`Functions\Devices`, `Functions\Projectiles` and `Functions\Constants` groups) is
the documented access surface, and every getter there maps onto one of the
offsets below. `tools/frida/entities.py` reads these live.

### Containers (from the WorldSim tick `FUN_1402a9030` and the world-dump writer)

| Path                          | Contents                                                                                                                                               |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `World+0x1CB0`                | `WorldSim` (`structs.sim`).                                                                                                                            |
| `World+0x1CC0`                | `TerrainManager` (`structs.terrain`), built by `World_ctor` via `FUN_1401fb780`; holds gravity/air-drag.                                               |
| `World+0x1CA0`                | Teams/players manager (`structs.world.teams`): per-team state, `+0x1300` = team count, `+0xF20 + side*0x148` = per-side block, `+0x12F8` = a map/tree. |
| `World+0x1CA8`                | `manager_1ca8`: owns the device list at `+0x6C0`/`+0x6C8` (`std::vector<Device*>`).                                                                    |
| `WorldSim+0x30`/`+0x38`       | `std::vector<Node*>` begin/end (8 bytes per slot). Slots 0 and 1 are the reserved null/sentinel entries; real nodes start at index 2.                  |
| `WorldSim+0xCC` (in Node)     | `std::vector<Link>` control block (begin/end/cap at node `+0xCC`/`+0xD4`/`+0xDC`); Link elements are `0x19C` bytes.                                    |
| `WorldSim+0xB48 + side*0x18`  | Per-side structure list; each structure is `0xE90` bytes.                                                                                              |
| `WorldSim+0x1960`             | Timed/scheduled list (walked by the tick with a time key).                                                                                             |
| `WorldSim+0x1101` / `+0x1102` | Physics-enabled flags (the tick early-outs when both are 0; `EnablePhysics` drives these).                                                             |

### `Node` (`structs.node`)

`Node` is a **packed (4-byte) MSVC class**, so its pointers and vector sit at
4-mod-8 offsets that the `structs` field vocabulary (natural alignment) cannot
express. The naturally-aligned scalars are modelled; the packed members are
documented here instead:

| Offset                         | Meaning                                                                          |
| ------------------------------ | -------------------------------------------------------------------------------- |
| `+0xEC`                        | `u32` node id (Lua `NodeExists`/`NodePosition`/`NodeTeam`/...).                  |
| `+0xF0`                        | `u32` team id (`side = team % 100`).                                             |
| `+0xF8` / `+0xFC`              | `f32` mass / drag.                                                               |
| `+0x100` / `+0x104` / `+0x108` | `f32` position x/y/z.                                                            |
| `+0x10C` / `+0x110` / `+0x114` | `f32` velocity x/y/z.                                                            |
| `+0x124`                       | `i32` structure id (`NodeStructureId`); `-1` when unassigned.                    |
| `+0x128` / `+0x12C`            | `f32` previous-step position x/y.                                                |
| `+0xBC`                        | `ptr` projectile (null unless the node is a projectile; Lua `IsNodeProjectile`). |
| `+0xC4`                        | `ptr` attached `Device`/`Weapon` controller (null otherwise).                    |
| `+0xCC`/`+0xD4`/`+0xDC`        | `std::vector<Link>` begin/end/cap, `0x19C`-byte elements.                        |

This layout is **verified live** against the game's own world dump: for node
`N251` the probe read id `251`, team `2`, structure `1`, position
`1995.333, 106.2096`, matching the dump line for `N251` exactly. `NodeVelocity`
reads the velocity triple.

### Resolved `Physics.*` parameters (`structs.sim`)

The `WorldSim` constructor (`FUN_1402f9e90`) reads every `Physics.*` config key
once through the config registry (`World+0x140`, getter `FUN_1403e5df0`) and
caches the resolved value at a fixed sim offset. Those offsets are modelled as
`structs.sim` fields (all named by their config key). The most useful are
`fixed_timestep` (`+0x1860`, `1 / Physics.FramesRate`), `frame_batch_a`
(`+0x1864`, `Physics.FramesPerTick`), `frame_batch_b` (`+0x1868`,
`Physics.TickLookahead`), `minimum_mass` (`+0x1108`), the angle/stress limits
(`+0x1114`.. `+0x1128`, stored in radians), `min_stiffness`/`max_stiffness`
(`+0x12A0`/`+0x12A4`) and the water parameters (`+0x12B0`..`+0x12CC`). Verified
live: `minimum_mass` 15, `angle_stress_primary` 0.5236 rad (30°), water drag 50,
stiffness 10000/1000000, `water_max_depth` 500.

`Physics.Gravity` and `Physics.AirDrag` are **not** on the sim; the
`TerrainManager` ctor (`FUN_1401fb780`) caches them at `terrain+0x9F4` and
`terrain+0x9FC`. Verified live: gravity `981`, air-drag `0.4`.

### Devices

Devices (and weapons) hang off `manager_1ca8+0x6C0` (`std::vector<Device*>`).
Each device carries its team id encoded at `+0x318` (`side = team % 100`) and a
state byte at `+0x326` (`5` = a skipping state the world dump ignores); the
device-specific serialized block starts at `+0x310` (0x38 bytes) and a weapon's
extra block at `+0x4B4` (0x14 bytes). Verified live: the vector holds 8 devices
whose `+0x318` values mark both sides. Device ids/types/health offsets are not
yet mapped; use the Lua getters (`GetDeviceId`, `GetDeviceType`,
`GetDeviceHitpoints`) as the reference for what to find.

### The game's own world dump (the fastest way to re-derive offsets)

The tick writes a full text dump of the world — teams, clients, every node with
its links, structures, projectiles and modifiers — when the byte at
`*(WorldSim+0x78)+8` is nonzero. The writer is `FUN_1402afbf0(sim, path)`
(called with `"%s/world-dump-%d-%s.txt"`), and it writes into
`users/<steamid>/`. `entities.py --dump` flips that gate for a moment and the
files land next to the user data. Because the dump prints the _same_ fields the
Lua API exposes, it is the ground truth for validating any entity offset on a
new build: enable it, read a node's values, then match them against a live
memory read. The text format is produced by `FUN_1402b0ac0`; the binary writer
half is `FUN_1402afcc0`.

## UI toolkit and Lua UI API (1.38.2-r22447)

Forts' UI is a **custom C++ widget toolkit driven by declarative Lua screens**,
not a third-party UI library. Screens are plain-text Lua tables in
`data/ui/screens/*.lua` of the form
`Root = { Type = ..., Name = ..., Style = ..., Control = { Position/Size/Anchor/Children }, ... }`;
`data/ui/styles.lua` defines the style set, `data/ui/uisprites.lua` the sprites,
and `data/ui/layout.lua` the layout constants (`MiddleX`, `MainPanel`, ...).
(`scripts/*.lua` are compiled Lua 5.1.1 bytecode, but the `ui/` screens are
source.) The engine also exposes the toolkit to scripts as a documented API
(Forts Scripting API → _Functions/User Interface_, plus the `OnControlActivated`
and `DismissResult` events); this is the supported way for a mission or mod
script to create and mutate its own windows.

Layout expressions (`ScriptX`/`ScriptY`/`ScriptW`/`ScriptH`, e.g.
`MiddleX - MainPanel.x`, `ParentMiddleX`, `PrevVisibleSiblingBottom + 4`) are a
tiny Lua-expression mini-language evaluated by `EvaluateLayoutScript`
(`0x946C0`). A `$name` prefix in a text argument means a localised string id.

### Widget classes and the factory

RTTI classes: `Control` → `WindowFrame` → `StaticWindow` → `Static` /
`BorderedWindow`; plus `Button`, `Text`, `TextButton`, `EditBox`, `ListBox`,
`TabbedPanel` (also implements `ICallbackTarget`), `SliderBar`, `DropDownMenu`,
`Graph`. `Ui_WidgetFactory` (`0x54FA20`) dispatches on a case-insensitive
`_strnicmp` of the `Type` string and constructs one widget:

| `Type`         | class                          | alloc size |
| -------------- | ------------------------------ | ---------- |
| `Control`      | Control                        | 0x190      |
| `Button`       | Button                         | 0x3E8      |
| `Graph`        | Graph                          | 0x240      |
| `Static`       | Static                         | 0x328      |
| `StaticWindow` | StaticWindow                   | 0x338      |
| `Text`         | Text                           | 0x880      |
| `TextButton`   | TextButton                     | 0x930      |
| `EditBox`      | EditBox                        | 0x9C0      |
| `Window`       | BorderedWindow                 | 0x200      |
| `WindowFrame`  | WindowFrame                    | 0x268      |
| `ListBox`      | ListBox                        | 0x408      |
| `TabbedPanel`  | TabbedPanel (+ICallbackTarget) | 0x218      |
| `SliderBar`    | SliderBar                      | 0x3A0      |
| `DropDownMenu` | DropDownMenu                   | 0x370      |

`structs.control` models the base `Control` (`0x190`): vptr at `0x0`, the
`std::vector<Control*>` of children at `0xD0`, the `std::string` name at `0x128`
(SSO buffer, size `+0x138`, capacity `+0x140`), and a child-lookup gate byte at
`0x148`. Control names are the first argument to the Lua UI functions and the
key the engine uses for its own named lookups (e.g. `DebugPanel`,
`ResourcePanelEnemy`, `HUDPanel`, `ObjectivesPanel`).

### Screen loading and the active-screen selector

`Ui_BuildFromLua` (`0x550DF0`) builds a control/screen graph from a Lua chunk
(used by the per-screen ctors and by `Ui_LoadControl`); it injects `ScreenW` /
`ScreenH` (`0x71F620` / `0x71F628`) into the screen state. `Lua_LoadFile`
(`0x3E4230`) loads and runs a Lua file through the pack-aware virtual filesystem
(Lua 5.1.1 / LuaPlus), sandboxed — it strips/restores `loadfile`, `require`,
`module`, `package` and gates globals.

The Lua UI bindings all operate on the **currently selected screen**: the global
`UiActiveScreen` (`0x7DD5D8`, u32) selects it and `UiFlags` (`0x7DD5CC`, u32)
must have bit `0x2` set or every UI binding early-outs. The control tree root is
reached through the UI/display manager `UiManager_ptr` (`0x7DEBF8`); its `+0x28`
points at a display object holding the win32 HWND and the `GetClientRect`-derived
client size (i32 at `+0x48`/`+0x4C`, f32 at `+0x6C`/`+0x70`, flag at `+0x7C`),
which is what `Ui_CenterOnDesignSize` (`0x55A360`) centres the 1066.67×600 design
canvas against. Helpers: `Ui_FindControl` (`0x55B060`, recursive name lookup),
`Ui_AddChild` (`0x559EA0`) / `Ui_AddChildFront` (`0x559F50`).

### Lua UI API — C implementations

Registered by `Lua_RegisterApi` (`0xB1290`); the `_Name`/`Name` binding strings
sit at `0x6F43C8..0x6F4A80` (the `Set*` family) and `0x6FBCD0..` (`Get*Text`/
`CustomData`/`Sprite`).

| Lua function           | C++                       | RVA       |
| ---------------------- | ------------------------- | --------- |
| `LoadControl`          | `Ui_LoadControl`          | `0x94A50` |
| `AddTextControl`       | `Ui_AddTextControl`       | `0x94C60` |
| `AddTextButtonControl` | `Ui_AddTextButtonControl` | `0x94E60` |
| `AddButtonControl`     | `Ui_AddButtonControl`     | `0x95080` |
| `AddSpriteControl`     | `Ui_AddSpriteControl`     | `0x951E0` |
| `ControlExists`        | `Ui_ControlExists`        | `0x952C0` |
| `SetButtonCallback`    | `Ui_SetButtonCallback`    | `0x95500` |
| `SetControlText`       | `Ui_SetControlText`       | `0x955B0` |
| `GetChildCount`        | `Ui_GetChildCount`        | `0x94100` |
| `GetChildName`         | `Ui_GetChildName`         | `0x941C0` |
| `EvaluateLayoutScript` | `Ui_EvaluateLayoutScript` | `0x946C0` |
| `ShowControl`          | `Ui_ShowControl`          | `0x96150` |
| `DeleteControl`        | `Ui_DeleteControl`        | `0x96190` |
| `WorldToScreen`        | `Ui_WorldToScreen`        | `0xB0460` |
| `ScreenToWorld`        | `Ui_ScreenToWorld`        | `0xB04A0` |

`SetButtonCallback(parent, name, int id)` assigns the numerical activation id so
a control dispatches `OnControlActivated(name, code, doubleClick)`; controls made
by `AddButtonControl`/`AddTextButtonControl` dispatch without it, controls that
came from `LoadControl` do **not** until it is called. Changing game state from
`OnControlActivated` must go through `SendScriptEvent` (direct changes desync).

### Creating a window from a script

Either imperatively:

```lua
AddTextControl("", "MyWin.Title",  "Hello", ANCHOR_TOP_LEFT, Vec3(20, 60, 0), false, "Title")
AddButtonControl("", "MyWin.Close", "ui-button-short", ANCHOR_TOP_LEFT,
                 Vec3(192, 41, 0), Vec3(20, 120, 0), "Heading")   -- fires OnControlActivated
```

or by loading a declarative tree (the pattern the game's own `battlelog.lua`
uses) and then wiring buttons:

```lua
LoadControl("ui/screens/mywin.lua", "")            -- add my tree under the screen root
CenterControl("", "MyWin", true, true)
if ControlExists("", "MyWin.Close") then
    SetButtonCallback("", "MyWin.Close", 1)         -- make it dispatch OnControlActivated
end
```

`ANCHOR_*`, `FRAME_*` and `Vec3` are defined in `scripts/forts.lua`
(compiled bytecode). `data/maps/03-weapons/03-weapons.lua` and
`data/maps/Minigame-Height/Minigame-Height.lua` are the best in-ship examples of
`AddTextControl`/`AddSpriteControl`/`SetControlText` use, and
`data/scripts/battlelog.lua` is the smallest `LoadControl` example.

## Ghidra tooling

- **Ghidra 12.1.4** (headless), driven by `pyghidra` / `pyghidra-mcp`
  (MCP server `pyghidra`, configured in `.kilo/kilo.json`).
- Project: repo-local `ghidra-projects/` (the `forts` project). Import
  `Forts.exe` with default analysis; **auto-analysis takes a few minutes**.
  Symbol search, `decompile_function`, `list_xrefs`, `disassemble` and
  `read_bytes` work as soon as `analysis_complete == true`.
- The MCP `search_code` / `search_strings` tools additionally need the MCP-side
  **code index** (it decompiles all ~17k functions once, several minutes, into
  `ghidra-projects/<project>-pyghidra-mcp/chromadb`). Until then they report
  "index not complete"; wait it out.
- Re-importing `Forts.exe` gives the program a new name suffix. Match the binary
  by the SHA-256 in `targets/*.json` before trusting any address; everything here
  is version-specific.

## Runtime environment (Frida 17)

Agents cannot use `Thread.sleep`/`setTimeout`, and `Module.findBaseAddress` was
removed. The scripts therefore poll from Python and use
`Process.findModuleByName`, and read `World_Sim_Update_Tick`'s `float delta`
from the boxed `context.xmm1` via a small ArrayBuffer→Float32 helper.

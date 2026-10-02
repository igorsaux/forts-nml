# Forts Native Mod Loader

`forts-nml` is a native mod loader for the game **Forts**. It is a DLL proxy that
the game loads as `DINPUT8.dll`: it forwards the real DirectInput API untouched
while installing lightweight hooks into the running game and loading user mods
from disk.

It is deliberately low-level. It is a _loader_, not a dependency/version manager:
it gives mods a stable, versioned C ABI and a small set of interfaces, and
otherwise stays out of the way. Anything else — a scripting layer, an event bus,
a dependency resolver — can be built on top of it.

The complete API reference (types, ownership and lifetime rules, and the
semantics of every interface member) lives in
[`src/forts.h`](src/forts.h).

## Building

Requirements:

- Zig **0.16.0** (`build.zig.zon` pins the minimum).
- Python 3.12 + [`uv`](https://docs.astral.sh/uv/) — the build calls
  `uv run tools/frida/gen_zig.py` to generate `manifests.zig` from
  `tools/frida/targets/`.

```sh
zig build
```

Outputs under `zig-out/`:

- `bin/DINPUT8.dll` — the loader/proxy to drop into the game directory.
- `bin/ExampleLogger.dll`, `bin/ExampleClient.dll`, `bin/ExampleHook.dll` — example mods.
- `include/forts.h` — the ABI header for mod authors.

## Installing

1. Copy `zig-out/bin/DINPUT8.dll` into the game directory (next to `Forts.exe`).
2. Create `<game>/settings.nml.json` (see [Configuration](#configuration)).
3. Put each mod DLL somewhere relative to the game directory and list its path in
   `settings.nml.json`.

## Configuration

The loader reads one small JSON file.

### `<game>/settings.nml.json`

Lists the mods to load, in order:

```json
{
  "mods": ["ExampleLogger.dll", "ExampleClient.dll"]
}
```

Each entry is the path of a mod DLL relative to the game directory, so a plain
file name means "next to `Forts.exe`". Paths may include subdirectories, for
example `"mods/ExampleLogger.dll"`. If the file is missing or empty, the loader
writes the default (`{"mods":[]}`) and loads nothing.

## Writing a mod

A mod is a DLL that exports three C-callconv functions. Include `forts.h` (shipped
in `zig-out/include/`) and implement them. This is a complete, if useless, mod:

```c
#include "forts.h"

#define CSTR(lit) ((Forts_CString){ (lit), sizeof(lit) - 1 })

static Forts_GetInterface get_iface;
static Forts_Handle        mod_handle;

int Forts_Mod_load(Forts_GetInterface get, Forts_Handle handle) {
    get_iface  = get;      // stays valid for the whole mod lifetime
    mod_handle = handle;   // this mod's own handle
    return 0;              // non-zero aborts loading
}

int Forts_Mod_init(void) {
    return 0;
}

void Forts_Mod_unload(void) {}
```

The three calls happen in this order:

| Call                                    | When                                | Notes                                                                                          |
| --------------------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------- |
| `Forts_Mod_load(get_iface, mod_handle)` | once, when the mod is loaded        | Register your protocols here. Non-zero return fails the load.                                  |
| `Forts_Mod_init(void)`                  | once, **after all mods are loaded** | Safe place to resolve protocols published by other mods. Non-zero return fails initialisation. |
| `Forts_Mod_unload(void)`                | once, on process detach             | Before this mod's memory becomes invalid.                                                      |

The distinction between `load` and `init` is the whole point of having two: during
`load` another mod may not be ready yet, but by `init` every mod has registered its
protocols, so cross-mod lookups always succeed there.

### Getting an interface

Interfaces are resolved by name through the `Forts_GetInterface` function passed
to `Forts_Mod_load`. The name is one of the `FORTS_*_INTERFACE_LAST` macros; the
result is an opaque pointer you cast to the matching interface struct:

```c
Forts_HandleInterface* handle_iface =
    (Forts_HandleInterface*)get_iface(CSTR(FORTS_HANDLE_INTERFACE_LAST));
```

An unknown name gives `NULL`. The same call also works for the debug log:

```c
Forts_DebugLogInterface* log_iface =
    (Forts_DebugLogInterface*)get_iface(CSTR(FORTS_DEBUG_LOG_INTERFACE_LAST));
log_iface->print(CSTR("hello from my mod"));
```

### Talking to other mods

A _protocol_ is a struct that starts with a `Forts_UUID` (16 bytes); the rest is
its payload, usually a table of function pointers. It is the one supported way
for mods to expose functionality to each other, because it keeps the ABI stable:
consumers agree on a UUID and a struct layout, not on each other's symbols.

Here is a mod that publishes a logger protocol. The protocol object must be
`static` (or otherwise live for the mod's lifetime) because the host stores a
pointer to it:

```c
typedef struct {
    Forts_UUID uuid;                       // always first
    void (*log)(Forts_CString msg);
} LoggerProtocol001;

static void logger_log(Forts_CString msg) {
    // ... do something with msg ...
}

static LoggerProtocol001 LOGGER = {
    .uuid = { 0x1b, 0x9c, 0x96, 0x64, 0xf3, 0x21, 0x4a, 0x7b,
              0xb7, 0x44, 0x4a, 0xbc, 0x68, 0xea, 0x9f, 0x2f },
    .log  = logger_log,
};

int Forts_Mod_load(Forts_GetInterface get, Forts_Handle handle) {
    Forts_HandleInterface* handle_iface =
        (Forts_HandleInterface*)get(CSTR(FORTS_HANDLE_INTERFACE_LAST));

    return handle_iface->install_protocols(handle, &LOGGER, 1); // 0 on success
}
```

A mod that wants to use it does the lookup in two steps. First ask the runtime
_which mods_ implement the UUID; then ask each such mod handle for _its_
protocol. The consumer only needs the UUID bytes, not the provider's code:

```c
static const Forts_UUID LOGGER_UUID = {
    0x1b, 0x9c, 0x96, 0x64, 0xf3, 0x21, 0x4a, 0x7b,
    0xb7, 0x44, 0x4a, 0xbc, 0x68, 0xea, 0x9f, 0x2f,
};

int Forts_Mod_init(void) {
    Forts_HandleInterface* handle_iface =
        (Forts_HandleInterface*)get_iface(CSTR(FORTS_HANDLE_INTERFACE_LAST));
    Forts_RuntimeInterface* runtime_iface =
        (Forts_RuntimeInterface*)get_iface(CSTR(FORTS_RUNTIME_INTERFACE_LAST));

    Forts_Handle* mods = NULL;
    size_t        mod_count = 0;

    runtime_iface->locate_protocol(LOGGER_UUID, &mods, &mod_count);
    // `mods` is now the address of an array of `mod_count` handles.

    if (mod_count > 0) {
        LoggerProtocol001* logger =
            (LoggerProtocol001*)handle_iface->get_protocol(mods[0], LOGGER_UUID);

        if (logger != NULL) {
            logger->log(CSTR("hello, world!"));
        }
    }

    return 0;
}
```

### Hooking game functions

The `Forts_HookInterface` attaches your callbacks to the game's own functions.
The loader patches a fixed, version-specific set of functions when it starts and
dispatches to every mod that asked for them; check `has_function` before relying
on a name.

```c
static Forts_HookInterface* hook_iface;

// Must match the target's signature exactly. For "World_ctor" that is:
//   World* World_ctor(World* this, Engine* engine, MatchSetup* setup);
static void* on_world_ctor(void* world, void* engine, void* setup) {
    // runs before the real constructor
    return world;
}

int Forts_Mod_load(Forts_GetInterface get, Forts_Handle handle) {
    hook_iface = (Forts_HookInterface*)get(CSTR(FORTS_HOOK_INTERFACE_LAST));

    if (hook_iface->has_function(CSTR("World_ctor"))) {
        hook_iface->add_pre_hook(CSTR("World_ctor"), (const void*)on_world_ctor);
    }

    return 0;
}
```

There are three kinds of callback:

| Call                      | Runs                          | Notes                                                  |
| ------------------------- | ----------------------------- | ------------------------------------------------------ |
| `add_pre_hook(name, fn)`  | before the implementation     | any number; run in registration order                  |
| `add_post_hook(name, fn)` | after the implementation      | any number; run in registration order                  |
| `replace(name, fn)`       | instead of the implementation | one per function; call the original via `get_original` |

A callback is invoked with the same arguments, on the same thread, as the
function it hooks. Pre- and post-hook return values are ignored; the return
value of a replacement (or of the original, if not replaced) becomes the
function's result. Because pre- and post-hooks get arguments by value, they
cannot rewrite them or the result — that requires a `replace` that calls the
original:

```c
static void(*original_world_ctor)(void*, void*, void*);

static void* replacement_world_ctor(void* world, void* engine, void* setup) {
    // ... inspect or change arguments ...
    return original_world_ctor(world, engine, setup); // call through
}

int Forts_Mod_load(Forts_GetInterface get, Forts_Handle handle) {
    Forts_HookInterface* hook_iface =
        (Forts_HookInterface*)get(CSTR(FORTS_HOOK_INTERFACE_LAST));

    hook_iface->get_original(CSTR("World_ctor"), (const void**)&original_world_ctor);
    hook_iface->replace(CSTR("World_ctor"), (const void*)replacement_world_ctor);

    return 0;
}
```

Register from `Forts_Mod_load` or `Forts_Mod_init`: once every mod has
initialised, the hook set is frozen and further registrations return non-zero.
The query calls (`has_function`, `is_replaced`, `get_original`) work at any time.

### Reading game object fields

Object layouts move between game versions, so the ABI never hands out raw
offsets. `Forts_FieldInterface` resolves a named field of a named game type at
runtime and returns a pointer into the live object:

```c
static Forts_FieldInterface* field_iface;

// Example: read MatchSetup::map_path (an inline char buffer) from an object.
static void print_map_path(Forts_DebugLogInterface* log_iface, void* setup) {
    Forts_FieldInfo info;

    if (!field_iface->get_info(CSTR("MatchSetup"), CSTR("map_path"), &info)) {
        return; // this build does not expose the field
    }

    char* value =
        (char*)field_iface->locate(setup, CSTR("MatchSetup"), CSTR("map_path"));

    if (value != NULL) {
        log_iface->print((Forts_CString){ value, strnlen(value, info.size) });
    }
}
```

`has_field` is the feature test, `get_info` reports the field's size and
alignment, and `locate` returns the field's address inside the object (a
borrowed interior pointer, valid while the object lives). The bytes are untyped:
read or write them with the layout of `type_name` for the running game version.
A field the build lacks yields `0` from the boolean calls and `NULL` from
`locate`.

### Reading game global variables

The game's global variables move between versions just like object fields, so
`Forts_VariableInterface` addresses them the same way — by name, with no offsets
in the mod. It is the global-variable counterpart of `Forts_FieldInterface`:
`exists` is the feature test, `get_info` reports size and alignment, and
`locate` returns the address of the variable's storage. No object is involved:

```c
static Forts_VariableInterface* variable_iface;

// Example: read SimFrame, a global u32 frame counter.
static int read_sim_frame(uint32_t* out) {
    Forts_VariableInfo info;

    if (!variable_iface->get_info(CSTR("SimFrame"), &info)) {
        return 0; // this build does not expose the global
    }

    uint32_t* value = (uint32_t*)variable_iface->locate(CSTR("SimFrame"));

    if (value == NULL || info.size != sizeof(*value)) {
        return 0;
    }

    *out = *value;
    return 1;
}
```

`locate` returns the address of the variable itself — owned by the game module
and valid for the process lifetime, not an interior pointer into an object. As
with fields, the bytes are untyped: read or write them with the layout you know
for the variable. A variable the build lacks yields `0` from the boolean calls
and `NULL` from `locate`.

### Allocating memory

Most mods allocate with their own runtime. When memory has to cross the ABI, use
`Forts_AllocatorInterface` so it can be released by the side that owns the
allocator:

```c
Forts_AllocatorInterface* alloc_iface =
    (Forts_AllocatorInterface*)get_iface(CSTR(FORTS_ALLOCATOR_INTERFACE_LAST));

uint8_t* buffer = alloc_iface->alloc(256); // NULL on failure or a size of 0
// ... use buffer ...
alloc_iface->free(buffer, 256);            // pass the size the block has now
```

`alloc` returns byte-aligned memory; `realloc(old, old_size, new_size)` resizes a
block, returning a possibly moved pointer or `NULL` on failure (the original
block is then left intact). A `NULL` `old` allocates a fresh block; a `new_size`
of 0 frees. For a stronger alignment use `alloc_aligned(amount, alignment)` with
a power-of-two `alignment`, and release the result with `free_aligned(ptr,
amount, alignment)` — not with `free`. Blocks are uninitialized; the host keeps
no record of them and does not free them at unload, so release everything before
`Forts_Mod_unload` returns.

### Synchronising shared data between mods

Protocols let one mod call another, but they do not by themselves make two mods
safe to touch the same memory at the same time: each mod has its own runtime, so
they cannot share a mutex. `Forts_SyncInterface` closes that gap. It exposes a
single process-wide reader/writer lock, the same one the loader uses internally,
so any number of mods can coordinate access to data they both agree on:

```c
static Forts_SyncInterface* sync_iface;

// A snapshot of shared state, read under the shared lock.
static void read_shared(SharedState* shared, SharedState* out) {
    sync_iface->read_sync(out, shared, sizeof(*out));
}

// Publish a new value, written under the exclusive lock.
static void write_shared(SharedState* shared, const SharedState* value) {
    sync_iface->write_sync(shared, value, sizeof(*value));
}
```

`read_sync` copies _out of_ shared data under a shared lock, and `write_sync`
copies _into_ it under an exclusive lock; each copy is atomic with respect to the
other, so a reader never observes a half-written value. When the two sides are
more than a copy — for example a multi-step update that must not interleave —
take the lock yourself:

```c
sync_iface->lock_exclusive();
// ... mutate shared state ...
sync_iface->unlock_exclusive();

sync_iface->lock_shared();
// ... read a consistent view of shared state ...
sync_iface->unlock_shared();
```

The lock is **not recursive** and is shared with the loader, so do not take it
twice on one thread and do not call back into another loader interface while
holding it — that interface may need the same lock. Always release it before
`Forts_Mod_unload` returns.

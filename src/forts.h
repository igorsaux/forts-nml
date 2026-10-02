// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: 0BSD
//
// Public ABI between the Forts mod loader (host) and mods.
//
// This header is the only contract a mod has to compile against. It is
// intentionally C-only and POD-only: no C++ name mangling, no STL, no ownership
// transfer across the boundary beyond what is documented here.
//
// The API is thread-safe unless otherwise noted.
//
// ABI stability rules:
//   * An interface struct is frozen once published. New members may only be
//     appended before the trailing `_LAST` macro is repointed; reordering or
//     resizing existing members is a breaking change.
//   * A breaking change gets a new versioned name and typedef, e.g.
//     `Forts_HandleInterface002`. The plain typedef
//     (`Forts_HandleInterface`) and the `FORTS_HANDLE_INTERFACE_LAST` macro
//     always name the newest version.
//   * The struct behind a requested interface name is guaranteed to be **not
//     smaller** than the version that name denotes. Resolving an older name
//     yields the newest struct, which is a byte-compatible superset, so a
//     consumer compiled against an older version may always read the members
//     it knows and ignore the rest.
//   * All functions use the C calling convention (x64: a single platform ABI).
//   * Out-of-contract arguments are not reported gracefully. A pointer that a
//     member documents as required must be non-NULL and valid; passing NULL or
//     a mismatched type is a contract violation, checked with an assertion in
//     debug builds and undefined behaviour in release builds.
//   * A `Forts_CString` returned from an interface points at memory owned by
//     the provider; it stays valid only until the next call that provider
//     documents as invalidating it, and is invalid after the mod unloads.
//
// This header is the reference: it documents the types, their ownership and
// lifetime rules, and the semantics of every member. Working examples and
// walkthroughs live in the project README and under `src/examples/`.

#ifndef FORTS_H
#define FORTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// --------------------------------------------------------------------------- //
// Basic types
// --------------------------------------------------------------------------- //

/// Boolean result of an API call. `0` is false; any non-zero value is true, and
/// members documented to return a boolean return exactly `0` or `1`.
typedef int Forts_Bool;

/// A 16-byte globally unique protocol identifier. The exact same bytes must be
/// used by the provider (when installing) and the consumer (when locating), so
/// pick them once and treat them as a constant.
typedef uint8_t Forts_UUID[16];

/// Non-owning UTF-8 byte range. `ptr` is not required to be NUL-terminated, so
/// always pass `len`; never use `strlen`/`strcmp` on `ptr` directly. `ptr` may
/// be NULL only when `len` is 0.
typedef struct {
    const char* ptr;
    size_t      len;
} Forts_CString;

/// Size and alignment, in bytes, of one field of a game object as described by
/// the build manifest for the running game version. Returned by
/// `Forts_FieldInterface::get_info`.
///
/// `size` is the width of the field's representation: the scalar width, the
/// character count of an inline NUL-terminated string buffer, or the size of a
/// `std::vector` control block. `alignment` is the field's natural alignment.
/// `Forts_FieldInterface::locate` returns the field's address; these two values
/// are what a mod needs to interpret (or overwrite) the bytes there.
typedef struct {
    /// Width of the field in bytes.
    size_t size;
    /// Natural alignment of the field in bytes.
    size_t alignment;
} Forts_FieldInfo;

/// Size and alignment, in bytes, of one global variable as described by the
/// build manifest for the running game version. Returned by
/// `Forts_VariableInterface::get_info`.
///
/// `size` is the width of the variable's representation (the scalar width, the
/// character count of an inline NUL-terminated string buffer, or the size of a
/// `std::vector` control block). `alignment` is the variable's natural
/// alignment. `Forts_VariableInterface::locate` returns the variable's address;
/// these two values are what a mod needs to interpret (or overwrite) the bytes
/// there.
typedef struct {
    /// Width of the variable in bytes.
    size_t size;
    /// Natural alignment of the variable in bytes.
    size_t alignment;
} Forts_VariableInfo;

// Opaque pointers handed across the ABI. They are only meaningful to the code
// that produced them; a mod must not dereference, copy into another type, or
// free any of them.
typedef const void* Forts_Interface;  ///< An interface struct (see below).
typedef const void* Forts_Protocol;   ///< A UUID-prefixed protocol struct.
typedef void*       Forts_Handle;     ///< Opaque per-mod handle.

/// Resolves an interface by name. Returns NULL for an unknown name.
///
/// Names are the version-qualified `FORTS_*_INTERFACE_LAST` strings. The
/// returned pointer is owned by the host and stays valid for the mod's lifetime.
/// `get_iface` itself is handed to the mod in `Forts_Mod_load` and stays valid
/// for the mod's lifetime.
typedef Forts_Interface (*Forts_GetInterface)(Forts_CString name);

// --------------------------------------------------------------------------- //
// Mod entry points
// --------------------------------------------------------------------------- //
// Exported by every mod DLL; loaded by the host with GetProcAddress.
// All three export names are fixed and case-sensitive.

/// Called once on load. `get_iface` stays valid for the mod's lifetime.
/// `mod_handle` is this mod's own opaque handle; pass it back to members of
/// `Forts_HandleInterface`. Register protocols from here.
/// Return 0 on success; any non-zero value aborts loading of this mod.
typedef int  (*Forts_ModLoadFn)(Forts_GetInterface get_iface, Forts_Handle mod_handle);

/// Called once after all mods have loaded. Return 0 on success; any non-zero
/// value aborts initialisation. Because every mod has already loaded, this is
/// the safe place to look up protocols published by other mods.
typedef int  (*Forts_ModInitFn)(void);

/// Called once on unload, before the mod's other interfaces become invalid.
/// Use it to release resources. No return value: failures cannot be reported.
typedef void (*Forts_ModUnloadFn)(void);

#define FORTS_MOD_LOAD_NAME   "Forts_Mod_load"
#define FORTS_MOD_INIT_NAME   "Forts_Mod_init"
#define FORTS_MOD_UNLOAD_NAME "Forts_Mod_unload"

// --------------------------------------------------------------------------- //
// Protocols
// --------------------------------------------------------------------------- //
// A protocol is any struct that begins with a `Forts_UUID` (16 bytes). The UUID
// identifies the protocol; the remaining bytes are its payload, conventionally
// a vtable of function pointers. Two protocols with the same UUID are the same
// protocol, even if their payloads differ.
//
// A provider registers its protocols with
// `Forts_HandleInterface::install_protocols` while handling `Forts_Mod_load`.
// The host keeps only borrowed pointers, so every registered protocol must stay
// alive at a stable address for the mod's lifetime; a `static`/global object is
// the usual choice. A mod may register at most one protocol per UUID, and may
// not register a protocol after the registry has been frozen.
//
// A consumer discovers providers and resolves their protocols in two steps:
//   1. `Forts_RuntimeInterface::locate_protocol` returns the handles of every
//      mod that registered the UUID (as an array plus a count).
//   2. `Forts_HandleInterface::get_protocol` returns the protocol with that
//      UUID from one specific mod handle.
// Step 1 is cross-mod discovery; step 2 is scoped to a single mod.

// --------------------------------------------------------------------------- //
// Interfaces
// --------------------------------------------------------------------------- //
// Every interface is a struct of plain function pointers. Resolve one by its
// version-qualified name with `Forts_GetInterface` and cast the result to the
// matching `Forts_*Interface` typedef.

/// Handle of the calling mod. Provides identity and protocol registration.
typedef struct {
    /// Returns the absolute path to this mod's DLL.
    ///
    /// Result: a UTF-8 path without a trailing separator.
    /// The memory is owned by the host and stays valid until the mod unloads.
    Forts_CString   (*get_path)(Forts_Handle mod);

    /// Publishes protocols belonging to `mod`.
    ///
    /// `protocols` points at `protocol_count` `Forts_Protocol` values; each
    /// entry must be non-NULL and begin with a `Forts_UUID` (16 bytes) that
    /// identifies it. The host keeps a borrowed pointer to each protocol for the
    /// mod's lifetime, so the protocol objects must remain alive and at a stable
    /// address until the mod unloads (a `static`/global is the usual choice).
    ///
    /// This must be called while handling `Forts_Mod_load`. Once every mod has
    /// loaded, the registry is frozen and this returns non-zero.
    /// Returns 0 on success.
    int             (*install_protocols)(Forts_Handle mod, const Forts_Protocol* protocols, size_t protocol_count);

    /// Looks up a protocol by UUID **on the given mod handle**.
    ///
    /// Searches only the protocols registered by `mod`. `uuid` points at the
    /// 16 identifier bytes. Returns the matching `Forts_Protocol`, or NULL if
    /// this mod does not provide it.
    ///
    /// To discover which mods provide a UUID, use
    /// `Forts_RuntimeInterface::locate_protocol` first, then call this once per
    /// returned handle.
    Forts_Protocol  (*get_protocol)(Forts_Handle mod, const Forts_UUID uuid);
} Forts_HandleInterface001;

typedef Forts_HandleInterface001 Forts_HandleInterface;
#define FORTS_HANDLE_INTERFACE_LAST "HandleInterface001"

/// Host debug log (OutputDebugString).
///
/// Useful for development output that is visible to DebugView and debuggers
/// without needing a console.
typedef struct {
    /// Writes `msg` (UTF-8, not NUL-terminated) to the host debug log.
    /// A message with `len == 0` is ignored.
    void (*print)(Forts_CString msg);
} Forts_DebugLogInterface001;

typedef Forts_DebugLogInterface001 Forts_DebugLogInterface;
#define FORTS_DEBUG_LOG_INTERFACE_LAST "DebugLogInterface001"

/// Runtime information and cross-mod protocol discovery.
typedef struct {
    /// Returns the game version in format like "1.38.2-r22447".
    ///
    /// The memory is owned by the host and stays valid until unload.
    Forts_CString   (*get_game_version)(void);

    /// Returns absolute path to the game directory.
    ///
    /// The memory is owned by the host and stays valid until unload.
    Forts_CString   (*get_game_dir)(void);

    /// Finds every mod that published a protocol with `uuid`.
    ///
    /// `uuid` points at the 16 identifier bytes. On return, `*mods` points at
    /// an array of `*mod_count` `Forts_Handle` values owned by the host, or is
    /// NULL with `*mod_count == 0` when no mod provides the UUID. The array is
    /// owned by the host and stays valid until unload; the mod must not free it.
    void            (*locate_protocol)(const Forts_UUID uuid, Forts_Handle** mods, size_t* mod_count);
} Forts_RuntimeInterface001;

typedef Forts_RuntimeInterface001 Forts_RuntimeInterface;
#define FORTS_RUNTIME_INTERFACE_LAST "RuntimeInterface001"

/// Host allocation, so that memory can cross the ABI and be released by the
/// side that owns the allocator.
///
/// Every block returned by a member of this interface is owned by the caller and
/// must be released through the matching member: a block from `alloc`/`realloc`
/// with `free`, and a block from `alloc_aligned` with `free_aligned`. The host
/// keeps no record of outstanding blocks and does not free them when the mod
/// unloads, so a mod must release everything it allocates before it unloads.
///
/// Releasing a block through the wrong member, or with a size or alignment other
/// than the one it was allocated with, is undefined behaviour.
///
/// All members are thread-safe and callable from any thread at any time.
typedef struct {
    /// Allocates `amount` bytes of uninitialized memory.
    ///
    /// The result is only guaranteed to be byte-aligned; use `alloc_aligned`
    /// when a stronger alignment is required. Returns NULL when `amount` is 0
    /// or allocation fails. Release the result with `free(ptr, amount)`.
    uint8_t*    (*alloc)(size_t amount);

    /// Releases a block previously returned by `alloc` or `realloc`.
    ///
    /// `size` must be the size the block currently has (the `amount` passed to
    /// `alloc`, or the `new_size` passed to the last `realloc`). A NULL `ptr` or
    /// a `size` of 0 is a no-op. Otherwise `ptr` must be exactly a block that
    /// `alloc`/`realloc` returned and `size` must be its current size; anything
    /// else, including a block from `alloc_aligned`, is undefined behaviour.
    void        (*free)(uint8_t* ptr, size_t size);

    /// Resizes a block to `new_size` bytes and returns it.
    ///
    /// `old` / `old_size` describe the current block, exactly as passed to
    /// `alloc` or the previous `realloc`. The result may differ from `old`; the
    /// old pointer must not be used afterwards.
    ///
    /// A NULL `old` (with any `old_size`) allocates a fresh `new_size`-byte
    /// block, like `alloc`. A `new_size` of 0 frees the block and returns an
    /// unspecified pointer that must not be dereferenced. Returns NULL only when
    /// allocation fails; the original block is then left intact and remains
    /// owned by the caller.
    uint8_t*    (*realloc)(uint8_t* old, size_t old_size, size_t new_size);

    /// Allocates `amount` bytes aligned to an `alignment`-byte boundary.
    ///
    /// `alignment` must be a non-zero power of two; any other value is rejected
    /// with an assertion in debug builds and is undefined behaviour in release
    /// builds. Returns NULL when `amount` is 0, `alignment` is 0, or allocation
    /// fails. The result must be released with `free_aligned(ptr, amount,
    /// alignment)` using the same `alignment`.
    void*       (*alloc_aligned)(size_t amount, size_t alignment);

    /// Releases a block previously returned by `alloc_aligned`.
    ///
    /// `size` and `alignment` must be exactly the values passed to
    /// `alloc_aligned`. A NULL `ptr`, a `size` of 0, or an `alignment` of 0 is a
    /// no-op. Passing a block from `alloc`/`realloc`, or a size or alignment
    /// other than the one it was allocated with, is undefined behaviour.
    void        (*free_aligned)(void* ptr, size_t size, size_t alignment);

} Forts_AllocatorInterface001;

typedef Forts_AllocatorInterface001 Forts_AllocatorInterface;
#define FORTS_ALLOCATOR_INTERFACE_LAST "AllocatorInterface001"

/// Hooks into the game's own functions.
///
/// The loader patches a fixed set of named game functions at startup; the names
/// and the signature each function has are declared by the build manifest for
/// the running game version. A mod does not patch memory itself: it attaches
/// callbacks to a name and the loader dispatches them.
///
/// For a hooked function, one invocation runs, in order:
///   1. every pre-hook, in the order it was added (mods in load order);
///   2. the replacement, if one was installed with `replace`, otherwise the
///      original implementation;
///   3. every post-hook, in the order it was added.
/// The return value of step 2 becomes the function's result; the return values
/// of pre- and post-hooks are ignored.
///
/// A callback must match the exact signature of its target as declared by the
/// build manifest; calling one with a mismatched signature is undefined
/// behaviour. Callbacks run on whatever thread called the game function, with
/// that call's arguments. The function pointers are borrowed and must stay valid
/// for the mod's lifetime, so a `static`/global function is the usual choice.
///
/// Pre- and post-hooks receive the call's arguments by value: they cannot change
/// them or the function's result. A mod that needs to rewrite arguments or the
/// result must install a `replace` and call the original, obtained from
/// `get_original`, itself. Exposing a stable, version-independent wrapper around
/// such functions is the job of a separate protocol mod, not of this interface.
///
/// Registration is only accepted while the mod is loading or initialising
/// (`Forts_Mod_load` / `Forts_Mod_init`). After every mod has initialised the
/// hook set is frozen and these calls return non-zero. The query members
/// (`has_function`, `is_replaced`, `get_original`) remain valid at any time.
typedef struct {
    /// Returns whether `name` is a game function the loader has hooked in the
    /// running build (and is therefore a valid hook target).
    ///
    /// Returns 1 if hookable, 0 otherwise. This is independent of whether any
    /// mod has attached hooks or installed a replacement. Use it to
    /// feature-detect before registering.
    Forts_Bool (*has_function)(Forts_CString name);

    /// Returns whether a mod has installed a replacement for `name` with
    /// `replace`.
    ///
    /// Returns 1 if replaced, 0 if not replaced or if `name` is unknown.
    Forts_Bool (*is_replaced)(Forts_CString name);

    /// Registers `fn` as a pre-hook of `name`: a callback that runs before the
    /// function's implementation (or replacement) on every call.
    ///
    /// Multiple pre-hooks may be attached to the same function. Returns 0 on
    /// success, non-zero if `name` is unknown, the hook set is frozen, or
    /// registration otherwise fails.
    int (*add_pre_hook)(Forts_CString name, const void* fn);

    /// Registers `fn` as a post-hook of `name`: a callback that runs after the
    /// function's implementation (or replacement) on every call.
    ///
    /// Rules are the same as for `add_pre_hook`. Returns 0 on success, non-zero
    /// on failure.
    int (*add_post_hook)(Forts_CString name, const void* fn);

    /// Replaces the implementation of `name` with `fn`.
    ///
    /// At most one replacement may be installed per function. `fn` runs instead
    /// of the original; to call through, it obtains a pointer to the original
    /// from `get_original` and invokes that with the same signature. Pre- and
    /// post-hooks attached to `name` still run around the replacement. Returns 0
    /// on success, non-zero if `name` is unknown, the hook set is frozen, or the
    /// function is already replaced.
    int (*replace)(Forts_CString name, const void* fn);

    /// Writes a pointer to the original implementation of the hooked function
    /// `name` into `*fn`.
    ///
    /// The written pointer is the unmodified game function (the trampoline).
    /// It may be called with the same signature as `name`, including when a
    /// replacement is installed; this is how a replacement calls through.
    ///
    /// Returns 1 and writes `*fn` on success; returns 0 if `name` is not a
    /// hooked function, in which case `*fn` is left untouched. `fn` must not be
    /// NULL. The pointer is owned by the host and stays valid for the mod's
    /// lifetime.
    Forts_Bool (*get_original)(Forts_CString name, const void** fn);
} Forts_HookInterface001;

typedef Forts_HookInterface001 Forts_HookInterface;
#define FORTS_HOOK_INTERFACE_LAST "HookInterface001"

/// Access to members of the game's own object types by name.
///
/// Field layouts are build-specific and change between game versions, so a mod
/// must not hard-code offsets. Instead the loader carries a per-build map from
/// type and field names to their location, size and alignment; this interface
/// queries that map and resolves a field inside a live object.
///
/// Names are matched exactly (case-sensitive UTF-8). A field that the running
/// build does not expose is reported as absent rather than as an error: check
/// `has_field` first, or treat a `0`/NULL result as "not available". The bytes
/// at the returned address are untyped; interpreting them requires the layout
/// the mod expects for `type_name`.
typedef struct {
    /// Returns whether the running build exposes the field `field_name` of the
    /// object type `type_name`. Returns 1 if present, 0 otherwise.
    Forts_Bool (*has_field)(Forts_CString type_name, Forts_CString field_name);

    /// Writes the size and alignment of a field into `*info`.
    ///
    /// Returns 1 on success and 0 if the field is unknown, in which case `*info`
    /// is left untouched. `info` must not be NULL.
    Forts_Bool (*get_info)(Forts_CString type_name, Forts_CString field_name, Forts_FieldInfo* info);

    /// Returns a pointer to the field inside the object at `this`, or NULL if
    /// the type or field is unknown in the running build.
    ///
    /// `this` must be non-NULL and point to a live object of type `type_name`;
    /// the pointer is not otherwise validated. The returned pointer is an
    /// interior pointer owned by that object and stays valid only while the
    /// object does; the loader neither copies nor retains it. Read or write it
    /// using the `size` and `alignment` reported by `get_info` and the layout the
    /// mod knows for `type_name`.
    void* (*locate)(void* this, Forts_CString type_name, Forts_CString field_name);
} Forts_FieldInterface001;

typedef Forts_FieldInterface001 Forts_FieldInterface;
#define FORTS_FIELD_INTERFACE_LAST "FieldInterface001"

/// Access to the game's global variables by name.
///
/// The global-variable counterpart of `Forts_FieldInterface`: instead of a field
/// inside a live object, each entry names a global variable of the running game
/// build and `locate` returns the address of that variable's storage. Variable
/// locations are build-specific and change between game versions, so a mod must
/// not hard-code their addresses; this interface queries the loader's per-build
/// map by name.
///
/// Names are matched exactly (case-sensitive UTF-8). A variable that the running
/// build does not expose is reported as absent rather than as an error: check
/// `exists` first, or treat a `0`/NULL result as "not available". The bytes at
/// the returned address are untyped; interpreting them requires the layout the
/// mod expects for the variable.
typedef struct {
    /// Returns whether the running build exposes the global variable `name`.
    /// Returns 1 if present, 0 otherwise.
    Forts_Bool (*exists)(Forts_CString name);

    /// Writes the size and alignment of the global variable `name` into `*info`.
    ///
    /// Returns 1 on success and 0 if the variable is unknown, in which case
    /// `*info` is left untouched. `info` must not be NULL.
    Forts_Bool (*get_info)(Forts_CString name, Forts_VariableInfo* info);

    /// Returns a pointer to the storage of the global variable `name`, or NULL
    /// if the variable is unknown in the running build.
    ///
    /// Unlike `Forts_FieldInterface::locate`, no object is involved: the returned
    /// pointer is the address of the variable itself. It is owned by the game
    /// module and stays valid for the process lifetime; the loader neither copies
    /// nor retains it. Read or write it using the `size` and `alignment` reported
    /// by `get_info` and the layout the mod knows for the variable.
    void* (*locate)(Forts_CString name);
} Forts_VariableInterface001;

typedef Forts_VariableInterface001 Forts_VariableInterface;
#define FORTS_VARIABLE_INTERFACE_LAST "VariableInterface001"

/// A process-wide reader/writer lock shared by every mod and by the loader
/// itself.
///
/// The loader serialises access to its own state with a single reader/writer
/// lock and exposes that same lock here. Its other interfaces acquire the lock
/// internally when they touch loader state; this one exists so that mods can
/// synchronise *mod-owned* shared data with each other, which is otherwise
/// impossible since two mods do not share a runtime.
///
/// The lock is a classic reader/writer lock:
///   * any number of readers may hold it at once;
///   * a writer holds it exclusively, so it cannot overlap a reader or another
///     writer.
///
/// It is **not recursive** and is shared with the loader, so two rules apply:
///   * a thread that already holds the lock in any mode must not acquire it
///     again (that deadlocks); pair every `lock_*` with the matching `unlock_*`
///     on the same thread;
///   * do not call back into another loader interface (or wait on anything that
///     might) while holding the lock, because that interface may try to take
///     the same lock.
///
/// All members are callable from any thread at any time. Release every lock
/// before the mod unloads; holding it across `Forts_Mod_unload` can deadlock the
/// loader.
typedef struct {
    /// Acquires the lock for shared (read) access.
    ///
    /// Blocks until no writer holds the lock. Any number of readers may hold it
    /// simultaneously.
    void (*lock_shared)(void);

    /// Releases a shared lock acquired with `lock_shared`.
    ///
    /// Must be called by the thread that acquired it.
    void (*unlock_shared)(void);

    /// Acquires the lock for exclusive (write) access.
    ///
    /// Blocks until every reader and writer has released the lock.
    void (*lock_exclusive)(void);

    /// Releases an exclusive lock acquired with `lock_exclusive`.
    ///
    /// Must be called by the thread that acquired it.
    void (*unlock_exclusive)(void);

    /// Copies `len` bytes from shared data `src` into local `dst` under a single
    /// shared lock.
    ///
    /// Use this to take a consistent snapshot of data another mod may be
    /// mutating: `src` is the shared (possibly contended) buffer, `dst` is the
    /// caller's private copy. Because the whole copy runs under one shared
    /// lock, it cannot overlap a concurrent `write_sync`. `dst` and `src` must
    /// point at valid, non-overlapping buffers of at least `len` bytes; `len`
    /// may be 0.
    void (*read_sync)(void* dst, const void* src, size_t len);

    /// Copies `len` bytes from local `src` into shared data `dst` under a single
    /// exclusive lock.
    ///
    /// The write counterpart of `read_sync`: `dst` is the shared buffer and
    /// `src` is the caller's private data. Because the whole copy runs under one
    /// exclusive lock, no reader can observe a partially written value.
    /// `dst` and `src` must point at valid, non-overlapping buffers of at least
    /// `len` bytes; `len` may be 0.
    void (*write_sync)(void* dst, const void* src, size_t len);
} Forts_SyncInterface001;

typedef Forts_SyncInterface001 Forts_SyncInterface;
#define FORTS_SYNC_INTERFACE_LAST "SyncInterface001"

#ifdef __cplusplus
}
#endif

#endif

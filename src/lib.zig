// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: LGPL-3.0-only

const std = @import("std");
const builtin = @import("builtin");

const api = @import("api.zig");
const root = @import("root.zig");
const utils = @import("utils.zig");
const windows = @import("windows.zig");

const SCOPE = std.log.scoped(.lib);

const HookedFunctions = struct {
    // cast to function and call to get back to the original implementation
    trampoline: []const u8,
    // cast to function and call to get to the our relay
    relay: []const u8,
    replaced_by: ?*const anyopaque = null,
    pre_hooks: std.ArrayList(*const anyopaque) = .empty,
    post_hooks: std.ArrayList(*const anyopaque) = .empty,

    pub inline fn deinit(this: *HookedFunctions, allocator: std.mem.Allocator) void {
        this.pre_hooks.deinit(allocator);
        this.post_hooks.deinit(allocator);
    }
};

const Settings = struct {
    mods: []const []const u8 = &.{},
};

const SETTINGS_NAME = "settings.nml.json";

const ModCallbacks = struct {
    load: *const api.FnModLoad,
    init: *const api.FnModInit,
    unload: *const api.FnModUnload,
};

const Mod = struct {
    arena: std.heap.ArenaAllocator,
    dll_path: []const u8,
    lib_handle: windows.HANDLE,
    callbacks: ModCallbacks,
    protocols: std.ArrayList(api.Protocol) = .empty,

    pub inline fn deinit(this: *Mod, unload: bool) void {
        if (unload) {
            _ = windows.kernel32.FreeLibrary(this.lib_handle);
        }

        this.arena.deinit();
    }
};

const State = struct {
    base: usize,
    manifest: *const root.manifests.Manifest,
    game_dir_path: []const u8,
    game_dir: std.Io.Dir,
    patches_memory: ?[]u8 = null,
    hooked_functions: std.StringHashMapUnmanaged(HookedFunctions) = .empty,
    hooks_frozen: std.atomic.Value(bool) = .init(false),
    settings_arena: std.heap.ArenaAllocator,
    settings: Settings = .{},
    mods: std.ArrayList(*Mod) = .empty,
    protocols_registry: std.AutoHashMapUnmanaged(api.UUID, std.ArrayList(*Mod)) = .empty,
    protocols_frozen: std.atomic.Value(bool) = .init(false),

    pub inline fn init(
        base: usize,
        manifest: *const root.manifests.Manifest,
        exe_dir_path: []u8,
    ) !State {
        const game_dir = std.Io.Dir.openDirAbsolute(root.io(), exe_dir_path, .{
            .iterate = true,
        }) catch |err| {
            SCOPE.err("failed to open the '{s}' directory: {t}", .{ exe_dir_path, err });

            return err;
        };

        return .{
            .base = base,
            .manifest = manifest,
            .game_dir_path = exe_dir_path,
            .game_dir = game_dir,
            .settings_arena = .init(root.allocator()),
        };
    }

    pub inline fn deinit(this: *State, unload: bool) void {
        for (this.mods.items) |m| {
            SCOPE.debug("calling '{s}' on mod '{s}'", .{ api.FnModUnloadName, m.dll_path });
            m.callbacks.unload();
            SCOPE.debug("mod '{s}' unloaded", .{m.dll_path});

            m.deinit(unload);
            root.allocator().destroy(m);
        }

        this.mods.deinit(root.allocator());

        {
            var iter = this.protocols_registry.valueIterator();

            while (iter.next()) |mods| {
                mods.deinit(root.allocator());
            }

            this.protocols_registry.deinit(root.allocator());
        }

        root.allocator().free(this.game_dir_path);

        this.game_dir.close(root.io());

        if (this.patches_memory) |m| {
            _ = windows.kernel32.VirtualFree(m.ptr, 0, windows.MEM_DECOMMIT | windows.MEM_RELEASE);
            this.patches_memory = null;
        }

        {
            var iter = this.hooked_functions.valueIterator();

            while (iter.next()) |hf| {
                hf.deinit(root.allocator());
            }

            this.hooked_functions.deinit(root.allocator());
        }

        this.settings_arena.deinit();
    }

    pub fn patchFunctions(this: *State) !void {
        // TODO: better
        var threads: std.ArrayList(windows.Thread) = .empty;
        defer {
            for (threads.items) |t| {
                t.close();
            }

            threads.deinit(root.allocator());
        }

        // fetch all the threads
        {
            const pid = windows.kernel32.GetCurrentProcessId();
            const tid = windows.kernel32.GetCurrentThreadId();

            const snapshot = windows.kernel32.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0);
            defer _ = windows.kernel32.CloseHandle(snapshot);

            var entry: windows.THREADENTRY32 = .{};
            if (windows.kernel32.Thread32First(snapshot, &entry) == .FALSE) {
                SCOPE.err("failed to get the first thread entry: {}", .{windows.kernel32.GetLastError()});

                return error.Windows;
            }

            if (entry.th32OwnerProcessID == pid and entry.th32ThreadID != tid) {
                const handle = windows.kernel32.OpenThread(windows.THREAD_SUSPEND_RESUME, .FALSE, entry.th32ThreadID) orelse {
                    SCOPE.err("failed to open a thread: {}", .{windows.kernel32.GetLastError()});

                    return error.Windows;
                };

                threads.append(root.allocator(), .{
                    .id = entry.th32ThreadID,
                    .handle = handle,
                }) catch |err| {
                    SCOPE.err("failed to append a thread id: {t}", .{err});

                    return err;
                };
            }

            while (windows.kernel32.Thread32Next(snapshot, &entry) != .FALSE) {
                if (entry.th32OwnerProcessID != pid) {
                    continue;
                }

                if (entry.th32ThreadID == tid) {
                    continue;
                }

                const handle = windows.kernel32.OpenThread(windows.THREAD_SUSPEND_RESUME, .FALSE, entry.th32ThreadID) orelse {
                    SCOPE.err("failed to open a thread: {}", .{windows.kernel32.GetLastError()});

                    return error.Windows;
                };

                threads.append(root.allocator(), .{
                    .id = entry.th32ThreadID,
                    .handle = handle,
                }) catch |err| {
                    SCOPE.err("failed to append a thread id: {t}", .{err});

                    return err;
                };
            }
        }

        SCOPE.debug("suspending the threads", .{});

        for (threads.items) |t| {
            t.susp();
        }
        defer for (threads.items) |t| {
            t.resum();
        };

        // wait for suspend
        windows.kernel32.Sleep(1000);

        var system_info: windows.SYSTEM_INFO = undefined;
        windows.kernel32.GetSystemInfo(&system_info);

        // find memory for the paches
        {
            const memory_size = blk: {
                var total_size: usize = 0;

                for (this.manifest.functions) |f| {
                    total_size += f.patch.len + 14 * 2;
                }

                break :blk std.mem.Alignment
                    .fromByteUnits(system_info.dwPageSize)
                    .forward(total_size);
            };

            SCOPE.debug("required size for the memory: {}", .{memory_size});

            var cursor: usize = this.base -| 0x70000000;

            while (true) {
                const ptr = windows.kernel32.VirtualAlloc(
                    @ptrFromInt(cursor),
                    memory_size,
                    windows.MEM_RESERVE | windows.MEM_COMMIT,
                    windows.PAGE_EXECUTE_READWRITE,
                );

                if (ptr == null) {
                    cursor += system_info.dwAllocationGranularity;

                    if (cursor > this.base +| 0x70000000) {
                        SCOPE.err("failed to find a memory within 2GB", .{});

                        return error.Windows;
                    }

                    continue;
                }

                SCOPE.debug("allocated a memory region with base 0x{x}", .{@intFromPtr(ptr.?)});
                this.patches_memory = @as([*]u8, @ptrCast(ptr.?))[0..memory_size];

                break;
            }
        }

        // patch the functions
        {
            var mem_cursor: [*]u8 = this.patches_memory.?.ptr;

            for (this.manifest.functions) |f| {
                if (!f.patch.relocatable) {
                    SCOPE.warn("function '{s}' is not a relocatable, skipping", .{f.name});

                    continue;
                }

                const prologue = @as([*]const u8, @ptrFromInt(this.base + f.rva))[0..f.prologue.len];

                if (!std.mem.eql(u8, f.prologue, prologue)) {
                    SCOPE.warn("function '{s}' has a modified prologue, skipping", .{f.name});

                    continue;
                }

                // TODO: add support
                if (f.patch.relocs.len != 0) {
                    SCOPE.warn("function '{s}' has relocations, skipping", .{f.name});

                    continue;
                }

                const fn_ptr = this.manifest.relays.get(f.name) orelse {
                    SCOPE.warn("function '{s}' is not implemented, skipping", .{f.name});

                    continue;
                };

                const trampoline = blk: {
                    var writer: std.Io.Writer = .fixed(mem_cursor[0..(f.patch.original.len + 14)]);

                    writer.writeAll(f.patch.original) catch unreachable;
                    writer.writeAll(&.{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }) catch unreachable;
                    writer.writeInt(usize, this.base + f.patch.resume_rva, .native) catch unreachable;

                    break :blk mem_cursor[0..writer.end];
                };

                mem_cursor += trampoline.len;

                const relay = blk: {
                    var writer: std.Io.Writer = .fixed(mem_cursor[0..14]);

                    writer.writeAll(&.{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }) catch unreachable;
                    writer.writeInt(usize, @intFromPtr(fn_ptr), .native) catch unreachable;

                    break :blk mem_cursor[0..writer.end];
                };

                mem_cursor += relay.len;

                SCOPE.debug("function '{s}' trampoline: 0x{x}, relay: 0x{x}, detour: 0x{x}", .{
                    f.name,
                    @intFromPtr(trampoline.ptr),
                    @intFromPtr(relay.ptr),
                    @intFromPtr(fn_ptr),
                });

                this.hooked_functions.put(root.allocator(), f.name, .{
                    .trampoline = trampoline,
                    .relay = relay,
                }) catch |err| {
                    SCOPE.err("failed to save a function patch: {t}", .{err});

                    return err;
                };

                const Page = struct {
                    address: *anyopaque,
                    old_protect: windows.DWORD = 0,
                };

                const target_cursor: [*]u8 = @ptrFromInt(this.base + f.rva);
                var pages = [2]Page{
                    .{
                        .address = @ptrFromInt(std.mem.Alignment
                            .fromByteUnits(system_info.dwPageSize)
                            .backward(@intFromPtr(target_cursor))),
                    },
                    .{
                        .address = @ptrFromInt(std.mem.Alignment
                            .fromByteUnits(system_info.dwPageSize)
                            .forward(@intFromPtr(target_cursor))),
                    },
                };

                for (&pages) |*p| {
                    if (windows.kernel32.VirtualProtect(
                        p.address,
                        system_info.dwPageSize,
                        windows.PAGE_EXECUTE_READWRITE,
                        &p.old_protect,
                    ) == .FALSE) {
                        SCOPE.err("failed to change memory protection of page 0x{x}: {}", .{
                            @intFromPtr(p.address),
                            windows.kernel32.GetLastError(),
                        });

                        return error.Windows;
                    }
                }

                var buffer: [512]u8 = undefined;
                var writer: std.Io.Writer = .fixed(&buffer);

                const target: [*]u8 = @ptrFromInt(this.base + f.rva);
                const relay_va: i64 = @intCast(@intFromPtr(relay.ptr));
                const target_va: i64 = @intCast(@intFromPtr(target) + 5);

                writer.writeByte(0xE9) catch unreachable;
                writer.writeInt(i32, @intCast(relay_va - target_va), .native) catch unreachable;

                while (writer.end < f.patch.len) {
                    writer.writeByte(0x90) catch unreachable;
                }

                @memcpy(target, writer.buffer[0..writer.end]);

                for (&pages) |*p| {
                    _ = windows.kernel32.VirtualProtect(
                        p.address,
                        system_info.dwPageSize,
                        p.old_protect,
                        &p.old_protect,
                    );
                }

                _ = windows.kernel32.FlushInstructionCache(windows.kernel32.GetCurrentProcess(), target, f.patch.len);

                SCOPE.debug("function '{s}' was patched", .{f.name});
            }
        }

        {
            var old: windows.DWORD = undefined;

            _ = windows.kernel32.VirtualProtect(
                this.patches_memory.?.ptr,
                this.patches_memory.?.len,
                windows.PAGE_EXECUTE_READ,
                &old,
            );
        }
    }

    pub fn loadSettings(this: *State) !void {
        const file = this.game_dir.createFile(root.io(), SETTINGS_NAME, .{
            .read = true,
            .truncate = false,
        }) catch |err| {
            SCOPE.err("failed to open the settings file: {t}", .{err});

            return err;
        };
        defer file.close(root.io());

        var reader_buffer: [std.math.pow(usize, 2, 12)]u8 = undefined;
        var file_reader = file.reader(root.io(), &reader_buffer);

        const file_size = file_reader.getSize() catch |err| {
            SCOPE.err("failed to get the size of the settings file: {t}", .{err});

            return err;
        };

        this.settings = .{};
        _ = this.settings_arena.reset(.retain_capacity);

        const content = file_reader.interface.readAlloc(this.settings_arena.allocator(), file_size) catch |err| {
            SCOPE.err("failed to read the settings file: {t}", .{err});

            return err;
        };

        if (std.mem.trim(u8, content, " \t\n\r").len == 0) {
            SCOPE.debug("no settings found, saving the default one", .{});

            var writer_buffer: [std.math.pow(usize, 2, 12)]u8 = undefined;
            var file_writer = file.writer(root.io(), &writer_buffer);

            std.json.fmt(this.settings, .{ .whitespace = .indent_2 }).format(&file_writer.interface) catch |err| {
                SCOPE.err("failed to serialize the default settings to the file: {t}", .{err});

                return err;
            };
            file_writer.flush() catch |err| {
                SCOPE.err("failed to flush the settings file: {t}", .{err});

                return err;
            };

            return;
        }

        this.settings = std.json.parseFromSliceLeaky(Settings, this.settings_arena.allocator(), content, .{}) catch |err| {
            SCOPE.err("failed to parse the settings: {t}", .{err});

            return err;
        };
    }

    pub fn loadMods(this: *State) !void {
        errdefer {
            for (this.mods.items) |m| {
                SCOPE.debug("calling '{s}' on mod '{s}'", .{ api.FnModUnloadName, m.dll_path });
                m.callbacks.unload();
                SCOPE.debug("mod '{s}' unloaded", .{m.dll_path});

                m.deinit(true);
                root.allocator().destroy(m);
            }

            this.mods.clearRetainingCapacity();

            {
                var iter = this.protocols_registry.valueIterator();

                while (iter.next()) |mods| {
                    mods.deinit(root.allocator());
                }

                this.protocols_registry.clearRetainingCapacity();
            }
        }

        for (this.settings.mods) |relative_path| {
            SCOPE.debug("loading mod '{s}'", .{relative_path});

            var mod_arena: std.heap.ArenaAllocator = .init(root.allocator());
            errdefer mod_arena.deinit();

            const utf8_dll_path = std.fs.path.join(mod_arena.allocator(), &.{
                this.game_dir_path,
                relative_path,
            }) catch |err| {
                SCOPE.err("failed to join mod path: {t}", .{err});

                return err;
            };

            const mod_lib_handle = blk: {
                const utf16_dll_path = std.unicode.utf8ToUtf16LeAllocZ(mod_arena.allocator(), utf8_dll_path) catch |err| {
                    SCOPE.err("failed to convert the mod DLL path to the utf16: {t}", .{err});

                    return err;
                };

                break :blk windows.kernel32.LoadLibraryW(utf16_dll_path) orelse {
                    SCOPE.err("failed to load the mod DLL: {}", .{windows.kernel32.GetLastError()});

                    return error.Windows;
                };
            };
            errdefer _ = windows.kernel32.FreeLibrary(mod_lib_handle);

            const callbacks: ModCallbacks = .{
                .load = @ptrCast(windows.kernel32.GetProcAddress(mod_lib_handle, api.FnModLoadName) orelse {
                    SCOPE.err("mod '{s}' has no '{s}' exported function", .{ utf8_dll_path, api.FnModLoadName });

                    return error.BadMod;
                }),
                .init = @ptrCast(windows.kernel32.GetProcAddress(mod_lib_handle, api.FnModInitName) orelse {
                    SCOPE.err("mod '{s}' has no '{s}' exported function", .{ utf8_dll_path, api.FnModInitName });

                    return error.BadMod;
                }),
                .unload = @ptrCast(windows.kernel32.GetProcAddress(mod_lib_handle, api.FnModUnloadName) orelse {
                    SCOPE.err("mod '{s}' has no '{s}' exported function", .{ utf8_dll_path, api.FnModUnloadName });

                    return error.BadMod;
                }),
            };

            const mod = root.allocator().create(Mod) catch |err| {
                SCOPE.err("failed to allocate a mod handle: {t}", .{err});

                return err;
            };
            errdefer {
                mod.deinit(true);
                root.allocator().destroy(mod);
            }

            mod.* = .{
                .arena = mod_arena,
                .dll_path = utf8_dll_path,
                .lib_handle = mod_lib_handle,
                .callbacks = callbacks,
            };

            SCOPE.debug("calling '{s}' on mod '{s}'", .{ api.FnModLoadName, utf8_dll_path });

            const load_ret = callbacks.load(&getInterface, mod);

            if (load_ret != 0) {
                SCOPE.err("failed to load a mod '{s}': got {} from '{s}'", .{ utf8_dll_path, load_ret, api.FnModLoadName });

                return error.Mod;
            }

            this.mods.append(root.allocator(), mod) catch |err| {
                SCOPE.err("failed to append a mod: {t}", .{err});

                SCOPE.debug("calling '{s}' on mod '{s}'", .{ api.FnModUnloadName, utf8_dll_path });
                callbacks.unload();
                SCOPE.debug("mod '{s}' unloaded", .{utf8_dll_path});

                return err;
            };

            SCOPE.info("mod '{s}' loaded", .{utf8_dll_path});
        }

        state.?.protocols_frozen.store(true, .monotonic);

        for (this.mods.items) |m| {
            SCOPE.debug("calling '{s}' on mod '{s}'", .{ api.FnModInitName, m.dll_path });

            const init_ret = m.callbacks.init();

            if (init_ret != 0) {
                SCOPE.err("failed to init a mod '{s}': got {} from '{s}'", .{ m.dll_path, init_ret, api.FnModInitName });

                return error.Mod;
            }

            SCOPE.debug("mod '{s}' initialized", .{m.dll_path});
        }

        state.?.hooks_frozen.store(true, .monotonic);
    }
};

var lock: std.Io.RwLock = .init;
var state: ?State = null;

inline fn main() !void {
    std.debug.assert(state == null);

    const base = windows.kernel32.GetModuleHandleW(null);
    SCOPE.debug("base: 0x{x}", .{@intFromPtr(base)});

    const manifest, const exe_dir_path = blk: {
        var path_buffer: [windows.MAX_PATH:0]u16 = undefined;

        const path_len = windows.kernel32.GetModuleFileNameW(base, &path_buffer, path_buffer.len);
        const utf16_path = path_buffer[0..path_len];

        const utf8_path = std.unicode.utf16LeToUtf8Alloc(root.allocator(), utf16_path) catch |err| {
            SCOPE.err("failed to get utf8 path of the game: {t}", .{err});

            return err;
        };
        defer root.allocator().free(utf8_path);

        SCOPE.debug("game path: {s}", .{utf8_path});

        const Hash = std.crypto.hash.sha2.Sha256;
        var exe_hash_hex: [Hash.digest_length * 2]u8 = undefined;

        // get the hash of the executable file
        {
            var exe_file = std.Io.Dir.cwd().openFile(root.io(), utf8_path, .{}) catch |err| {
                SCOPE.err("failed to open the game executable: {t}", .{err});

                return err;
            };
            defer exe_file.close(root.io());

            var buffer: [std.math.pow(usize, 2, 14)]u8 = undefined;
            var file_reader = exe_file.reader(root.io(), &buffer);
            var reader = &file_reader.interface;

            var hasher: Hash = .init(.{});

            loop: while (true) {
                reader.fillMore() catch |err| switch (err) {
                    std.Io.Reader.Error.EndOfStream => break :loop,
                    else => {
                        SCOPE.err("failed to read the game executable: {t}", .{err});

                        return err;
                    },
                };

                hasher.update(reader.buffer[0..reader.end]);
                reader.end = 0;
            }

            var exe_hash: [Hash.digest_length]u8 = undefined;
            hasher.final(&exe_hash);

            _ = std.fmt.bufPrint(&exe_hash_hex, "{x}", .{exe_hash}) catch unreachable;
        }

        SCOPE.debug("exe hash: {s}", .{&exe_hash_hex});

        const manifest = root.manifests.selectByHash(&exe_hash_hex) orelse {
            SCOPE.err("the game version is not supported", .{});

            return error.Unsupported;
        };

        const exe_dir = root.allocator().dupe(u8, std.fs.path.dirname(utf8_path) orelse unreachable) catch |err| {
            SCOPE.err("failed to dupe the exe dir path: {t}", .{err});

            return err;
        };

        break :blk .{ manifest, exe_dir };
    };

    SCOPE.debug("game version: {s}", .{manifest.build.version});
    SCOPE.debug("exe dir: '{s}'", .{exe_dir_path});

    state = State.init(@intFromPtr(base), manifest, exe_dir_path) catch |err| {
        SCOPE.err("failed to initialize the state: {t}", .{err});

        return err;
    };
    errdefer {
        state.?.deinit(true);
        state = null;
    }

    state.?.loadSettings() catch |err| {
        SCOPE.err("failed to load settings: {t}", .{err});

        return err;
    };

    state.?.patchFunctions() catch |err| {
        SCOPE.err("failed to patch the functions: {t}", .{err});

        return err;
    };

    state.?.loadMods() catch |err| {
        SCOPE.err("failed to load mods: {t}", .{err});

        return err;
    };
}

fn mainWrapper() void {
    main() catch |err| {
        std.debug.panic("failed to initialize the library: {t}", .{err});
    };
}

pub inline fn start() !void {
    if (state != null) {
        return;
    }

    const t = std.Thread.spawn(.{
        .allocator = root.allocator(),
    }, mainWrapper, .{}) catch |err| {
        SCOPE.err("failed to spawn the thread: {t}", .{err});

        return err;
    };
    t.detach();
}

pub inline fn deinit(unload: bool) void {
    lock.lockUncancelable(root.io());
    defer lock.unlock(root.io());

    if (state) |*s| {
        s.deinit(unload);
        state = null;

        SCOPE.debug("the library was unloaded", .{});
    }
}

/// called by the generated code
pub inline fn callHooks(name: []const u8, comptime F: anytype, args: anytype) utils.returnTypeOf(F) {
    lock.lockSharedUncancelable(root.io());

    std.debug.assert(state != null);

    const func = state.?.hooked_functions.get(name) orelse {
        std.debug.panic("original function '{s}' not found", .{name});
    };

    // do not call custom hooks until they are frozen
    if (!state.?.hooks_frozen.load(.monotonic)) {
        const original: *const F = @ptrCast(func.trampoline.ptr);
        lock.unlockShared(root.io());

        return @call(.auto, original, args);
    }

    lock.unlockShared(root.io());

    for (func.pre_hooks.items) |h| {
        _ = @call(.auto, @as(*const F, @ptrCast(h)), args);
    }

    const ret = if (func.replaced_by) |f|
        @call(.auto, @as(*const F, @ptrCast(f)), args)
    else
        @call(.auto, @as(*const F, @ptrCast(func.trampoline.ptr)), args);

    for (func.post_hooks.items) |h| {
        _ = @call(.auto, @as(*const F, @ptrCast(h)), args);
    }

    return ret;
}

// === INTERFACES ===

const INTERFACES: std.StaticStringMap(api.Interface) = .initComptime(&.{
    .{ api.HANDLE_INTERFACE_LAST, &HANDLE_INTERFACE_001 },
    .{ api.DEBUG_LOG_INTERFACE_LAST, &DEBUG_LOG_INTERFACE_001 },
    .{ api.RUNTIME_INTERFACE_LAST, &RUNTIME_INTERFACE_001 },
    .{ api.ALLOCATOR_INTERFACE_LAST, &ALLOCATOR_INTERFACE_001 },
    .{ api.HOOK_INTERFACE_LAST, &HOOK_INTERFACE_001 },
    .{ api.FIELD_INTERFACE_LAST, &FIELD_INTERFACE_001 },
    .{ api.VARIABLE_INTERFACE_LAST, &VARIABLE_INTERFACE_001 },
    .{ api.SYNC_INTERFACE_LAST, &SYNC_INTERFACE_001 },
});

pub fn getInterface(name: api.CString) callconv(.c) api.Interface {
    if (INTERFACES.get(api.cstringSlice(name))) |iface| {
        return iface;
    }

    return null;
}

const HandleInterface = struct {
    fn getPath001(handle: api.Handle) callconv(.c) api.CString {
        // constant, no lock
        std.debug.assert(handle != null);

        const mod: *Mod = @ptrCast(@alignCast(handle.?));

        return api.cstringFrom(mod.dll_path);
    }

    fn installProtocols001(
        handle: api.Handle,
        protocols: ?[*]const api.Protocol,
        protocol_count: usize,
    ) callconv(.c) c_int {
        lock.lockUncancelable(root.io());
        defer lock.unlock(root.io());

        std.debug.assert(handle != null);

        const mod: *Mod = @ptrCast(@alignCast(handle.?));

        if (protocol_count == 0) {
            return 0;
        }

        std.debug.assert(protocols != null);

        const protocols_slice = protocols.?[0..protocol_count];

        std.debug.assert(state != null);

        if (state.?.protocols_frozen.load(.monotonic)) {
            SCOPE.err("trying to install protocols after they are frozen", .{});

            return -1;
        }

        for (protocols_slice, 0..) |protocol, i| {
            std.debug.assert(protocol != null);

            const header: *const api.ProtocolHeader = @ptrCast(@alignCast(protocol));

            for (mod.protocols.items) |installed| {
                const installed_header: *const api.ProtocolHeader = @ptrCast(@alignCast(installed));

                if (std.mem.eql(u8, &header.uuid, &installed_header.uuid)) {
                    SCOPE.err("trying to install a protocol that is already installed", .{});

                    return -1;
                }
            }

            for (protocols_slice[i + 1 ..]) |duplicate| {
                std.debug.assert(duplicate != null);

                const duplicate_header: *const api.ProtocolHeader = @ptrCast(@alignCast(duplicate));

                if (std.mem.eql(u8, &header.uuid, &duplicate_header.uuid)) {
                    SCOPE.err("trying to install the same protocol twice in one call", .{});

                    return -1;
                }
            }
        }

        mod.protocols.appendSlice(mod.arena.allocator(), protocols_slice) catch |err| {
            std.debug.panic("failed to append the protocols: {t}", .{err});
        };

        for (protocols_slice) |p| {
            std.debug.assert(p != null);

            const header: *const api.ProtocolHeader = @ptrCast(@alignCast(p));

            if (state.?.protocols_registry.getPtr(header.uuid)) |array| {
                if (std.mem.findScalar(*Mod, array.items, mod) == null) {
                    array.append(root.allocator(), mod) catch |err| {
                        std.debug.panic("failed to append a mod to the protocols registry: {t}", .{err});
                    };
                }
            } else {
                var array: std.ArrayList(*Mod) = .empty;
                array.append(root.allocator(), mod) catch |err| {
                    std.debug.panic("failed to append a mod to the protocols registry: {t}", .{err});
                };

                state.?.protocols_registry.put(root.allocator(), header.uuid, array) catch |err| {
                    std.debug.panic("failed to append a protocol to the registry: {t}", .{err});
                };
            }
        }

        return 0;
    }

    fn getProtocol001(
        handle: api.Handle,
        uuid: ?[*]const u8,
    ) callconv(.c) api.Protocol {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(handle != null);
        std.debug.assert(uuid != null);

        const mod: *Mod = @ptrCast(@alignCast(handle.?));

        for (mod.protocols.items) |p| {
            const header: *const api.ProtocolHeader = @ptrCast(@alignCast(p));

            if (std.mem.eql(u8, &header.uuid, uuid.?[0..16])) {
                return p;
            }
        }

        return null;
    }
};

const HANDLE_INTERFACE_001: api.HandleInterface001 = .{
    .get_path = &HandleInterface.getPath001,
    .install_protocols = &HandleInterface.installProtocols001,
    .get_protocol = &HandleInterface.getProtocol001,
};

const DebugLogInterface = struct {
    fn print001(msg: api.CString) callconv(.c) void {
        // thread safe, no lock
        std.debug.assert(msg.ptr != null);

        if (msg.len == 0) {
            return;
        }

        windows.outputDebugString(api.cstringSlice(msg));
    }
};

const DEBUG_LOG_INTERFACE_001: api.DebugLogInterface001 = .{
    .print = &DebugLogInterface.print001,
};

const RuntimeInterface = struct {
    fn getGameVersion001() callconv(.c) api.CString {
        // constant, no lock
        std.debug.assert(state != null);

        return api.cstringFrom(state.?.manifest.build.version);
    }

    fn getGameDir001() callconv(.c) api.CString {
        // constant, no lock
        std.debug.assert(state != null);

        return api.cstringFrom(state.?.game_dir_path);
    }

    fn locateProtocol001(uuid: ?[*]const u8, mods: ?*?[*]api.Handle, mod_count: ?*usize) callconv(.c) void {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(uuid != null);
        std.debug.assert(state != null);
        std.debug.assert(mods != null);
        std.debug.assert(mod_count != null);

        if (state.?.protocols_registry.getPtr(uuid.?[0..16].*)) |array| {
            mods.?.* = @ptrCast(array.items.ptr);
            mod_count.?.* = array.items.len;

            return;
        }

        mods.?.* = null;
        mod_count.?.* = 0;
    }
};

const RUNTIME_INTERFACE_001: api.RuntimeInterface001 = .{
    .get_game_version = &RuntimeInterface.getGameVersion001,
    .get_game_dir = &RuntimeInterface.getGameDir001,
    .locate_protocol = &RuntimeInterface.locateProtocol001,
};

const AllocatorInterface = struct {
    fn alloc001(amount: usize) callconv(.c) ?[*]u8 {
        // thread safe, no lock
        if (amount == 0) {
            return null;
        }

        const slice = root.allocator().alloc(u8, amount) catch {
            return null;
        };

        return slice.ptr;
    }

    fn free001(ptr: ?[*]u8, size: usize) callconv(.c) void {
        // thread safe, no lock
        if (ptr == null) {
            return;
        }

        if (size == 0) {
            return;
        }

        root.allocator().free(ptr.?[0..size]);
    }

    fn realloc001(old: ?[*]u8, old_size: usize, new_size: usize) callconv(.c) ?[*]u8 {
        // thread safe, no lock
        const try_slice = if (old == null)
            root.allocator().realloc(@as([]u8, &.{}), new_size)
        else
            root.allocator().realloc(old.?[0..old_size], new_size);

        const slice = try_slice catch {
            return null;
        };

        return slice.ptr;
    }

    fn allocAligned001(amount: usize, alignment: usize) callconv(.c) ?*anyopaque {
        // thread safe, no lock
        if (amount == 0) {
            return null;
        }

        if (alignment == 0) {
            return null;
        }

        const ptr = root.allocator().rawAlloc(
            amount,
            std.mem.Alignment.fromByteUnits(alignment),
            @returnAddress(),
        ) orelse {
            return null;
        };

        return ptr;
    }

    fn freeAligned001(ptr: ?*anyopaque, size: usize, alignment: usize) callconv(.c) void {
        // thread safe, no lock
        if (ptr == null) {
            return;
        }

        if (size == 0) {
            return;
        }

        if (alignment == 0) {
            return;
        }

        root.allocator().rawFree(
            @as([*]u8, @ptrCast(ptr.?))[0..size],
            std.mem.Alignment.fromByteUnits(alignment),
            @returnAddress(),
        );
    }
};

const ALLOCATOR_INTERFACE_001: api.AllocatorInterface001 = .{
    .alloc = &AllocatorInterface.alloc001,
    .free = &AllocatorInterface.free001,
    .realloc = &AllocatorInterface.realloc001,
    .alloc_aligned = &AllocatorInterface.allocAligned001,
    .free_aligned = &AllocatorInterface.freeAligned001,
};

const HookInterface = struct {
    fn hasFunction001(name: api.CString) callconv(.c) api.Bool {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(name.ptr != null);

        std.debug.assert(state != null);

        if (state.?.hooked_functions.get(name.ptr[0..name.len]) == null) {
            return 0;
        }

        return 1;
    }

    fn isReplaced001(name: api.CString) callconv(.c) api.Bool {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(name.ptr != null);

        std.debug.assert(state != null);

        if (state.?.hooked_functions.getPtr(name.ptr[0..name.len])) |hf| {
            if (hf.replaced_by != null) {
                return 1;
            }

            return 0;
        }

        return 0;
    }

    fn addPreHook001(name: api.CString, func: ?*const anyopaque) callconv(.c) c_int {
        lock.lockUncancelable(root.io());
        defer lock.unlock(root.io());

        std.debug.assert(name.ptr != null);
        std.debug.assert(func != null);

        std.debug.assert(state != null);

        const name_slice = api.cstringSlice(name);

        if (state.?.hooks_frozen.load(.monotonic)) {
            SCOPE.err("trying to add a pre-hook on '{s}' after they are frozen", .{name_slice});

            return -1;
        }

        if (state.?.hooked_functions.getPtr(name_slice)) |hf| {
            hf.pre_hooks.append(root.allocator(), func.?) catch |err| {
                std.debug.panic("failed to add a pre-hook on '{s}': {t}", .{ name_slice, err });
            };

            return 0;
        }

        SCOPE.err("trying to add a pre-hook on an unknown function '{s}'", .{name_slice});

        return -1;
    }

    fn addPostHook001(name: api.CString, func: ?*const anyopaque) callconv(.c) c_int {
        lock.lockUncancelable(root.io());
        defer lock.unlock(root.io());

        std.debug.assert(name.ptr != null);
        std.debug.assert(func != null);

        std.debug.assert(state != null);

        const name_slice = api.cstringSlice(name);

        if (state.?.hooks_frozen.load(.monotonic)) {
            SCOPE.err("trying to add a post-hook on '{s}' after they are frozen", .{name_slice});

            return -1;
        }

        if (state.?.hooked_functions.getPtr(name_slice)) |hf| {
            hf.post_hooks.append(root.allocator(), func.?) catch |err| {
                std.debug.panic("failed to add a post hook on '{s}': {t}", .{ name_slice, err });
            };

            return 0;
        }

        SCOPE.err("trying to add a post-hook on an unknown function '{s}'", .{name_slice});

        return -1;
    }

    fn replace001(name: api.CString, func: ?*const anyopaque) callconv(.c) c_int {
        lock.lockUncancelable(root.io());
        defer lock.unlock(root.io());

        std.debug.assert(name.ptr != null);
        std.debug.assert(func != null);

        std.debug.assert(state != null);

        const name_slice = api.cstringSlice(name);

        if (state.?.hooks_frozen.load(.monotonic)) {
            SCOPE.err("trying to replace a function '{s}' after they are frozen", .{name_slice});

            return -1;
        }

        if (state.?.hooked_functions.getPtr(name_slice)) |hf| {
            if (hf.replaced_by != null) {
                SCOPE.err("function '{s}' is already replaced", .{name_slice});

                return -1;
            }

            hf.replaced_by = func.?;

            return 0;
        }

        SCOPE.err("trying to replace an unknown function '{s}'", .{name_slice});

        return -1;
    }

    fn getOriginal001(name: api.CString, func: ?*?*const anyopaque) callconv(.c) api.Bool {
        lock.lockUncancelable(root.io());
        defer lock.unlock(root.io());

        std.debug.assert(name.ptr != null);
        std.debug.assert(func != null);

        std.debug.assert(state != null);

        if (state.?.hooked_functions.getPtr(api.cstringSlice(name))) |hf| {
            func.?.* = hf.trampoline.ptr;

            return 1;
        }

        return 0;
    }
};

const HOOK_INTERFACE_001: api.HookInterface001 = .{
    .has_function = &HookInterface.hasFunction001,
    .is_replaced = &HookInterface.isReplaced001,
    .add_pre_hook = &HookInterface.addPreHook001,
    .add_post_hook = &HookInterface.addPostHook001,
    .replace = &HookInterface.replace001,
    .get_original = &HookInterface.getOriginal001,
};

const FieldInterface = struct {
    fn hasField001(type_name: api.CString, field_name: api.CString) callconv(.c) api.Bool {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(type_name.ptr != null);
        std.debug.assert(field_name.ptr != null);

        std.debug.assert(state != null);

        if (state.?.manifest.accessors.get(api.cstringSlice(type_name))) |type_acc| {
            if (type_acc.get(api.cstringSlice(field_name)) != null) {
                return 1;
            }
        }

        return 0;
    }

    fn getInfo001(type_name: api.CString, field_name: api.CString, info: ?*api.FieldInfo) callconv(.c) api.Bool {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(type_name.ptr != null);
        std.debug.assert(field_name.ptr != null);
        std.debug.assert(info != null);

        std.debug.assert(state != null);

        if (state.?.manifest.accessors.get(api.cstringSlice(type_name))) |type_acc| {
            if (type_acc.get(api.cstringSlice(field_name))) |field_acc| {
                info.?.* = .{
                    .size = field_acc.size,
                    .alignment = field_acc.alignment,
                };

                return 1;
            }
        }

        return 0;
    }

    fn locate001(this: ?*anyopaque, type_name: api.CString, field_name: api.CString) callconv(.c) ?*anyopaque {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(this != null);
        std.debug.assert(type_name.ptr != null);
        std.debug.assert(field_name.ptr != null);

        std.debug.assert(state != null);

        if (state.?.manifest.accessors.get(api.cstringSlice(type_name))) |type_acc| {
            if (type_acc.get(api.cstringSlice(field_name))) |field_acc| {
                return field_acc.locate(this.?);
            }
        }

        return null;
    }
};

const FIELD_INTERFACE_001: api.FieldInterface001 = .{
    .has_field = &FieldInterface.hasField001,
    .get_info = &FieldInterface.getInfo001,
    .locate = &FieldInterface.locate001,
};

const VariableInterface = struct {
    fn exists001(name: api.CString) callconv(.c) api.Bool {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(name.ptr != null);

        std.debug.assert(state != null);

        if (state.?.manifest.variables.get(api.cstringSlice(name)) != null) {
            return 1;
        }

        return 0;
    }

    fn getInfo001(name: api.CString, info: ?*api.VariableInfo) callconv(.c) api.Bool {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(name.ptr != null);
        std.debug.assert(info != null);

        std.debug.assert(state != null);

        if (state.?.manifest.variables.get(api.cstringSlice(name))) |vi| {
            info.?.* = .{
                .size = vi.size,
                .alignment = vi.alignment,
            };

            return 1;
        }

        return 0;
    }

    fn locate001(name: api.CString) callconv(.c) ?*anyopaque {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(name.ptr != null);

        std.debug.assert(state != null);

        if (state.?.manifest.variables.get(api.cstringSlice(name))) |vi| {
            return @ptrFromInt(state.?.base + vi.rva);
        }

        return null;
    }
};

const VARIABLE_INTERFACE_001: api.VariableInterface001 = .{
    .exists = &VariableInterface.exists001,
    .get_info = &VariableInterface.getInfo001,
    .locate = &VariableInterface.locate001,
};

const SyncInterface = struct {
    fn lockShared001() callconv(.c) void {
        lock.lockSharedUncancelable(root.io());
    }

    fn unlockShared001() callconv(.c) void {
        lock.unlockShared(root.io());
    }

    fn lockExclusive001() callconv(.c) void {
        lock.lockUncancelable(root.io());
    }

    fn unlockExclusive001() callconv(.c) void {
        lock.unlock(root.io());
    }

    fn readSync001(dst: ?*anyopaque, src: ?*const anyopaque, len: usize) callconv(.c) void {
        lock.lockSharedUncancelable(root.io());
        defer lock.unlockShared(root.io());

        std.debug.assert(dst != null);
        std.debug.assert(src != null);

        if (len == 0) {
            return;
        }

        const dst_bytes: [*]u8 = @ptrCast(dst.?);
        const src_bytes: [*]const u8 = @ptrCast(src.?);

        @memcpy(dst_bytes[0..len], src_bytes[0..len]);
    }

    fn writeSync001(dst: ?*anyopaque, src: ?*const anyopaque, len: usize) callconv(.c) void {
        lock.lockUncancelable(root.io());
        defer lock.unlock(root.io());

        std.debug.assert(dst != null);
        std.debug.assert(src != null);

        if (len == 0) {
            return;
        }

        const dst_bytes: [*]u8 = @ptrCast(dst.?);
        const src_bytes: [*]const u8 = @ptrCast(src.?);

        @memcpy(dst_bytes[0..len], src_bytes[0..len]);
    }
};

const SYNC_INTERFACE_001: api.SyncInterface001 = .{
    .lock_shared = &SyncInterface.lockShared001,
    .unlock_shared = &SyncInterface.unlockShared001,
    .lock_exclusive = &SyncInterface.lockExclusive001,
    .unlock_exclusive = &SyncInterface.unlockExclusive001,
    .read_sync = &SyncInterface.readSync001,
    .write_sync = &SyncInterface.writeSync001,
};

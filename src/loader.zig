// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: LGPL-3.0-only

const std = @import("std");

const lib = @import("lib.zig");
const root = @import("root.zig");
const windows = @import("windows.zig");

const SCOPE = std.log.scoped(.loader);

const OriginalLibrary = struct {
    pub const Functions = struct {
        pub const DirectInput8Create = *const fn (
            hinst: windows.HINSTANCE,
            dwVersions: windows.DWORD,
            riidltf: windows.REFIID,
            ppvOut: [*c]windows.LPVOID,
            punkOuter: windows.LPUNKNOWN,
        ) callconv(.winapi) windows.HRESULT;

        direct_input_8_create: Functions.DirectInput8Create,
    };

    handle: windows.HMODULE,
    functions: Functions,

    pub inline fn load() !OriginalLibrary {
        // TODO: better
        const handle = windows.kernel32.LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("C:\\Windows\\System32\\dinput8.dll"));

        if (handle == null) {
            SCOPE.err("failed to load 'dinput8.dll': {}", .{windows.kernel32.GetLastError()});

            return error.Unknown;
        }

        const functions: OriginalLibrary.Functions = .{
            .direct_input_8_create = @ptrCast(windows.kernel32.GetProcAddress(handle, "DirectInput8Create") orelse {
                SCOPE.err("failed to find a symbol 'DirectInput8Create': {}", .{windows.kernel32.GetLastError()});

                return error.Unknown;
            }),
        };

        return .{
            .handle = handle,
            .functions = functions,
        };
    }
};

var mutex: std.Io.Mutex = .init;
var proxied_library: ?OriginalLibrary = null;

pub export fn DirectInput8Create(
    hinst: windows.HINSTANCE,
    dwVersions: windows.DWORD,
    riidltf: windows.REFIID,
    ppvOut: [*c]windows.LPVOID,
    punkOuter: windows.LPUNKNOWN,
) callconv(.winapi) windows.HRESULT {
    if (mutex.tryLock()) {
        defer mutex.unlock(root.io());

        if (proxied_library == null) {
            @branchHint(.cold);

            SCOPE.debug("loading the original library", .{});

            proxied_library = OriginalLibrary.load() catch {
                @panic("failed to load the original library");
            };

            SCOPE.debug("the original library was loaded", .{});
        }

        lib.start() catch |err| {
            std.debug.panic("failed to start the library: {t}", .{err});
        };

        std.debug.assert(proxied_library != null);
    }

    return proxied_library.?.functions.direct_input_8_create(
        hinst,
        dwVersions,
        riidltf,
        ppvOut,
        punkOuter,
    );
}

pub export fn DllMain(
    hinstDll: windows.HINSTANCE,
    fdwReason: windows.DWORD,
    lpReserved: windows.LPVOID,
) callconv(.winapi) windows.BOOL {
    _ = hinstDll;
    _ = lpReserved;

    switch (fdwReason) {
        windows.DLL_PROCESS_DETACH => {
            lib.deinit(false);
            root.resetDebugAllocator();
        },
        else => {},
    }

    return .TRUE;
}

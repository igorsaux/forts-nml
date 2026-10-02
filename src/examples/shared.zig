// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: 0BSD

const std = @import("std");
const root = @import("root");

const forts = @import("forts");

pub var get_iface: forts.Forts_GetInterface = null;
pub var mod_handle: forts.Forts_Handle = null;

pub inline fn getIface(comptime T: anytype, name: []const u8) ?*const T {
    return @ptrCast(@alignCast(get_iface.?(cstr(name))));
}

pub inline fn cstr(string: []const u8) forts.Forts_CString {
    return .{ .ptr = string.ptr, .len = string.len };
}

pub export fn Forts_Mod_load(
    _get_iface: forts.Forts_GetInterface,
    _mod_handle: forts.Forts_Handle,
) callconv(.c) c_int {
    get_iface = _get_iface;
    mod_handle = _mod_handle;

    @call(.auto, @field(root, "onLoad"), .{}) catch {
        return -1;
    };

    return 0;
}

pub export fn Forts_Mod_init() callconv(.c) c_int {
    @call(.auto, @field(root, "onInit"), .{}) catch {
        return -1;
    };

    return 0;
}

pub export fn Forts_Mod_unload() callconv(.c) void {
    @call(.auto, @field(root, "onUnload"), .{}) catch {};
}

pub const LoggerProtocol = extern struct {
    pub const UUID: forts.Forts_UUID = .{ '\x1b', '\x9c', '\x96', '\x64', '\xf3', '\x21', '\x4a', '\x7b', '\xb7', '\x44', '\x4a', '\xbc', '\x68', '\xea', '\x9f', '\x2f' };

    uuid: forts.Forts_UUID = UUID,
    log: *const fn (msg: forts.Forts_CString) callconv(.c) void,
};

pub const DebugLogWriter = struct {
    pub inline fn interface(buffer: []u8) std.Io.Writer {
        return .{
            .buffer = buffer,
            .vtable = &.{
                .drain = drain,
            },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const log_iface = getIface(forts.Forts_DebugLogInterface, forts.FORTS_DEBUG_LOG_INTERFACE_LAST);

        log_iface.?.print.?(cstr(w.buffer[0..w.end]));
        w.end = 0;

        var consumed: usize = 0;

        for (data) |slice| {
            log_iface.?.print.?(cstr(slice));
            consumed += slice.len;
        }

        for (0..splat) |_| {
            const slice = data[data.len - 1];

            log_iface.?.print.?(cstr(data[data.len - 1]));
            consumed += slice.len;
        }

        return consumed;
    }
};

pub fn debugLogFmt(comptime fmt: []const u8, args: anytype) void {
    var buffer: [std.math.pow(usize, 2, 12)]u8 = undefined;
    var writer = DebugLogWriter.interface(&buffer);

    writer.print(fmt, args) catch unreachable;
    writer.flush() catch unreachable;
}

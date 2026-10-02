// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: 0BSD

const std = @import("std");

const forts = @import("forts");

const shared = @import("shared.zig");

const LOGGER_PROTOCOL: shared.LoggerProtocol = .{
    .log = &log,
};

const PROTOCOLS = [_]forts.Forts_Protocol{
    &LOGGER_PROTOCOL,
};

fn log(msg: forts.Forts_CString) callconv(.c) void {
    var buffer: [std.math.pow(usize, 2, 12)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    writer.print("LoggerProtocol: {s}", .{msg.ptr[0..msg.len]}) catch {
        return;
    };

    const debug_log_iface = shared.getIface(forts.Forts_DebugLogInterface, forts.FORTS_DEBUG_LOG_INTERFACE_LAST);
    debug_log_iface.?.print.?(shared.cstr(writer.buffer[0..writer.end]));
}

pub inline fn onLoad() !void {
    const handle_iface = shared.getIface(forts.Forts_HandleInterface, forts.FORTS_HANDLE_INTERFACE_LAST);
    const ret = handle_iface.?.install_protocols.?(shared.mod_handle, &PROTOCOLS, PROTOCOLS.len);

    std.debug.assert(ret == 0);
}

pub inline fn onInit() !void {}

pub inline fn onUnload() !void {}

comptime {
    _ = shared;
}

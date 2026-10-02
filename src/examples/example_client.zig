// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: 0BSD

const std = @import("std");

const forts = @import("forts");

const shared = @import("shared.zig");

pub inline fn onLoad() !void {}

pub inline fn onInit() !void {
    var impls: ?[*]forts.Forts_Handle = null;
    var impl_count: usize = 0;

    const runtime_iface = shared.getIface(forts.Forts_RuntimeInterface, forts.FORTS_RUNTIME_INTERFACE_LAST);
    runtime_iface.?.locate_protocol.?(&shared.LoggerProtocol.UUID, @ptrCast(&impls), &impl_count);

    std.debug.assert(impl_count != 0);

    const handle_iface = shared.getIface(forts.Forts_HandleInterface, forts.FORTS_HANDLE_INTERFACE_LAST);

    const mod_handle = impls.?[0];
    const logger_protocol: ?*const shared.LoggerProtocol = @ptrCast(@alignCast(handle_iface.?.get_protocol.?(mod_handle, &shared.LoggerProtocol.UUID)));

    std.debug.assert(logger_protocol != null);

    logger_protocol.?.log(shared.cstr("Hello, world!"));
}

pub inline fn onUnload() !void {}

comptime {
    _ = shared;
}

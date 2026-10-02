// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: LGPL-3.0-only

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

fn log(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    var buffer: [std.math.pow(usize, 2, 12)]u8 = undefined;
    var writer = windows.DebugOutputWriter.interface(&buffer);

    const level = switch (message_level) {
        .err => "ERR",
        .warn => "WRN",
        .info => "INF",
        .debug => "DBG",
    };

    writer.print(
        "{s} {t}: " ++ format ++ "\n",
        .{ level, scope } ++ args,
    ) catch {};
    writer.flush() catch {};
}

pub const std_options: std.Options = .{
    .logFn = log,
};

pub const panic = std.debug.FullPanic(panicFn);

pub fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
    {
        var buffer: [std.math.pow(usize, 2, 13)]u8 = undefined;
        var writer = windows.DebugOutputWriter.interface(&buffer);

        writer.print("Panic: {s}\n", .{msg}) catch {};
        writer.flush() catch {};
    }

    std.debug.defaultPanic(msg, first_trace_addr);
}

pub inline fn allocator() std.mem.Allocator {
    if (builtin.mode == .Debug) {
        return debug_allocator.allocator();
    }

    return std.heap.smp_allocator;
}

pub inline fn resetDebugAllocator() void {
    _ = debug_allocator.deinit();
    debug_allocator = .init;
}

pub inline fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

const std = @import("std");
const builtin = @import("builtin");

/// called by the generated code
pub const lib = @import("lib.zig");
const loader = @import("loader.zig");
pub const DllMain = loader.DllMain;
pub const manifests = @import("manifests.zig");
const windows = @import("windows.zig");

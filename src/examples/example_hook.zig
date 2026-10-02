// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: 0BSD

const std = @import("std");

const forts = @import("forts");

const shared = @import("shared.zig");

fn onWorldCreated(world: ?*anyopaque, engine: ?*anyopaque, setup: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = engine;

    shared.debugLogFmt("World created", .{});

    if (setup == null) {
        shared.debugLogFmt("setup = null", .{});
    } else {
        const field_iface = shared.getIface(forts.Forts_FieldInterface, forts.FORTS_FIELD_INTERFACE_LAST);

        var field_info: forts.Forts_FieldInfo = undefined;

        if (field_iface.?.get_info.?(shared.cstr("MatchSetup"), shared.cstr("map_path"), &field_info) != 0) {
            const map_path_ptr: [*c]u8 = @ptrCast(field_iface.?.locate.?(setup, shared.cstr("MatchSetup"), shared.cstr("map_path")));

            if (map_path_ptr == null) {
                shared.debugLogFmt("map_path = null", .{});
            } else {
                const map_path = std.mem.span(map_path_ptr);
                shared.debugLogFmt("map_path = '{s}'", .{map_path});
            }
        }
    }

    return world;
}

fn onWorldDestroyed(world: ?*anyopaque) callconv(.c) void {
    _ = world;

    shared.debugLogFmt("World destroyed", .{});
}

var last_sim_frame: u32 = 0;

fn onWorldSimUpdateTick(world_sim: ?*anyopaque) callconv(.c) void {
    if (world_sim == null) {
        return;
    }

    const variable_iface = shared.getIface(forts.Forts_VariableInterface, forts.FORTS_VARIABLE_INTERFACE_LAST);

    const sim_frame_ptr = variable_iface.?.locate.?(shared.cstr("SimFrame")) orelse {
        return;
    };

    const sim_frame = std.mem.readInt(u32, @as([*]u8, @ptrCast(sim_frame_ptr))[0..4], .native);

    if (sim_frame == last_sim_frame) {
        return;
    }

    last_sim_frame = sim_frame;
    shared.debugLogFmt("Sim Frame: {}", .{sim_frame});
}

pub inline fn onLoad() !void {}

pub inline fn onInit() !void {
    const hook_iface = shared.getIface(forts.Forts_HookInterface, forts.FORTS_HOOK_INTERFACE_LAST);

    var ret = hook_iface.?.add_pre_hook.?(shared.cstr("World_ctor"), &onWorldCreated);
    std.debug.assert(ret == 0);

    ret = hook_iface.?.add_post_hook.?(shared.cstr("World_dtor"), &onWorldDestroyed);
    std.debug.assert(ret == 0);

    ret = hook_iface.?.add_post_hook.?(shared.cstr("World_Sim_Update_Tick"), &onWorldSimUpdateTick);
    std.debug.assert(ret == 0);
}

pub inline fn onUnload() !void {}

comptime {
    _ = shared;
}

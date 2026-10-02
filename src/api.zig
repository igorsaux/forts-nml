// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: LGPL-3.0-only

const forts = @import("forts");

pub const Bool = forts.Forts_Bool;
pub const FieldInfo = forts.Forts_FieldInfo;
pub const VariableInfo = forts.Forts_VariableInfo;
pub const CString = forts.Forts_CString;
pub const Handle = forts.Forts_Handle;
pub const Interface = forts.Forts_Interface;
pub const Protocol = forts.Forts_Protocol;
pub const UUID = forts.Forts_UUID;

pub const ProtocolHeader = extern struct {
    uuid: UUID,
};

/// `translate-c` lowers C function-pointer typedefs to `?*const fn(...)`.
/// Extract the bare function type so call sites can store a `*const Fn` without
/// an extra layer of pointer indirection.
fn FnType(comptime T: type) type {
    const pointer = switch (@typeInfo(T)) {
        .optional => |o| o.child,
        else => T,
    };

    return switch (@typeInfo(pointer)) {
        .pointer => |p| p.child,
        else => @compileError("expected a C function-pointer typedef"),
    };
}

pub const FnGetInterface = FnType(forts.Forts_GetInterface);
pub const FnModLoad = FnType(forts.Forts_ModLoadFn);
pub const FnModInit = FnType(forts.Forts_ModInitFn);
pub const FnModUnload = FnType(forts.Forts_ModUnloadFn);

pub const FnModLoadName = forts.FORTS_MOD_LOAD_NAME;
pub const FnModInitName = forts.FORTS_MOD_INIT_NAME;
pub const FnModUnloadName = forts.FORTS_MOD_UNLOAD_NAME;

pub const HANDLE_INTERFACE_LAST = forts.FORTS_HANDLE_INTERFACE_LAST;
pub const DEBUG_LOG_INTERFACE_LAST = forts.FORTS_DEBUG_LOG_INTERFACE_LAST;
pub const RUNTIME_INTERFACE_LAST = forts.FORTS_RUNTIME_INTERFACE_LAST;
pub const ALLOCATOR_INTERFACE_LAST = forts.FORTS_ALLOCATOR_INTERFACE_LAST;
pub const HOOK_INTERFACE_LAST = forts.FORTS_HOOK_INTERFACE_LAST;
pub const FIELD_INTERFACE_LAST = forts.FORTS_FIELD_INTERFACE_LAST;
pub const VARIABLE_INTERFACE_LAST = forts.FORTS_VARIABLE_INTERFACE_LAST;
pub const SYNC_INTERFACE_LAST = forts.FORTS_SYNC_INTERFACE_LAST;

pub const HandleInterface001 = forts.Forts_HandleInterface001;
pub const DebugLogInterface001 = forts.Forts_DebugLogInterface001;
pub const RuntimeInterface001 = forts.Forts_RuntimeInterface001;
pub const AllocatorInterface001 = forts.Forts_AllocatorInterface001;
pub const HookInterface001 = forts.Forts_HookInterface001;
pub const FieldInterface001 = forts.Forts_FieldInterface001;
pub const VariableInterface001 = forts.Forts_VariableInterface001;
pub const SyncInterface001 = forts.Forts_SyncInterface001;

pub inline fn cstringSlice(string: CString) []const u8 {
    const ptr: [*]const u8 = @ptrCast(string.ptr);

    return ptr[0..string.len];
}

pub inline fn cstringFrom(string: []const u8) CString {
    return .{
        .ptr = string.ptr,
        .len = string.len,
    };
}

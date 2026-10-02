// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: LGPL-3.0-only

const std = @import("std");

pub const LPCVOID = std.os.windows.LPCVOID;
pub const SIZE_T = std.os.windows.SIZE_T;
pub const LONG = std.os.windows.LONG;
pub const HANDLE = std.os.windows.HANDLE;
pub const LPCWSTR = std.os.windows.LPCWSTR;
pub const LPCSTR = std.os.windows.LPCSTR;
pub const LPWSTR = std.os.windows.LPWSTR;
pub const HMODULE = ?*anyopaque;
pub const HINSTANCE = std.os.windows.HINSTANCE;
pub const WORD = std.os.windows.WORD;
pub const DWORD = std.os.windows.DWORD;
pub const PDWORD = *DWORD;
pub const DWORD_PTR = std.os.windows.DWORD_PTR;
pub const LPVOID = std.os.windows.LPVOID;
pub const BOOL = std.os.windows.BOOL;
pub const FARPROC = ?*anyopaque;
pub const HRESULT = DWORD;
pub const REFIID = ?*anyopaque;
pub const LPUNKNOWN = ?*anyopaque;
pub const MAX_PATH = std.os.windows.MAX_PATH;

pub const DLL_PROCESS_DETACH: DWORD = 0;

pub const TH32CS_SNAPTHREAD: DWORD = 0x00000004;

pub const THREADENTRY32 = extern struct {
    dwSize: DWORD = @sizeOf(THREADENTRY32),
    cntUsage: DWORD = 0,
    th32ThreadID: DWORD = 0,
    th32OwnerProcessID: DWORD = 0,
    tpBasePri: LONG = 0,
    tpDeltaPri: LONG = 0,
    dwFlags: DWORD = 0,
};

pub const LPTHREADENTRY32 = *THREADENTRY32;

pub const THREAD_SUSPEND_RESUME = 0x0002;

pub const MEM_COMMIT = 0x00001000;
pub const MEM_RESERVE = 0x00002000;
pub const MEM_DECOMMIT = 0x00004000;
pub const MEM_RELEASE = 0x00008000;

pub const PAGE_EXECUTE_READ = 0x20;
pub const PAGE_EXECUTE_READWRITE = 0x40;

pub const SYSTEM_INFO = extern struct {
    pub const _DUMMYUNIONNAME = extern union {
        pub const _DUMMYSTRUCTNAME = extern struct {
            wProcessorArchitecture: WORD,
            wReserved: WORD,
        };

        dwOemId: DWORD,
        DUMMYSTRUCTNAME: _DUMMYSTRUCTNAME,
    };

    DUMMYUNIONNAME: _DUMMYUNIONNAME,
    dwPageSize: DWORD,
    lpMinimumApplicationAddress: LPVOID,
    lpMaximumApplicationAddress: LPVOID,
    dwActiveProcessorMask: DWORD_PTR,
    dwNumberOfProcessors: DWORD,
    dwProcessorType: DWORD,
    dwAllocationGranularity: DWORD,
    wProcessorLevel: WORD,
    wProcessorRevision: WORD,
};

pub const LPSYSTEM_INFO = *SYSTEM_INFO;

pub const LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

pub const kernel32 = struct {
    pub extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

    pub extern "kernel32" fn LoadLibraryW(lpLibFileName: LPCWSTR) callconv(.winapi) HMODULE;

    pub extern "kernel32" fn LoadLibraryExW(lpLibFileName: LPCWSTR, hFile: ?HANDLE, dwFlags: DWORD) callconv(.winapi) HMODULE;

    pub extern "kernel32" fn FreeLibrary(hLibModule: HMODULE) callconv(.winapi) BOOL;

    pub extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) callconv(.winapi) FARPROC;

    pub extern "kernel32" fn OutputDebugStringW(lpOutputString: LPCWSTR) callconv(.winapi) void;

    pub extern "kernel32" fn GetModuleHandleW(lpModuleName: ?LPCWSTR) callconv(.winapi) HMODULE;

    pub extern "kernel32" fn GetModuleFileNameW(hModule: HMODULE, lpFilename: ?LPWSTR, nSize: DWORD) callconv(.winapi) DWORD;

    pub extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(.winapi) HANDLE;

    pub extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;

    pub extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) DWORD;

    pub extern "kernel32" fn Thread32First(hSnapshot: HANDLE, lpte: LPTHREADENTRY32) callconv(.winapi) BOOL;

    pub extern "kernel32" fn Thread32Next(hSnapshot: HANDLE, lpte: LPTHREADENTRY32) callconv(.winapi) BOOL;

    pub extern "kernel32" fn GetCurrentThreadId() callconv(.winapi) DWORD;

    pub extern "kernel32" fn OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) callconv(.winapi) ?HANDLE;

    pub extern "kernel32" fn SuspendThread(hThread: HANDLE) callconv(.winapi) DWORD;

    pub extern "kernel32" fn ResumeThread(hThread: HANDLE) callconv(.winapi) DWORD;

    pub extern "kernel32" fn VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(.winapi) ?LPVOID;

    pub extern "kernel32" fn VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) callconv(.winapi) BOOL;

    pub extern "kernel32" fn GetSystemInfo(lpSystemInfo: LPSYSTEM_INFO) callconv(.winapi) void;

    pub extern "kernel32" fn VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD) callconv(.winapi) BOOL;

    pub extern "kernel32" fn FlushInstructionCache(hProcess: HANDLE, lpBaseAddress: LPCVOID, dwSize: SIZE_T) callconv(.winapi) BOOL;

    pub extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;

    pub extern "kernel32" fn Sleep(dwMilliseconds: DWORD) callconv(.winapi) void;
};

pub const Thread = struct {
    const Self = @This();

    id: DWORD,
    handle: HANDLE,

    pub inline fn susp(this: Self) void {
        _ = kernel32.SuspendThread(this.handle);
    }

    pub inline fn resum(this: Self) void {
        _ = kernel32.ResumeThread(this.handle);
    }

    pub inline fn close(this: Self) void {
        _ = kernel32.CloseHandle(this.handle);
    }
};

pub fn outputDebugString(slice: []const u8) void {
    if (slice.len == 0) {
        return;
    }

    var buffer: [std.math.pow(usize, 2, 12)]u8 = undefined;
    var allocator: std.heap.FixedBufferAllocator = .init(&buffer);

    const result = std.unicode.utf8ToUtf16LeAllocZ(allocator.allocator(), slice) catch @panic("OOM");

    kernel32.OutputDebugStringW(result);
}

pub const DebugOutputWriter = struct {
    pub inline fn interface(buffer: []u8) std.Io.Writer {
        return .{
            .buffer = buffer,
            .vtable = &.{
                .drain = drain,
            },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        outputDebugString(w.buffer[0..w.end]);
        w.end = 0;

        var consumed: usize = 0;

        for (data) |slice| {
            outputDebugString(slice);
            consumed += slice.len;
        }

        for (0..splat) |_| {
            const slice = data[data.len - 1];

            outputDebugString(data[data.len - 1]);
            consumed += slice.len;
        }

        return consumed;
    }
};

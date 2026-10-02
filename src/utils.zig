// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: LGPL-3.0-only

pub inline fn returnTypeOf(comptime F: anytype) type {
    return @typeInfo(F).@"fn".return_type orelse @TypeOf(void);
}

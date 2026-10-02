// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: LGPL-3.0-only

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const manifests_generator = b.addSystemCommand(&.{ "uv", "run" });
    manifests_generator.addFileArg(b.path("tools/frida/gen_zig.py"));
    manifests_generator.addArg("--targets-dir");
    manifests_generator.addDirectoryArg(b.path("tools/frida/targets"));
    const generated_manifests_path = manifests_generator.addOutputFileArg("manifests.zig");

    const forts_t = b.addTranslateC(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/forts.h"),
    });

    const forts = forts_t.createModule();

    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "forts", .module = forts },
        },
    });

    mod.addAnonymousImport("manifests.zig", .{
        .root_source_file = generated_manifests_path,
    });

    const lib = b.addLibrary(.{
        .name = "DINPUT8",
        .linkage = .dynamic,
        .root_module = mod,
    });

    b.installArtifact(lib);
    b.getInstallStep()
        .dependOn(&b.addInstallHeaderFile(b.path("src/forts.h"), "forts.h").step);

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // examples
    {
        const example_logger_lib = b.addLibrary(.{
            .name = "ExampleLogger",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .root_source_file = b.path("src/examples/example_logger.zig"),
                .imports = &.{
                    .{ .name = "forts", .module = forts },
                },
            }),
        });

        b.installArtifact(example_logger_lib);

        const example_client_lib = b.addLibrary(.{
            .name = "ExampleClient",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .root_source_file = b.path("src/examples/example_client.zig"),
                .imports = &.{
                    .{ .name = "forts", .module = forts },
                },
            }),
        });

        b.installArtifact(example_client_lib);

        const example_hook_lib = b.addLibrary(.{
            .name = "ExampleHook",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .root_source_file = b.path("src/examples/example_hook.zig"),
                .imports = &.{
                    .{ .name = "forts", .module = forts },
                },
            }),
        });

        b.installArtifact(example_hook_lib);
    }
}

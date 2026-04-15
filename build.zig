const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
    });
    translate_c.linkSystemLibrary("pam",.{});

    const pam = b.addModule("pam", .{
        .root_source_file = b.path("src/pam.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = translate_c.createModule() },
        },
    });

    const example = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("example/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ 
                .{ .name = "pam", .module = pam },
            },
        }),
    });


    const install_example = b.addInstallArtifact(example, .{});
    const example_step = b.step("example", "Build the example");
    example_step.dependOn(&example.step);
    example_step.dependOn(&install_example.step);

    const test_step = b.step("test", "Run unit tests");
    const tests = b.addTest(.{ .root_module = pam });
    const run_tests = b.addRunArtifact(tests);
    test_step.dependOn(&run_tests.step);
}

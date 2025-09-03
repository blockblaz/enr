const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const secp256k1_dep = b.dependency("secp256k1", .{
        .target = target,
        .optimize = optimize,
    });

    const peer_id_dep = b.dependency("peer_id", .{
        .target = target,
        .optimize = optimize,
    });

    const multiformats_dep = peer_id_dep.builder.dependency("zmultiformats", .{
        .target = target,
        .optimize = optimize,
    });

    const lib_mod = b.addModule("zig-enr",.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_mod.addImport("secp256k1", secp256k1_dep.module("secp256k1"));
    lib_mod.addImport("peer-id", peer_id_dep.module("peer-id"));
    lib_mod.addImport("multiformats", multiformats_dep.module("multiformats-zig"));
    lib_mod.linkLibrary(secp256k1_dep.artifact("libsecp"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "enr",
        .root_module = lib_mod,
    });

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);
}

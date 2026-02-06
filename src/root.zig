const std = @import("std");
const enrlib = @import("enr.zig");
const secp256k1 = @import("secp256k1.zig");

/// ENR (Ethereum Node Record) - A fully parsed and validated ENR for network operations.
///
/// This type provides immediate access to all ENR fields after parsing and validation.
/// It maintains the complete node information including IP address, ports, public key,
/// and signature in memory for fast access during network discovery protocols.
pub const ENR = enrlib.ENR;

/// EncodedENR - A lightweight wrapper around raw ENR text representation.
///
/// This type stores the ENR in its encoded string format and provides lazy parsing
/// capabilities. Fields are decoded on-demand when accessed, making it memory-efficient
/// for scenarios where not all ENR data needs to be processed immediately.
pub const EncodedENR = enrlib.EncodedENR;

/// SignableENR - A mutable ENR builder for creating and updating node records.
///
/// This type allows programmatic construction of ENR records by setting various
/// key-value pairs before signing with a private key. It handles the ENR encoding
/// format and ensures proper structure before signature generation.
pub const SignableENR = enrlib.SignableENR;
pub const KeyPair = enrlib.KeyPair;

/// Deinitializes the global context for secp256k1 operations.
/// It should be called in your main function before the program exits.
pub const deinitGlobalSecp256k1Ctx = secp256k1.deinitSecp256k1Context;

/// Returns a pointer to the global context for secp256k1 operations.
pub const getGlobalSecp256k1Ctx = secp256k1.getSecp256k1Context;

pub const max_enr_txt_size = enrlib.max_enr_txt_size;

/// Loads ENR from the given file path
pub fn loadENRFromDisk(enr: *ENR, file_path: []const u8) !void {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    var buf: [max_enr_txt_size]u8 = undefined;
    var r = file.readerStreaming(&buf);
    try readENR(&r.interface, enr);
}

/// Loads EncodedENR from the given file path
pub fn loadEncodedENRFromDisk(encoded_enr: *EncodedENR, file_path: []const u8) !void {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    var buf: [max_enr_txt_size]u8 = undefined;
    var r = file.readerStreaming(&buf);
    try readEncodedENR(&r.interface, encoded_enr);
}

/// Saves an ENR to disk with given file path
pub fn saveENRToDisk(file_path: []const u8, enr: *const ENR) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    var buf: [max_enr_txt_size]u8 = undefined;
    var w = file.writer(&buf);
    try writeENR(&w.interface, enr);
    try w.interface.flush();
}

/// Saves a SignableENR to disk with given file path
pub fn saveSignableENRToDisk(file_path: []const u8, signable_enr: *const SignableENR) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    var buf: [max_enr_txt_size]u8 = undefined;
    var w = file.writer(&buf);
    try writeSignableENR(&w.interface, signable_enr);
    try w.interface.flush();
}

/// Loads multiple ENRs from a single file
pub fn loadMultipleENRsFromDisk(enr_list: *std.ArrayList(ENR), allocator: std.mem.Allocator, file_path: []const u8, delimiter: u8) !void {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    // +1 to fit a max-size ENR token plus the delimiter byte in the streaming buffer.
    var read_buf: [max_enr_txt_size + 1]u8 = undefined;
    var r = file.readerStreaming(&read_buf);
    try readMultipleENRs(&r.interface, enr_list, allocator, delimiter);
}

/// Loads multiple EncodedENRs from a single file
pub fn loadMultipleEncodedENRsFromDisk(enr_list: *std.ArrayList(EncodedENR), allocator: std.mem.Allocator, file_path: []const u8, delimiter: u8) !void {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    // +1 to fit a max-size ENR token plus the delimiter byte in the streaming buffer.
    var read_buf: [max_enr_txt_size + 1]u8 = undefined;
    var r = file.readerStreaming(&read_buf);
    try readMultipleEncodedENRs(&r.interface, enr_list, allocator, delimiter);
}

/// Saves multiple ENRs to a single file
pub fn saveMultipleENRsToDisk(file_path: []const u8, enrs: []const ENR, delimiter: u8) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    var buf: [max_enr_txt_size]u8 = undefined;
    var w = file.writer(&buf);
    try writeMultipleENRs(&w.interface, enrs, delimiter);
    try w.interface.flush();
}

/// Saves multiple SignableENRs to a single file
pub fn saveMultipleSignableENRsToDisk(file_path: []const u8, signable_enrs: []const SignableENR, delimiter: u8) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    var buf: [max_enr_txt_size]u8 = undefined;
    var w = file.writer(&buf);
    try writeMultipleSignableENRs(&w.interface, signable_enrs, delimiter);
    try w.interface.flush();
}

/// Generic function to write ENR to any writer
pub fn writeENR(writer: anytype, enr: *const ENR) !void {
    var txt_buffer: [max_enr_txt_size]u8 = undefined;
    const out = try enr.encodeToTxt(&txt_buffer);
    try writer.writeAll(out);
}

/// Generic function to write SignableENR to any writer
pub fn writeSignableENR(writer: anytype, signable_enr: *const SignableENR) !void {
    var txt_buffer: [max_enr_txt_size]u8 = undefined;
    const out = try signable_enr.encodeToTxt(&txt_buffer);
    try writer.writeAll(out);
}

/// Generic function to write multiple ENRs to any writer
pub fn writeMultipleENRs(writer: anytype, enrs: []const ENR, delimiter: u8) !void {
    var txt_buffer: [max_enr_txt_size]u8 = undefined;
    for (enrs, 0..) |*enr, i| {
        const out = try enr.encodeToTxt(&txt_buffer);
        try writer.writeAll(out);

        if (i < enrs.len - 1) {
            try writer.writeByte(delimiter);
        }
    }
}

/// Generic function to write multiple SignableENRs to any writer
pub fn writeMultipleSignableENRs(writer: anytype, signable_enrs: []const SignableENR, delimiter: u8) !void {
    var txt_buffer: [max_enr_txt_size]u8 = undefined;
    for (signable_enrs, 0..) |*enr, i| {
        const out = try enr.encodeToTxt(&txt_buffer);
        try writer.writeAll(out);

        if (i < signable_enrs.len - 1) {
            try writer.writeByte(delimiter);
        }
    }
}

/// Generic function to read ENR from any reader
pub fn readENR(reader: *std.Io.Reader, enr: *ENR) !void {
    var buffer: [max_enr_txt_size]u8 = undefined;
    const bytes_read = try readTxtIntoBuffer(reader, &buffer);
    const content = std.mem.trim(u8, buffer[0..bytes_read], " \t\r\n");
    try ENR.decodeTxtInto(enr, content);
}

/// Generic function to read EncodedENR from any reader
pub fn readEncodedENR(reader: *std.Io.Reader, encoded_enr: *EncodedENR) !void {
    var buffer: [max_enr_txt_size]u8 = undefined;
    const bytes_read = try readTxtIntoBuffer(reader, &buffer);
    const content = std.mem.trim(u8, buffer[0..bytes_read], " \t\r\n");
    encoded_enr.* = try EncodedENR.decodeTxtInto(content);
}

fn readTxtIntoBuffer(reader: *std.Io.Reader, buffer: []u8) !usize {
    const bytes_read = reader.readSliceShort(buffer) catch return error.ReadFailed;
    if (bytes_read == buffer.len) {
        // Buffer is full. Drain any remaining bytes — trailing whitespace is
        // allowed (common when files end with a newline), but any non-whitespace
        // byte means the content genuinely exceeds the buffer.
        var extra: [1]u8 = undefined;
        while (true) {
            const n = reader.readSliceShort(&extra) catch return error.ReadFailed;
            if (n == 0) break;
            switch (extra[0]) {
                ' ', '\t', '\r', '\n' => {},
                else => return error.StreamTooLong,
            }
        }
    }
    return bytes_read;
}

/// Generic function to read multiple ENRs from any reader
pub fn readMultipleENRs(reader: *std.Io.Reader, enr_list: *std.ArrayList(ENR), allocator: std.mem.Allocator, delimiter: u8) !void {
    while (true) {
        const line = reader.takeDelimiter(delimiter) catch |err| switch (err) {
            error.StreamTooLong => {
                _ = reader.discardDelimiterInclusive(delimiter) catch 0;
                continue;
            },
            error.ReadFailed => return error.ReadFailed,
        };

        if (line == null) break;

        const trimmed = std.mem.trim(u8, line.?, " \t\r\n");
        if (trimmed.len == 0) continue;

        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, trimmed);
        try enr_list.append(allocator, enr);
    }
}

/// Generic function to read multiple EncodedENRs from any reader
pub fn readMultipleEncodedENRs(reader: *std.Io.Reader, enr_list: *std.ArrayList(EncodedENR), allocator: std.mem.Allocator, delimiter: u8) !void {
    while (true) {
        const line = reader.takeDelimiter(delimiter) catch |err| switch (err) {
            error.StreamTooLong => {
                _ = reader.discardDelimiterInclusive(delimiter) catch 0;
                continue;
            },
            error.ReadFailed => return error.ReadFailed,
        };

        if (line == null) break;

        const trimmed = std.mem.trim(u8, line.?, " \t\r\n");
        if (trimmed.len == 0) continue;

        const encoded_enr = try EncodedENR.decodeTxtInto(trimmed);
        try enr_list.append(allocator, encoded_enr);
    }
}

const testing = std.testing;

// Test ENR vectors from various Ethereum clients
const test_enrs = [_][]const u8{
    // Teku team's bootnode
    "enr:-KG4QMOEswP62yzDjSwWS4YEjtTZ5PO6r65CPqYBkgTTkrpaedQ8uEUo1uMALtJIvb2w_WWEVmg5yt1UAuK1ftxUU7QDhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQEnfA2iXNlY3AyNTZrMaEDfol8oLr6XJ7FsdAYE7lpJhKMls4G_v6qQOGKJUWGb_uDdGNwgiMog3VkcIIjKA",
    "enr:-KG4QF4B5WrlFcRhUU6dZETwY5ZzAXnA0vGC__L1Kdw602nDZwXSTs5RFXFIFUnbQJmhNGVU6OIX7KVrCSTODsz1tK4DhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQExNYEiXNlY3AyNTZrMaECQmM9vp7KhaXhI-nqL_R0ovULLCFSFTa9CPPSdb1zPX6DdGNwgiMog3VkcIIjKA",

    // Prysm team's bootnodes
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",

    // Lighthouse team's bootnodes
    "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QIqLuWybHNONr933Lk0dcMmAB5WgvGKRyDihy1wHDIVlNuuztX62W51voT4I8qD34GcTEOTmag1bcdZ_8aaT4NUBhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY04ng2lwNpAkAh8AgAIBAAAAAAAAAA-fiXNlY3AyNTZrMaEDscnRV6n1m-D9ID5UsURk0jsoKNXt1TIrj8uKOGW6iluDdWRwgiMohHVkcDaCI4I",

    // EF bootnodes
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",

    // Nimbus team's bootnodes
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
    "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
};

/// Helper to write ENR to temp file
fn writeTempEnr(tmp_dir: *std.testing.TmpDir, file_name: []const u8, enr: *ENR) !void {
    const allocator = testing.allocator;

    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    try saveENRToDisk(full_path, enr);
}

/// Helper to read ENR from temp file
fn readTempEnr(tmp_dir: *std.testing.TmpDir, file_name: []const u8, enr: *ENR) !void {
    const allocator = testing.allocator;

    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    try loadENRFromDisk(enr, full_path);
}

/// Helper to write multiple ENRs to temp file
fn writeTempMultipleEnrs(tmp_dir: *std.testing.TmpDir, file_name: []const u8, enrs: []ENR, delimiter: u8) !void {
    const allocator = testing.allocator;

    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    try saveMultipleENRsToDisk(full_path, enrs, delimiter);
}

/// Helper to read multiple ENRs from temp file
fn readTempMultipleEnrs(allocator: std.mem.Allocator, tmp_dir: *std.testing.TmpDir, file_name: []const u8, delimiter: u8) !std.ArrayList(ENR) {
    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    var enr_list: std.ArrayList(ENR) = .empty;
    try loadMultipleENRsFromDisk(&enr_list, allocator, full_path, delimiter);

    return enr_list;
}

/// Helper to read EncodedENR from temp file
fn readTempEncodedEnr(tmp_dir: *std.testing.TmpDir, file_name: []const u8, encoded_enr: *EncodedENR) !void {
    const allocator = testing.allocator;

    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    try loadEncodedENRFromDisk(encoded_enr, full_path);
}

/// Helper to read multiple EncodedENRs from temp file
fn readTempMultipleEncodedEnrs(allocator: std.mem.Allocator, tmp_dir: *std.testing.TmpDir, file_name: []const u8, delimiter: u8) !std.ArrayList(EncodedENR) {
    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    var enr_list: std.ArrayList(EncodedENR) = .empty;
    try loadMultipleEncodedENRsFromDisk(&enr_list, allocator, full_path, delimiter);

    return enr_list;
}

/// Helper to write SignableENR to temp file
fn writeTempSignableEnr(tmp_dir: *std.testing.TmpDir, file_name: []const u8, signable_enr: *SignableENR) !void {
    const allocator = testing.allocator;

    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    try saveSignableENRToDisk(full_path, signable_enr);
}

/// Helper to write multiple SignableENRs to temp file
fn writeTempMultipleSignableEnrs(tmp_dir: *std.testing.TmpDir, file_name: []const u8, signable_enrs: []SignableENR, delimiter: u8) !void {
    const allocator = testing.allocator;

    const tmp_dir_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const full_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, file_name });
    defer allocator.free(full_path);

    try saveMultipleSignableENRsToDisk(full_path, signable_enrs, delimiter);
}

/// Helper to compare two ENRs by encoding
fn expectEqualEnrs(original: *ENR, loaded: *ENR) !void {
    var original_encoded: [enrlib.max_enr_size]u8 = undefined;
    var loaded_encoded: [enrlib.max_enr_size]u8 = undefined;

    try original.encodeInto(&original_encoded);
    try loaded.encodeInto(&loaded_encoded);

    const original_len = original.encodedLen();
    const loaded_len = loaded.encodedLen();

    try testing.expectEqual(original_len, loaded_len);
    try testing.expectEqualSlices(u8, original_encoded[0..original_len], loaded_encoded[0..loaded_len]);
}

/// Helper to create test file with content
fn createTestFileWithContent(tmp_dir: *std.testing.TmpDir, file_name: []const u8, content: []const u8) !void {
    const file = try tmp_dir.dir.createFile(file_name, .{});
    defer file.close();
    var buf: [max_enr_txt_size]u8 = undefined;
    var w = file.writer(&buf);
    try w.interface.writeAll(content);
    try w.interface.flush();
}

test "single ENR file operations" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var enr: ENR = undefined;
    try ENR.decodeTxtInto(&enr, test_enrs[0]);

    try std.testing.expectEqual(3, enr.seq);
    var ip_buffer: [16]u8 = undefined;
    try std.testing.expectEqualStrings("4.157.240.54", (try enr.getIPStr(&ip_buffer)).?);
    var sig_buffer: [130]u8 = undefined;
    try std.testing.expectEqualStrings("0xc384b303fadb2cc38d2c164b86048ed4d9e4f3baafae423ea6019204d392ba5a79d43cb84528d6e3002ed248bdbdb0fd6584566839cadd5402e2b57edc5453b4", try enr.getSignatureStr(&sig_buffer, .lower));
    var pubkey_buffer: [68]u8 = undefined;
    try std.testing.expectEqualStrings("0x037e897ca0bafa5c9ec5b1d01813b96926128c96ce06fefeaa40e18a2545866ffb", try enr.getPublicKeyStr(&pubkey_buffer, .lower));
    try std.testing.expectEqual(@as(u16, 9000), (try enr.getUDP()).?);

    const test_file = "test_single_enr.txt";

    try writeTempEnr(&tmp_dir, test_file, &enr);

    var loaded_enr: ENR = undefined;
    try readTempEnr(&tmp_dir, test_file, &loaded_enr);

    try expectEqualEnrs(&enr, &loaded_enr);
}

test "multiple ENRs with newline delimiter" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;
    var enr_list: std.ArrayList(ENR) = .empty;
    defer enr_list.deinit(allocator);

    for (test_enrs[0..5]) |enr_txt| {
        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, enr_txt);
        try enr_list.append(allocator, enr);
    }

    const test_file = "test_multiple_enrs_newline.txt";

    try writeTempMultipleEnrs(&tmp_dir, test_file, enr_list.items, '\n');

    var loaded_enr_list = try readTempMultipleEnrs(allocator, &tmp_dir, test_file, '\n');
    defer loaded_enr_list.deinit(allocator);

    try testing.expectEqual(enr_list.items.len, loaded_enr_list.items.len);

    for (enr_list.items, loaded_enr_list.items) |*original, *loaded| {
        try expectEqualEnrs(original, loaded);
    }
}

test "error handling - file not found" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const result = tmp_dir.dir.openFile("nonexistent_file.txt", .{});

    try testing.expectError(error.FileNotFound, result);
}

test "error handling - invalid ENR format" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const test_file = "test_invalid_enr.txt";

    try createTestFileWithContent(&tmp_dir, test_file, "invalid-enr-content");

    var enr: ENR = undefined;
    const read_file = try tmp_dir.dir.openFile(test_file, .{});
    defer read_file.close();

    const file_size = try read_file.getEndPos();
    var enr_txt: [enrlib.max_enr_size]u8 = undefined;
    var read_buf: [4096]u8 = undefined;
    var rdr = read_file.reader(&read_buf);
    rdr.interface.readSliceAll(enr_txt[0..file_size]) catch return error.ReadFailed;

    const result = ENR.decodeTxtInto(&enr, enr_txt[0..file_size]);
    try testing.expectError(error.BadPrefix, result);
}

test "directory creation" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var enr: ENR = undefined;
    try ENR.decodeTxtInto(&enr, test_enrs[0]);

    try tmp_dir.dir.makePath("nested");
    const test_file = "nested/enr.txt";

    try writeTempEnr(&tmp_dir, test_file, &enr);

    var loaded_enr: ENR = undefined;
    try readTempEnr(&tmp_dir, test_file, &loaded_enr);
}

test "empty and whitespace handling in multiple ENRs" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;
    const test_file = "test_empty_entries.txt";

    const content = test_enrs[0] ++ "\n\n  \t  \n" ++ test_enrs[1] ++ "\n   \n" ++ test_enrs[2];
    try createTestFileWithContent(&tmp_dir, test_file, content);

    var enr_list = try readTempMultipleEnrs(allocator, &tmp_dir, test_file, '\n');
    defer enr_list.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), enr_list.items.len);
}

test "custom delimiter" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;
    var enr_list: std.ArrayList(ENR) = .empty;
    defer enr_list.deinit(allocator);

    for (test_enrs[12..14]) |enr_txt| {
        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, enr_txt);
        try enr_list.append(allocator, enr);
    }

    const test_file = "test_custom_delimiter.txt";

    try writeTempMultipleEnrs(&tmp_dir, test_file, enr_list.items, '|');

    var loaded_enr_list = try readTempMultipleEnrs(allocator, &tmp_dir, test_file, '|');
    defer loaded_enr_list.deinit(allocator);

    try testing.expectEqual(enr_list.items.len, loaded_enr_list.items.len);
}

test "EncodedENR file operations" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const test_file = "test_encoded_enr.txt";

    try createTestFileWithContent(&tmp_dir, test_file, test_enrs[0]);

    var loaded_encoded_enr: EncodedENR = undefined;
    try readTempEncodedEnr(&tmp_dir, test_file, &loaded_encoded_enr);

    var enr: ENR = undefined;
    loaded_encoded_enr.decodeIntoENR(&enr);

    try testing.expectEqual(@as(u64, 3), enr.seq);
    var ip_buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("4.157.240.54", (try loaded_encoded_enr.getIPStr(&ip_buffer)).?);
    var sig_buffer: [130]u8 = undefined;
    try std.testing.expectEqualStrings("0xc384b303fadb2cc38d2c164b86048ed4d9e4f3baafae423ea6019204d392ba5a79d43cb84528d6e3002ed248bdbdb0fd6584566839cadd5402e2b57edc5453b4", try loaded_encoded_enr.getSignatureStr(&sig_buffer, .lower));
    var pubkey_buffer: [68]u8 = undefined;
    try std.testing.expectEqualStrings("0x037e897ca0bafa5c9ec5b1d01813b96926128c96ce06fefeaa40e18a2545866ffb", try loaded_encoded_enr.getPublicKeyStr(&pubkey_buffer, .lower));
    try std.testing.expectEqual(@as(u16, 9000), (try loaded_encoded_enr.getUDP()).?);
}

test "multiple EncodedENRs file operations" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;
    const test_file = "test_multiple_encoded_enrs.txt";

    const content = try std.mem.join(allocator, "\n", test_enrs[0..5]);
    defer allocator.free(content);
    try createTestFileWithContent(&tmp_dir, test_file, content);

    var loaded_encoded_enr_list = try readTempMultipleEncodedEnrs(allocator, &tmp_dir, test_file, '\n');
    defer loaded_encoded_enr_list.deinit(allocator);

    var loaded_enr_list = try readTempMultipleEnrs(allocator, &tmp_dir, test_file, '\n');
    defer loaded_enr_list.deinit(allocator);

    try testing.expectEqual(@as(usize, 5), loaded_encoded_enr_list.items.len);
    try testing.expectEqual(loaded_enr_list.items.len, loaded_encoded_enr_list.items.len);

    for (loaded_encoded_enr_list.items, loaded_enr_list.items) |*encoded_enr, *enr| {
        try testing.expectEqual(enr.seq, encoded_enr.seq());

        var ip_buffer1: [16]u8 = undefined;
        var ip_buffer2: [16]u8 = undefined;

        const ip1 = try enr.getIPStr(&ip_buffer1);
        const ip2 = try encoded_enr.getIPStr(&ip_buffer2);

        try testing.expectEqualStrings(ip1.?, ip2.?);

        const udp1 = try enr.getUDP();
        const udp2 = try encoded_enr.getUDP();
        try testing.expectEqual(udp1.?, udp2.?);

        var pubkey_buffer1: [68]u8 = undefined;
        var pubkey_buffer2: [68]u8 = undefined;

        const pubkey1 = try enr.getPublicKeyStr(&pubkey_buffer1, .lower);
        const pubkey2 = try encoded_enr.getPublicKeyStr(&pubkey_buffer2, .lower);
        try testing.expectEqualStrings(pubkey1, pubkey2);

        var sig_buffer1: [130]u8 = undefined;
        var sig_buffer2: [130]u8 = undefined;

        const sig1 = try enr.getSignatureStr(&sig_buffer1, .lower);
        const sig2 = try encoded_enr.getSignatureStr(&sig_buffer2, .lower);
        try testing.expectEqualStrings(sig1, sig2);
    }
}

test "SignableENR file operations" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key_pair = KeyPair.generate();
    var signable_enr = SignableENR.create(key_pair);
    defer signable_enr.deinit();

    try signable_enr.set("ip", &[_]u8{ 127, 0, 0, 1 });
    var udp_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &udp_bytes, 30303, .big);
    try signable_enr.set("udp", &udp_bytes);

    const test_file = "test_signable_enr.txt";

    try writeTempSignableEnr(&tmp_dir, test_file, &signable_enr);

    var loaded_enr: ENR = undefined;
    try readTempEnr(&tmp_dir, test_file, &loaded_enr);

    try testing.expectEqual(@as(u16, 30303), (try loaded_enr.getUDP()).?);
    var ip_buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("127.0.0.1", (try loaded_enr.getIPStr(&ip_buffer)).?);
}

test "multiple SignableENRs file operations" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;
    var signable_enr_list: std.ArrayList(SignableENR) = .empty;
    defer {
        for (signable_enr_list.items) |*item| {
            item.deinit();
        }
        signable_enr_list.deinit(allocator);
    }

    for (0..3) |i| {
        const key_pair = KeyPair.generate();
        var signable_enr = SignableENR.create(key_pair);
        try signable_enr.set("ip", &[_]u8{ 127, 0, 0, @intCast(i + 1) });

        var udp_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &udp_bytes, @intCast(30303 + i), .big);
        try signable_enr.set("udp", &udp_bytes);

        try signable_enr_list.append(allocator, signable_enr);
    }

    const test_file = "test_multiple_signable_enrs.txt";

    try writeTempMultipleSignableEnrs(&tmp_dir, test_file, signable_enr_list.items, '\n');

    var loaded_enr_list = try readTempMultipleEnrs(allocator, &tmp_dir, test_file, '\n');
    defer loaded_enr_list.deinit(allocator);

    try testing.expectEqual(signable_enr_list.items.len, loaded_enr_list.items.len);

    for (loaded_enr_list.items, 0..) |*enr, i| {
        try testing.expectEqual(@as(u16, @intCast(30303 + i)), (try enr.getUDP()).?);

        var ip_buffer: [16]u8 = undefined;
        const expected_ip = switch (i) {
            0 => "127.0.0.1",
            1 => "127.0.0.2",
            2 => "127.0.0.3",
            else => unreachable,
        };
        try testing.expectEqualStrings(expected_ip, (try enr.getIPStr(&ip_buffer)).?);
    }
}

test "writeENR to different writers" {
    var enr: ENR = undefined;
    try ENR.decodeTxtInto(&enr, test_enrs[0]);

    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);

    try writeENR(fbs.writer(), &enr);

    const written_data = fbs.getWritten();
    try testing.expectEqualStrings(test_enrs[0], written_data);

    const allocator = testing.allocator;
    var array_buffer: std.ArrayList(u8) = .empty;
    defer array_buffer.deinit(allocator);

    try writeENR(array_buffer.writer(allocator), &enr);
    try testing.expectEqualStrings(test_enrs[0], array_buffer.items);
}

test "writeSignableENR to different writers" {
    const key_pair = KeyPair.generate();
    var signable_enr = SignableENR.create(key_pair);
    defer signable_enr.deinit();

    try signable_enr.set("ip", &[_]u8{ 192, 168, 1, 100 });
    var udp_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &udp_bytes, 8080, .big);
    try signable_enr.set("udp", &udp_bytes);

    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);

    try writeSignableENR(fbs.writer(), &signable_enr);

    const written_data = fbs.getWritten();

    var parsed_enr: ENR = undefined;
    try ENR.decodeTxtInto(&parsed_enr, written_data);

    try testing.expectEqual(@as(u16, 8080), (try parsed_enr.getUDP()).?);
    var ip_buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("192.168.1.100", (try parsed_enr.getIPStr(&ip_buffer)).?);

    const allocator = testing.allocator;
    var array_buffer: std.ArrayList(u8) = .empty;
    defer array_buffer.deinit(allocator);

    try writeSignableENR(array_buffer.writer(allocator), &signable_enr);

    try testing.expectEqualStrings(written_data, array_buffer.items);
}

test "writeMultipleENRs to different writers" {
    const allocator = testing.allocator;
    var enr_list: std.ArrayList(ENR) = .empty;
    defer enr_list.deinit(allocator);

    for (test_enrs[0..3]) |enr_txt| {
        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, enr_txt);
        try enr_list.append(allocator, enr);
    }

    // Test with newline delimiter
    {
        var buffer: [4096]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try writeMultipleENRs(fbs.writer(), enr_list.items, '\n');

        const written_data = fbs.getWritten();
        const expected = try std.mem.join(allocator, "\n", test_enrs[0..3]);
        defer allocator.free(expected);

        try testing.expectEqualStrings(expected, written_data);
    }

    // Test with custom delimiter
    {
        var buffer: [4096]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try writeMultipleENRs(fbs.writer(), enr_list.items, '|');

        const written_data = fbs.getWritten();
        const expected = try std.mem.join(allocator, "|", test_enrs[0..3]);
        defer allocator.free(expected);

        try testing.expectEqualStrings(expected, written_data);
    }

    // Test writing to ArrayList
    {
        var array_buffer: std.ArrayList(u8) = .empty;
        defer array_buffer.deinit(allocator);

        try writeMultipleENRs(array_buffer.writer(allocator), enr_list.items, ',');

        const expected = try std.mem.join(allocator, ",", test_enrs[0..3]);
        defer allocator.free(expected);

        try testing.expectEqualStrings(expected, array_buffer.items);
    }
}

test "writeMultipleSignableENRs to different writers" {
    const allocator = testing.allocator;
    var signable_enr_list: std.ArrayList(SignableENR) = .empty;
    defer {
        for (signable_enr_list.items) |*item| {
            item.deinit();
        }
        signable_enr_list.deinit(allocator);
    }

    for (0..2) |i| {
        const key_pair = KeyPair.generate();
        var signable_enr = SignableENR.create(key_pair);

        try signable_enr.set("ip", &[_]u8{ 10, 0, 0, @intCast(i + 1) });
        var udp_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &udp_bytes, @intCast(5000 + i), .big);
        try signable_enr.set("udp", &udp_bytes);

        try signable_enr_list.append(allocator, signable_enr);
    }

    var buffer: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);

    try writeMultipleSignableENRs(fbs.writer(), signable_enr_list.items, '\n');

    const written_data = fbs.getWritten();

    var lines = std.mem.splitSequence(u8, written_data, "\n");
    var count: usize = 0;
    while (lines.next()) |line| {
        var parsed_enr: ENR = undefined;
        try ENR.decodeTxtInto(&parsed_enr, line);

        try testing.expectEqual(@as(u16, @intCast(5000 + count)), (try parsed_enr.getUDP()).?);
        var ip_buffer: [16]u8 = undefined;
        const expected_ip = if (count == 0) "10.0.0.1" else "10.0.0.2";
        try testing.expectEqualStrings(expected_ip, (try parsed_enr.getIPStr(&ip_buffer)).?);

        count += 1;
    }
    try testing.expectEqual(@as(usize, 2), count);

    var array_buffer: std.ArrayList(u8) = .empty;
    defer array_buffer.deinit(allocator);

    try writeMultipleSignableENRs(array_buffer.writer(allocator), signable_enr_list.items, '|');

    try testing.expect(std.mem.indexOf(u8, array_buffer.items, "|") != null);
}

test "writer functions with empty inputs" {
    {
        var buffer: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        const empty_enrs: []ENR = &[_]ENR{};
        try writeMultipleENRs(fbs.writer(), empty_enrs, '\n');

        const written_data = fbs.getWritten();
        try testing.expectEqual(@as(usize, 0), written_data.len);
    }

    {
        var buffer: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        const empty_signable_enrs: []SignableENR = &[_]SignableENR{};
        try writeMultipleSignableENRs(fbs.writer(), empty_signable_enrs, '\n');

        const written_data = fbs.getWritten();
        try testing.expectEqual(@as(usize, 0), written_data.len);
    }
}

test "writer functions with single item (no delimiter)" {
    {
        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, test_enrs[0]);

        var buffer: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try writeMultipleENRs(fbs.writer(), &[_]ENR{enr}, '|');

        const written_data = fbs.getWritten();
        try testing.expectEqualStrings(test_enrs[0], written_data);
        try testing.expect(std.mem.indexOf(u8, written_data, "|") == null);
    }

    // Test writeMultipleSignableENRs with single SignableENR
    {
        const key_pair = KeyPair.generate();
        var signable_enr = SignableENR.create(key_pair);
        defer signable_enr.deinit();

        try signable_enr.set("ip", &[_]u8{ 1, 2, 3, 4 });
        var udp_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &udp_bytes, 1234, .big);
        try signable_enr.set("udp", &udp_bytes);

        var buffer: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try writeMultipleSignableENRs(fbs.writer(), &[_]SignableENR{signable_enr}, '|');

        const written_data = fbs.getWritten();
        try testing.expect(std.mem.indexOf(u8, written_data, "|") == null);

        var parsed_enr: ENR = undefined;
        try ENR.decodeTxtInto(&parsed_enr, written_data);
        try testing.expectEqual(@as(u16, 1234), (try parsed_enr.getUDP()).?);
    }
}

test "readENR from different readers" {
    var enr: ENR = undefined;
    try ENR.decodeTxtInto(&enr, test_enrs[0]);

    // Test reading from fixed reader
    {
        var reader: std.Io.Reader = .fixed(test_enrs[0]);
        var read_enr: ENR = undefined;
        try readENR(&reader, &read_enr);
        try expectEqualEnrs(&enr, &read_enr);
    }

    // Test reading from file via temp file
    {
        var tmp_dir = testing.tmpDir(.{});
        defer tmp_dir.cleanup();

        const test_file = "test_read_enr.txt";
        try createTestFileWithContent(&tmp_dir, test_file, test_enrs[0]);

        const file = try tmp_dir.dir.openFile(test_file, .{});
        defer file.close();

        var read_enr: ENR = undefined;
        var read_buf: [max_enr_txt_size]u8 = undefined;
        var r = file.readerStreaming(&read_buf);
        try readENR(&r.interface, &read_enr);
        try expectEqualEnrs(&enr, &read_enr);
    }
}

test "readEncodedENR from different readers" {
    // Test reading from fixed reader
    {
        var reader: std.Io.Reader = .fixed(test_enrs[0]);
        var read_encoded_enr: EncodedENR = undefined;
        try readEncodedENR(&reader, &read_encoded_enr);

        try testing.expectEqual(@as(u64, 3), read_encoded_enr.seq());
        var ip_buffer: [16]u8 = undefined;
        try testing.expectEqualStrings("4.157.240.54", (try read_encoded_enr.getIPStr(&ip_buffer)).?);
    }

    // Test reading from ArrayList buffer
    {
        const allocator = testing.allocator;
        var array_buffer: std.ArrayList(u8) = .empty;
        defer array_buffer.deinit(allocator);

        try array_buffer.appendSlice(allocator, test_enrs[0]);

        var reader: std.Io.Reader = .fixed(array_buffer.items);
        var read_encoded_enr: EncodedENR = undefined;
        try readEncodedENR(&reader, &read_encoded_enr);

        try testing.expectEqual(@as(u64, 3), read_encoded_enr.seq());
    }
}

test "readMultipleENRs from different readers" {
    const allocator = testing.allocator;

    const content = try std.mem.join(allocator, "\n", test_enrs[0..3]);
    defer allocator.free(content);

    // Test reading from fixed buffer
    {
        var reader: std.Io.Reader = .fixed(content);
        var enr_list: std.ArrayList(ENR) = .empty;
        defer enr_list.deinit(allocator);

        try readMultipleENRs(&reader, &enr_list, allocator, '\n');

        try testing.expectEqual(@as(usize, 3), enr_list.items.len);

        try testing.expectEqual(@as(u64, 3), enr_list.items[0].seq);
        var ip_buffer: [16]u8 = undefined;
        try testing.expectEqualStrings("4.157.240.54", (try enr_list.items[0].getIPStr(&ip_buffer)).?);
    }

    // Test reading from temp file
    {
        var tmp_dir = testing.tmpDir(.{});
        defer tmp_dir.cleanup();

        const test_file = "test_read_multiple.txt";
        try createTestFileWithContent(&tmp_dir, test_file, content);

        const file = try tmp_dir.dir.openFile(test_file, .{});
        defer file.close();

        var read_buf: [max_enr_txt_size]u8 = undefined;
        var r = file.readerStreaming(&read_buf);
        var enr_list: std.ArrayList(ENR) = .empty;
        defer enr_list.deinit(allocator);

        try readMultipleENRs(&r.interface, &enr_list, allocator, '\n');
        try testing.expectEqual(@as(usize, 3), enr_list.items.len);
    }
}

test "readMultipleEncodedENRs from different readers" {
    const allocator = testing.allocator;

    const content = try std.mem.join(allocator, "|", test_enrs[0..2]);
    defer allocator.free(content);

    var reader: std.Io.Reader = .fixed(content);
    var encoded_enr_list: std.ArrayList(EncodedENR) = .empty;
    defer encoded_enr_list.deinit(allocator);

    try readMultipleEncodedENRs(&reader, &encoded_enr_list, allocator, '|');

    try testing.expectEqual(@as(usize, 2), encoded_enr_list.items.len);

    try testing.expectEqual(@as(u64, 3), encoded_enr_list.items[0].seq());
    var ip_buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("4.157.240.54", (try encoded_enr_list.items[0].getIPStr(&ip_buffer)).?);
}

test "read functions with whitespace handling" {
    const allocator = testing.allocator;

    // Test single ENR with surrounding whitespace
    {
        const content_with_whitespace = "  \t  " ++ test_enrs[0] ++ "  \n  ";
        var reader: std.Io.Reader = .fixed(content_with_whitespace);

        var read_enr: ENR = undefined;
        try readENR(&reader, &read_enr);

        try testing.expectEqual(@as(u64, 3), read_enr.seq);
    }

    // Test multiple ENRs with empty lines and whitespace
    {
        const content = test_enrs[0] ++ "\n\n  \t  \n" ++ test_enrs[1] ++ "\n   \n";
        var reader: std.Io.Reader = .fixed(content);

        var enr_list: std.ArrayList(ENR) = .empty;
        defer enr_list.deinit(allocator);

        try readMultipleENRs(&reader, &enr_list, allocator, '\n');
        try testing.expectEqual(@as(usize, 2), enr_list.items.len);
    }
}

test "read functions error handling" {
    const allocator = testing.allocator;

    // Test reading invalid ENR format
    {
        const invalid_content = "invalid-enr-format";
        var reader: std.Io.Reader = .fixed(invalid_content);

        var enr: ENR = undefined;
        const result = readENR(&reader, &enr);
        try testing.expectError(error.BadPrefix, result);
    }

    // Test reading from empty reader
    {
        var reader: std.Io.Reader = .fixed("");
        var enr_list: std.ArrayList(ENR) = .empty;
        defer enr_list.deinit(allocator);

        try readMultipleENRs(&reader, &enr_list, allocator, '\n');
        try testing.expectEqual(@as(usize, 0), enr_list.items.len);
    }
}

test "standard input simulation" {
    const stdin_content = test_enrs[0];
    var reader: std.Io.Reader = .fixed(stdin_content);

    var enr: ENR = undefined;
    try readENR(&reader, &enr);

    try testing.expectEqual(@as(u64, 3), enr.seq);
    var ip_buffer: [16]u8 = undefined;
    try testing.expectEqualStrings("4.157.240.54", (try enr.getIPStr(&ip_buffer)).?);
}

test "max ENR text size boundary - text encoding exceeds old buffer size" {
    // Create a SignableENR and pad it with data so the binary encoding approaches
    // max_enr_size (300). The base64 text form will then exceed 304 bytes (the old
    // undersized buffer of max_enr_size + len("enr:")) but must fit within
    // max_enr_txt_size.
    const key_pair = KeyPair.generate();
    var signable_enr = SignableENR.create(key_pair);
    defer signable_enr.deinit();

    try signable_enr.set("ip", &[_]u8{ 10, 0, 0, 1 });
    var udp_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &udp_bytes, 9000, .big);
    try signable_enr.set("udp", &udp_bytes);

    // Add padding data to push binary size close to max_enr_size.
    // Use a conservative initial size, then verify the result.
    // Start by adding a large pad value, then check encodedLen.
    var pad_value: [enrlib.max_enr_size]u8 = undefined;
    @memset(&pad_value, 0xAB);

    // Binary search for the right padding size that keeps us just under max_enr_size
    var lo: usize = 100;
    var hi: usize = 200;
    while (lo < hi) {
        const mid = (lo + hi + 1) / 2;
        try signable_enr.set("pad", pad_value[0..mid]);
        if (signable_enr.encodedLen() <= enrlib.max_enr_size) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    try signable_enr.set("pad", pad_value[0..lo]);

    const binary_len = signable_enr.encodedLen();

    // Binary must not exceed the limit
    try testing.expect(binary_len <= enrlib.max_enr_size);
    // Binary must be large enough that base64 text exceeds the old 304-byte buffer
    const old_buffer_size = enrlib.max_enr_size + enrlib.enr_txt_prefix_len; // 304
    const txt_len = signable_enr.encodedTxtLen();
    try testing.expect(txt_len > old_buffer_size);
    // Text must fit within the correctly computed max_enr_txt_size
    try testing.expect(txt_len <= enrlib.max_enr_txt_size);

    // Round-trip: encode to text, then decode back
    var txt_buf: [enrlib.max_enr_txt_size]u8 = undefined;
    const txt = try signable_enr.encodeToTxt(&txt_buf);
    try testing.expectEqual(txt_len, txt.len);

    // Decode the text back into an ENR and verify fields
    var decoded_enr: ENR = undefined;
    try ENR.decodeTxtInto(&decoded_enr, txt);
    try testing.expectEqual(@as(u16, 9000), (try decoded_enr.getUDP()).?);
    var decoded_ip_buf: [16]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", (try decoded_enr.getIPStr(&decoded_ip_buf)).?);

    // Also verify file round-trip with the near-max-size ENR
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try writeTempSignableEnr(&tmp_dir, "max_boundary.txt", &signable_enr);

    var loaded_enr: ENR = undefined;
    try readTempEnr(&tmp_dir, "max_boundary.txt", &loaded_enr);
    try testing.expectEqual(@as(u16, 9000), (try loaded_enr.getUDP()).?);
    var loaded_ip_buf: [16]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", (try loaded_enr.getIPStr(&loaded_ip_buf)).?);
}

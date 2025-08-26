const std = @import("std");
const enrlib = @import("enr");

pub const ENR = enrlib.ENR;
pub const EncodedENR = enrlib.EncodedENR;
pub const SignableENR = enrlib.SignableENR;

/// ENR file I/O error set
pub const EnrFileError = error{
    /// The ENR file is too large to process
    EnrFileTooLarge,
};

/// Loads ENR from the given file path
pub fn loadEnrFromDisk(enr: *ENR, file_path: []const u8) !void {
    const enr_file = try std.fs.cwd().openFile(file_path, .{});
    defer enr_file.close();

    const file_size = try enr_file.getEndPos();
    if (file_size > enrlib.max_enr_size) return EnrFileError.EnrFileTooLarge;

    var enr_txt: [enrlib.max_enr_size]u8 = undefined;
    _ = try enr_file.readAll(enr_txt[0..file_size]);

    try ENR.decodeTxtInto(enr, enr_txt[0..file_size]);
}

/// Loads EncodedENR from the given file path
pub fn loadEncodedEnrFromDisk(encoded_enr: *EncodedENR, file_path: []const u8) !void {
    const enr_file = try std.fs.cwd().openFile(file_path, .{});
    defer enr_file.close();

    const file_size = try enr_file.getEndPos();
    if (file_size > enrlib.max_enr_size) return EnrFileError.EnrFileTooLarge;

    var temp_txt: [enrlib.max_enr_size]u8 = undefined;
    _ = try enr_file.readAll(temp_txt[0..file_size]);

    encoded_enr.* = try EncodedENR.decodeTxtInto(temp_txt[0..file_size]);
}

/// Saves an ENR to disk with given file path
pub fn saveEnrToDisk(file_path: []const u8, enr: *ENR) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
    const out = try enr.encodeToTxt(&txt_buffer);

    try file.writeAll(out);
}

/// Saves a SignableENR to disk with given file path
pub fn saveSignableEnrToDisk(file_path: []const u8, signable_enr: *SignableENR) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
    const out = try signable_enr.encodeToTxt(&txt_buffer);

    try file.writeAll(out);
}

/// Loads multiple ENRs from a single file
pub fn loadMultipleEnrsFromDisk(enr_list: *std.ArrayList(ENR), file_path: []const u8, delimiter: []const u8) !void {
    const enr_file = try std.fs.cwd().openFile(file_path, .{});
    defer enr_file.close();

    const file_size = try enr_file.getEndPos();
    const file_content = try enr_list.allocator.alloc(u8, file_size);
    defer enr_list.allocator.free(file_content);

    _ = try enr_file.readAll(file_content);

    var iterator = std.mem.splitSequence(u8, file_content, delimiter);

    while (iterator.next()) |enr_txt| {
        const trimmed = std.mem.trim(u8, enr_txt, " \t\r\n");
        if (trimmed.len == 0) continue; // Skip empty entries

        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, trimmed);

        try enr_list.append(enr);
    }
}

/// Loads multiple EncodedENRs from a single file
pub fn loadMultipleEncodedEnrsFromDisk(enr_list: *std.ArrayList(EncodedENR), file_path: []const u8, delimiter: []const u8) !void {
    const enr_file = try std.fs.cwd().openFile(file_path, .{});
    defer enr_file.close();

    const file_size = try enr_file.getEndPos();
    const file_content = try enr_list.allocator.alloc(u8, file_size);
    defer enr_list.allocator.free(file_content);

    _ = try enr_file.readAll(file_content);

    var iterator = std.mem.splitSequence(u8, file_content, delimiter);

    while (iterator.next()) |enr_txt| {
        const trimmed = std.mem.trim(u8, enr_txt, " \t\r\n");
        if (trimmed.len == 0) continue; // Skip empty entries

        const encoded_enr = try EncodedENR.decodeTxtInto(trimmed);

        try enr_list.append(encoded_enr);
    }
}

/// Saves multiple ENRs to a single file
pub fn saveMultipleEnrsToDisk(file_path: []const u8, enrs: []ENR, delimiter: []const u8) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    for (enrs, 0..) |*enr, i| {
        var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
        const out = try enr.encodeToTxt(&txt_buffer);
        try file.writeAll(out);

        if (i < enrs.len - 1) {
            try file.writeAll(delimiter);
        }
    }
}

/// Saves multiple SignableENRs to a single file
pub fn saveMultipleSignableEnrsToDisk(file_path: []const u8, signable_enrs: []SignableENR, delimiter: []const u8) !void {
    if (std.fs.path.dirname(file_path)) |dir_path| {
        try std.fs.cwd().makePath(dir_path);
    }

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    for (signable_enrs, 0..) |*signable_enr, i| {
        var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
        const out = try signable_enr.encodeToTxt(&txt_buffer);
        try file.writeAll(out);

        if (i < signable_enrs.len - 1) {
            try file.writeAll(delimiter);
        }
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

test "single ENR file operations" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var enr: ENR = undefined;
    try ENR.decodeTxtInto(&enr, test_enrs[0]);

    try std.testing.expectEqual(3, enr.seq);
    var ip_buffer: [16]u8 = undefined;
    try std.testing.expectEqualStrings("4.157.240.54", (try enr.getIpStr(&ip_buffer)).?);
    var sig_buffer: [130]u8 = undefined;
    try std.testing.expectEqualStrings("0xc384b303fadb2cc38d2c164b86048ed4d9e4f3baafae423ea6019204d392ba5a79d43cb84528d6e3002ed248bdbdb0fd6584566839cadd5402e2b57edc5453b4", try enr.getSignatureStr(&sig_buffer, .lower));
    var pubkey_buffer: [68]u8 = undefined;
    try std.testing.expectEqualStrings("0x037e897ca0bafa5c9ec5b1d01813b96926128c96ce06fefeaa40e18a2545866ffb", try enr.getPublicKeyStr(&pubkey_buffer, .lower));
    try std.testing.expectEqual(@as(u16, 9000), (try enr.getUdp()).?);

    const test_file = "test_single_enr.txt";

    const tmp_file = try tmp_dir.dir.createFile(test_file, .{});
    var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
    const out = try enr.encodeToTxt(&txt_buffer);
    try tmp_file.writeAll(out);
    tmp_file.close();

    var loaded_enr: ENR = undefined;
    const read_file = try tmp_dir.dir.openFile(test_file, .{});
    defer read_file.close();

    const file_size = try read_file.getEndPos();
    var enr_txt: [enrlib.max_enr_size]u8 = undefined;
    _ = try read_file.readAll(enr_txt[0..file_size]);
    try ENR.decodeTxtInto(&loaded_enr, enr_txt[0..file_size]);

    var original_encoded: [1024]u8 = undefined;
    var loaded_encoded: [1024]u8 = undefined;

    try enr.encodeInto(&original_encoded);
    try loaded_enr.encodeInto(&loaded_encoded);

    const original_len = enr.encodedLen();
    const loaded_len = loaded_enr.encodedLen();

    try testing.expectEqual(original_len, loaded_len);
    try testing.expectEqualSlices(u8, original_encoded[0..original_len], loaded_encoded[0..loaded_len]);
}

test "multiple ENRs with newline delimiter" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;
    var enr_list = std.ArrayList(ENR).init(allocator);
    defer enr_list.deinit();

    for (test_enrs[0..5]) |enr_txt| {
        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, enr_txt);
        try enr_list.append(enr);
    }

    const test_file = "test_multiple_enrs_newline.txt";

    const tmp_file = try tmp_dir.dir.createFile(test_file, .{});
    for (enr_list.items, 0..) |*enr, i| {
        var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
        const out = try enr.encodeToTxt(&txt_buffer);
        try tmp_file.writeAll(out);

        if (i < enr_list.items.len - 1) {
            try tmp_file.writeAll("\n");
        }
    }
    tmp_file.close();

    var loaded_enr_list = std.ArrayList(ENR).init(allocator);
    defer loaded_enr_list.deinit();

    const read_file = try tmp_dir.dir.openFile(test_file, .{});
    defer read_file.close();

    const file_size = try read_file.getEndPos();
    const file_content = try allocator.alloc(u8, file_size);
    defer allocator.free(file_content);

    _ = try read_file.readAll(file_content);

    var iterator = std.mem.splitSequence(u8, file_content, "\n");

    while (iterator.next()) |enr_txt| {
        const trimmed = std.mem.trim(u8, enr_txt, " \t\r\n");
        if (trimmed.len == 0) continue;

        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, trimmed);
        try loaded_enr_list.append(enr);
    }

    try testing.expectEqual(enr_list.items.len, loaded_enr_list.items.len);

    for (enr_list.items, loaded_enr_list.items) |*original, *loaded| {
        var original_encoded: [1024]u8 = undefined;
        var loaded_encoded: [1024]u8 = undefined;

        try original.encodeInto(&original_encoded);
        try loaded.encodeInto(&loaded_encoded);

        const original_len = original.encodedLen();
        const loaded_len = loaded.encodedLen();

        try testing.expectEqual(original_len, loaded_len);
        try testing.expectEqualSlices(u8, original_encoded[0..original_len], loaded_encoded[0..loaded_len]);
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

    const file = try tmp_dir.dir.createFile(test_file, .{});
    try file.writeAll("invalid-enr-content");
    file.close();

    var enr: ENR = undefined;
    const read_file = try tmp_dir.dir.openFile(test_file, .{});
    defer read_file.close();

    const file_size = try read_file.getEndPos();
    var enr_txt: [enrlib.max_enr_size]u8 = undefined;
    _ = try read_file.readAll(enr_txt[0..file_size]);

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

    const file = try tmp_dir.dir.createFile(test_file, .{});
    var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
    const out = try enr.encodeToTxt(&txt_buffer);
    try file.writeAll(out);
    file.close();

    var loaded_enr: ENR = undefined;
    const read_file = try tmp_dir.dir.openFile(test_file, .{});
    defer read_file.close();

    const file_size = try read_file.getEndPos();
    var enr_txt: [enrlib.max_enr_size]u8 = undefined;
    _ = try read_file.readAll(enr_txt[0..file_size]);
    try ENR.decodeTxtInto(&loaded_enr, enr_txt[0..file_size]);
}

test "empty and whitespace handling in multiple ENRs" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;

    const test_file = "test_empty_entries.txt";

    const file = try tmp_dir.dir.createFile(test_file, .{});
    const content = test_enrs[0] ++ "\n\n  \t  \n" ++ test_enrs[1] ++ "\n   \n" ++ test_enrs[2];
    try file.writeAll(content);
    file.close();

    var enr_list = std.ArrayList(ENR).init(allocator);
    defer enr_list.deinit();

    const read_file = try tmp_dir.dir.openFile(test_file, .{});
    defer read_file.close();

    const file_size = try read_file.getEndPos();
    const file_content = try allocator.alloc(u8, file_size);
    defer allocator.free(file_content);

    _ = try read_file.readAll(file_content);

    var iterator = std.mem.splitSequence(u8, file_content, "\n");

    while (iterator.next()) |enr_txt| {
        const trimmed = std.mem.trim(u8, enr_txt, " \t\r\n");
        if (trimmed.len == 0) continue;

        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, trimmed);
        try enr_list.append(enr);
    }

    try testing.expectEqual(@as(usize, 3), enr_list.items.len);
}

test "custom delimiter" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const allocator = testing.allocator;
    var enr_list = std.ArrayList(ENR).init(allocator);
    defer enr_list.deinit();

    for (test_enrs[12..14]) |enr_txt| {
        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, enr_txt);
        try enr_list.append(enr);
    }

    const test_file = "test_custom_delimiter.txt";

    const file = try tmp_dir.dir.createFile(test_file, .{});
    for (enr_list.items, 0..) |*enr, i| {
        var txt_buffer: [enrlib.max_enr_size * 2 + 4]u8 = undefined;
        const out = try enr.encodeToTxt(&txt_buffer);
        try file.writeAll(out);

        if (i < enr_list.items.len - 1) {
            try file.writeAll(" | ");
        }
    }
    file.close();

    var loaded_enr_list = std.ArrayList(ENR).init(allocator);
    defer loaded_enr_list.deinit();

    const read_file = try tmp_dir.dir.openFile(test_file, .{});
    defer read_file.close();

    const file_size = try read_file.getEndPos();
    const file_content = try allocator.alloc(u8, file_size);
    defer allocator.free(file_content);

    _ = try read_file.readAll(file_content);

    var iterator = std.mem.splitSequence(u8, file_content, " | ");

    while (iterator.next()) |enr_txt| {
        const trimmed = std.mem.trim(u8, enr_txt, " \t\r\n");
        if (trimmed.len == 0) continue;

        var enr: ENR = undefined;
        try ENR.decodeTxtInto(&enr, trimmed);
        try loaded_enr_list.append(enr);
    }

    try testing.expectEqual(enr_list.items.len, loaded_enr_list.items.len);
}

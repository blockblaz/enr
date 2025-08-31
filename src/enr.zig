// This code originally copy from https://github.com/ChainSafe/zig-discv5/blob/aa2cd1735a575b8ce663914ac6279ad0ba3c4ede/src/enr.zig
// with replacements of the secp256k1 algorithm and adding some helper functions.
const std = @import("std");

const rlp = @import("rlp.zig");

const RLPReader = rlp.RLPReader;
const RLPWriter = rlp.RLPWriter;

const Keccak = std.crypto.hash.sha3.Keccak256;
const secp256k1 = @import("secp256k1.zig");

const digest_size = secp256k1.digest_size;
pub const max_enr_size = 300;
pub const signature_size = 64;
// non-kv bytes
// list_len_len, list_len, sig_len_len, sig_len, sig, seq, id_len, id_byte
pub const max_kvs_size = max_enr_size - signature_size - 7;

// assuming single-byte keys, empty values
pub const max_kvs = max_kvs_size / 3;

/// Key-Value store for ENR
pub const KVs = struct {
    map: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn init() KVs {
        return KVs{
            .map = std.StringHashMap([]const u8).init(std.heap.page_allocator),
            .allocator = std.heap.page_allocator,
        };
    }

    pub fn deinit(self: *KVs) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    pub fn put(self: *KVs, key: []const u8, value: []const u8) !void {
        const owned_key = try self.allocator.dupe(u8, key);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.map.put(owned_key, owned_value);
    }

    pub fn get(self: *const KVs, key: []const u8) ?[]const u8 {
        return self.map.get(key);
    }

    pub fn append(self: *KVs, key: []const u8, value: []const u8) !void {
        try self.put(key, value);
    }

    pub const Iterator = struct {
        keys: std.ArrayList([]const u8),
        map: *const std.StringHashMap([]const u8),
        index: usize,

        pub fn init(kvs: *const KVs) Iterator {
            var keys = std.ArrayList([]const u8).init(kvs.allocator);

            var map_it = kvs.map.iterator();
            while (map_it.next()) |entry| {
                keys.append(entry.key_ptr.*) catch unreachable;
            }

            std.sort.heap([]const u8, keys.items, {}, struct {
                fn lessThan(context: void, a: []const u8, b: []const u8) bool {
                    _ = context;
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.lessThan);

            return Iterator{
                .keys = keys,
                .map = &kvs.map,
                .index = 0,
            };
        }

        pub fn next(self: *Iterator) ?[2][]const u8 {
            if (self.index >= self.keys.items.len) return null;

            const key = self.keys.items[self.index];
            const value = self.map.get(key).?;
            self.index += 1;

            return [2][]const u8{ key, value };
        }

        pub fn deinit(self: *Iterator) void {
            self.keys.deinit();
        }
    };

    pub fn iterator(self: *const KVs) Iterator {
        return Iterator.init(self);
    }
};

/// ID scheme for ENR
pub const IDScheme = enum {
    v4,

    pub fn init(id: []const u8) Error!IDScheme {
        if (std.mem.eql(u8, id, "v4")) {
            return IDScheme.v4;
        } else {
            return Error.BadID;
        }
    }

    pub fn publicKeyKey(id: IDScheme) []const u8 {
        switch (id) {
            .v4 => return "secp256k1",
        }
    }

    pub fn publicKey(id: IDScheme, value: []const u8) Error!PublicKey {
        switch (id) {
            .v4 => {
                return PublicKey{ .v4 = secp256k1.PublicKey.fromSlice(value) catch return Error.BadPubkey };
            },
        }
    }

    pub fn publicKeyFromKVs(id: IDScheme, kvs: *KVs) Error!PublicKey {
        switch (id) {
            .v4 => {
                return try id.publicKey(kvs.get(id.publicKeyKey()) orelse return Error.BadPubkey);
            },
        }
    }
};

/// Key pair for ENR
pub const KeyPair = union(IDScheme) {
    v4: secp256k1.SecretKey,

    pub fn fromSecretKeyString(secret: []const u8) !KeyPair {
        const key = try secp256k1.SecretKey.fromString(secret);
        return KeyPair{ .v4 = key };
    }

    pub fn fromSecretKeySlice(slice: []const u8) !KeyPair {
        const key = try secp256k1.SecretKey.fromSlice(slice);
        return KeyPair{ .v4 = key };
    }

    pub fn generate() KeyPair {
        return KeyPair{ .v4 = secp256k1.SecretKey.generate() };
    }

    pub fn generateWithRandom(rng: std.Random) KeyPair {
        return KeyPair{ .v4 = secp256k1.SecretKey.generateWithRandom(rng) };
    }

    pub fn sign(self: KeyPair, data: []const u8) ![signature_size]u8 {
        switch (self) {
            .v4 => |kp| {
                var hashed: [digest_size]u8 = undefined;
                Keccak.hash(data, &hashed, .{});

                const msg = secp256k1.Message.fromDigest(hashed);
                const sig = secp256k1.getSecp256k1Context().signEcdsa(&msg, &kp);
                return sig.serializeCompact();
            },
        }
    }

    pub fn publicKey(self: KeyPair) PublicKey {
        switch (self) {
            .v4 => |kp| {
                return PublicKey{ .v4 = kp.publicKey(secp256k1.getSecp256k1Context().*) };
            },
        }
    }
};

/// Public key for ENR
pub const PublicKey = union(IDScheme) {
    v4: secp256k1.PublicKey,

    pub fn init(id: IDScheme, data: []const u8) !PublicKey {
        switch (id) {
            .v4 => {
                return PublicKey{ .v4 = try secp256k1.PublicKey.fromSlice(data) };
            },
        }
    }

    pub fn verify(self: PublicKey, data: []const u8, signature: []const u8) Error!void {
        switch (self) {
            .v4 => |pk| {
                var hashed: [digest_size]u8 = undefined;
                Keccak.hash(data, &hashed, .{});

                return try secp256k1.getSecp256k1Context().verifyEcdsa(secp256k1.Message.fromDigest(hashed), try secp256k1.Signature.fromCompact(signature), pk);
            },
        }
    }

    pub fn verifier(self: PublicKey, signature: []const u8) Error!secp256k1.Verifier {
        switch (self) {
            .v4 => |pk| {
                return secp256k1.Verifier.init(secp256k1.Signature.fromCompact(signature) catch return error.BadSignature, pk);
            },
        }
    }

    pub fn nodeId(self: PublicKey) NodeId {
        switch (self) {
            .v4 => |pk| {
                var node_id: NodeId = undefined;
                Keccak.hash(&pk.serializeUncompressed(), &node_id, .{});
                return node_id;
            },
        }
    }
};

pub const node_id_size = 32;
pub const NodeId = [node_id_size]u8;

const Error = rlp.RLPReader.Error || error{
    TooShort,
    TooLong,
    BadPrefix,
    BadKVs,
    BadID,
    BadPubkey,
    BadSignature,
};

/// ENR (Ethereum Node Record) - A fully parsed and validated ENR for network operations.
///
/// This type provides immediate access to all ENR fields after parsing and validation.
/// It maintains the complete node information including IP address, ports, public key,
/// and signature in memory for fast access during network discovery protocols.
pub const ENR = struct {
    kvs: KVs,
    seq: u64,
    signature: [signature_size]u8,

    pub fn deinit(self: *ENR) void {
        self.kvs.deinit();
    }

    pub fn get(self: *ENR, key: []const u8) ?[]const u8 {
        return self.kvs.get(key);
    }

    pub fn id(self: *ENR) IDScheme {
        return IDScheme.init(self.kvs.get("id").?) catch unreachable;
    }

    pub fn publicKey(self: *ENR) PublicKey {
        return self.id().publicKeyFromKVs(&self.kvs) catch unreachable;
    }

    pub fn nodeId(self: *ENR) NodeId {
        return self.publicKey().nodeId();
    }

    pub fn encodeInto(self: *ENR, out: []u8) !void {
        try encodeIntoFromComponents(out, &self.kvs, self.seq, self.signature);
    }

    pub fn encodedLen(self: *ENR) usize {
        return totalLen(&self.kvs, self.seq);
    }

    /// Encode ENR to base64 text format (with "enr:" prefix)
    /// The `out` buffer must be at least `encodedTxtLen()` bytes long
    pub fn encodeToTxt(self: *ENR, out: []u8) ![]u8 {
        const binary_len = self.encodedLen();
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded_len = encoder.calcSize(binary_len);
        const required_len = 4 + encoded_len;

        if (out.len < required_len) {
            return error.BufferTooSmall;
        }

        var binary_buf: [max_enr_size]u8 = undefined;
        try self.encodeInto(binary_buf[0..binary_len]);

        @memcpy(out[0..4], "enr:");
        _ = encoder.encode(out[4 .. 4 + encoded_len], binary_buf[0..binary_len]);

        return out[0 .. 4 + encoded_len];
    }

    /// Calculate the length needed for the encoded text format (including "enr:" prefix)
    pub fn encodedTxtLen(self: *ENR) usize {
        const binary_len = self.encodedLen();
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const base64_len = encoder.calcSize(binary_len);
        return 4 + base64_len; // "enr:" + base64
    }

    pub fn decodeInto(enr: *ENR, data: []const u8) Error!void {
        if (data.len < 8 + signature_size) {
            return Error.TooShort;
        }
        if (data.len > max_enr_size) {
            return Error.TooLong;
        }

        var outer_reader = RLPReader.init(data);
        const list_data = try outer_reader.read(.{.long_list});
        var list_reader = RLPReader.init(list_data);

        const sig = try list_reader.read(.{.long_string});

        const seq_pos = list_reader.pos;
        const seq_bytes = try list_reader.read(.{ .single_byte, .short_string });
        const seq = std.mem.readVarInt(u64, seq_bytes, .big);

        var kvs = KVs.init();
        while (!list_reader.finished()) {
            const key = list_reader.read(.{ .short_string, .long_string }) catch unreachable;
            const value = list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;

            kvs.put(key, value) catch unreachable;
        }

        const id_scheme = try IDScheme.init(kvs.get("id") orelse return Error.BadID);
        const public_key = id_scheme.publicKeyFromKVs(&kvs) catch return Error.BadPubkey;

        // Verify the signature, streaming the signed data to the verifier
        var sig_verifier = try public_key.verifier(sig);

        // signed_data_list = length_prefix + elements
        {
            const elements = list_reader.data[seq_pos..];
            var length_prefix_buf: [2]u8 = undefined;
            var writer = RLPWriter.init(&length_prefix_buf);
            writer.writeListLength(elements.len) catch unreachable;
            const length_prefix = length_prefix_buf[0..writer.pos];

            // write the length prefix
            sig_verifier.update(length_prefix);
            // write the elements
            sig_verifier.update(elements);

            sig_verifier.verify() catch return Error.BadSignature;
        }

        // the ENR has been proven valid, write
        @memcpy(&enr.signature, sig);
        enr.seq = seq;
        enr.kvs = kvs;
    }

    pub fn decodeTxtInto(enr: *ENR, source: []const u8) !void {
        if (!std.mem.eql(u8, source[0..4], "enr:")) {
            return Error.BadPrefix;
        }

        var buffer: [max_enr_size]u8 = undefined;
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const size = try decoder.calcSizeForSlice(source[4..]);
        try decoder.decode(buffer[0..size], source[4..]);

        try decodeInto(enr, buffer[0..size]);
    }

    pub fn getIp(self: *ENR) !?std.net.Ip4Address {
        if (self.get("ip")) |ip_bytes| {
            if (ip_bytes.len != 4) return error.InvalidLength;
            return std.net.Ip4Address.init(ip_bytes[0..4].*, 0);
        }
        return null;
    }

    pub fn getIpStr(self: *ENR, out: []u8) !?[]const u8 {
        if (self.get("ip")) |ip_bytes| {
            if (ip_bytes.len != 4) return error.InvalidLength;
            const formatted = try std.fmt.bufPrint(out, "{}.{}.{}.{}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] });
            return formatted;
        }
        return null;
    }

    pub fn getUdp(self: *ENR) !?u16 {
        if (self.get("udp")) |udp_bytes| {
            if (udp_bytes.len != 2) return error.InvalidLength;
            return std.mem.readInt(u16, udp_bytes[0..2], .big);
        }
        return null;
    }

    pub fn getPublicKeyStr(self: *ENR, out: []u8, case: std.fmt.Case) ![]const u8 {
        const pk = self.publicKey();
        const serialized = switch (pk) {
            .v4 => |p| p.serialize(),
        };

        const public_key_hex = std.fmt.bytesToHex(serialized, case);
        if (out.len < public_key_hex.len + 2) return error.BufferTooSmall;
        @memcpy(out[0..2], "0x");
        @memcpy(out[2 .. public_key_hex.len + 2], public_key_hex[0..public_key_hex.len]);
        return out[0 .. public_key_hex.len + 2];
    }

    pub fn getSignatureStr(self: *ENR, out: []u8, case: std.fmt.Case) ![]const u8 {
        const signature_hex = std.fmt.bytesToHex(self.signature, case);
        if (out.len < signature_hex.len + 2) return error.BufferTooSmall;
        @memcpy(out[0..2], "0x");
        @memcpy(out[2 .. signature_hex.len + 2], signature_hex[0..signature_hex.len]);
        return out[0 .. signature_hex.len + 2];
    }
};

/// SignableENR - A mutable ENR builder for creating and updating node records.
///
/// This type allows programmatic construction of ENR records by setting various
/// key-value pairs before signing with a private key. It handles the ENR encoding
/// format and ensures proper structure before signature generation.
pub const SignableENR = struct {
    kvs: KVs,
    seq: u64,
    kp: KeyPair,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.kvs.deinit();
    }

    pub fn create(key_pair: KeyPair) SignableENR {
        var kvs = KVs.init();
        switch (key_pair) {
            .v4 => |kp| {
                kvs.put("id", "v4") catch unreachable;
                kvs.put("secp256k1", &kp.publicKey(secp256k1.getSecp256k1Context().*).serialize()) catch unreachable;
            },
        }
        return SignableENR{ .kp = key_pair, .kvs = kvs, .seq = 0 };
    }

    pub fn fromSecretKeyString(key: []const u8) !SignableENR {
        return SignableENR.create(try KeyPair.fromSecretKeyString(key));
    }

    pub fn fromSecretKeySlice(key: []const u8) !SignableENR {
        return SignableENR.create(try KeyPair.fromSecretKeySlice(key));
    }

    pub fn get(self: *Self, key: []const u8) ?[]const u8 {
        return self.kvs.get(key);
    }

    pub fn set(self: *Self, key: []const u8, value: []const u8) !void {
        try self.kvs.put(key, value);
    }

    pub fn id(self: *Self) IDScheme {
        return IDScheme.init(self.kvs.get("id").?) catch unreachable;
    }

    pub fn publicKey(self: *Self) PublicKey {
        return self.id().publicKeyFromKVs(&self.kvs) catch unreachable;
    }

    pub fn nodeId(self: *Self) NodeId {
        return self.publicKey().nodeId();
    }

    pub fn sign(self: *Self) ![signature_size]u8 {
        var buffer = [_]u8{0} ** max_enr_size;
        try encodeSignedPayload(&buffer, &self.kvs, self.seq);
        const signed = buffer[0..signedLen(&self.kvs, self.seq)];
        return try self.kp.sign(signed);
    }

    pub fn encodeInto(self: *Self, out: []u8) !void {
        const signature = try self.sign();
        try encodeIntoFromComponents(out, &self.kvs, self.seq, signature);
    }

    pub fn encodedLen(self: *Self) usize {
        return totalLen(&self.kvs, self.seq);
    }

    /// Calculate the length needed for the encoded text format (including "enr:" prefix)
    pub fn encodedTxtLen(self: *Self) usize {
        const binary_len = self.encodedLen();
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const base64_len = encoder.calcSize(binary_len);
        return 4 + base64_len; // "enr:" + base64
    }

    /// Encode SignableENR to base64 text format (with "enr:" prefix)
    /// The `out` buffer must be at least `encodedTxtLen()` bytes long
    pub fn encodeToTxt(self: *Self, out: []u8) ![]u8 {
        const binary_len = self.encodedLen();
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded_len = encoder.calcSize(binary_len);
        const required_len = 4 + encoded_len;

        if (out.len < required_len) {
            return error.BufferTooSmall;
        }

        var binary_buf: [max_enr_size]u8 = undefined;
        try self.encodeInto(binary_buf[0..binary_len]);

        @memcpy(out[0..4], "enr:");
        _ = encoder.encode(out[4 .. 4 + encoded_len], binary_buf[0..binary_len]);

        return out[0..required_len];
    }

    pub fn getIp(self: *Self) !?std.net.Ip4Address {
        if (self.get("ip")) |ip_bytes| {
            if (ip_bytes.len != 4) return error.InvalidLength;
            return std.net.Ip4Address.init(ip_bytes[0..4].*, 0);
        }
        return null;
    }

    pub fn getIpStr(self: *Self, out: []u8) !?[]const u8 {
        if (self.get("ip")) |ip_bytes| {
            if (ip_bytes.len != 4) return error.InvalidLength;
            const formatted = try std.fmt.bufPrint(out, "{}.{}.{}.{}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] });
            return formatted;
        }
        return null;
    }

    pub fn getUdp(self: *Self) !?u16 {
        if (self.get("udp")) |udp_bytes| {
            if (udp_bytes.len != 2) return error.InvalidLength;
            return std.mem.readInt(u16, udp_bytes[0..2], .big);
        }
        return null;
    }

    pub fn getPublicKeyStr(self: *Self, out: []u8, case: std.fmt.Case) ![]const u8 {
        const pk = self.publicKey();
        const serialized = switch (pk) {
            .v4 => |p| p.serialize(),
        };

        const public_key_hex = std.fmt.bytesToHex(serialized, case);
        if (out.len < public_key_hex.len + 2) return error.BufferTooSmall;
        @memcpy(out[0..2], "0x");
        @memcpy(out[2 .. public_key_hex.len + 2], public_key_hex[0..public_key_hex.len]);
        return out[0 .. public_key_hex.len + 2];
    }

    pub fn signStr(self: *Self, out: []u8, case: std.fmt.Case) ![]const u8 {
        const signature_hex = std.fmt.bytesToHex(try self.sign(), case);
        if (out.len < signature_hex.len + 2) return error.BufferTooSmall;
        @memcpy(out[0..2], "0x");
        @memcpy(out[2 .. signature_hex.len + 2], signature_hex[0..signature_hex.len]);
        return out[0 .. signature_hex.len + 2];
    }
};

fn encodeIntoFromComponents(out: []u8, kvs: *KVs, seq: u64, signature: [signature_size]u8) !void {
    var writer = RLPWriter.init(out);
    try writer.writeListLength(listLen(kvs, seq));
    try writer.writeString(&signature);
    try writer.writeInt(u64, seq);

    var kvs_it = kvs.iterator();
    defer kvs_it.deinit();

    while (kvs_it.next()) |entry| {
        try writer.writeString(entry[0]);
        try writer.writeString(entry[1]);
    }
}

fn encodeSignedPayload(out: []u8, kvs: *KVs, seq: u64) !void {
    var writer = RLPWriter.init(out);
    try writer.writeListLength(signedListLen(kvs, seq));
    try writer.writeInt(u64, seq);

    var kvs_it = kvs.iterator();
    defer kvs_it.deinit();

    while (kvs_it.next()) |entry| {
        try writer.writeString(entry[0]);
        try writer.writeString(entry[1]);
    }
}

/// The length of the whole rlp list
fn totalLen(kvs: *KVs, seq: u64) usize {
    const list_len = listLen(kvs, seq);
    return rlp.elemLen(list_len);
}

/// The length of all rlp list elements
fn listLen(kvs: *KVs, seq: u64) usize {
    return signedListLen(kvs, seq) + rlp.elemLen(signature_size); // signature
}

/// The length of the rlp list that is signed over
fn signedLen(kvs: *KVs, seq: u64) usize {
    const list_len = signedListLen(kvs, seq);
    return rlp.elemLen(list_len);
}

/// The length of the rlp list elements that are signed over
fn signedListLen(kvs: *KVs, seq: u64) usize {
    var length: usize = 0;
    length += rlp.intLen(u64, seq); // seq
    length += kvsLen(kvs);

    return length;
}

fn kvsLen(kvs: *KVs) usize {
    var length: usize = 0;
    var it = kvs.iterator();
    defer it.deinit();

    while (it.next()) |entry| {
        length += rlp.elemLen(entry[0].len);
        length += rlp.elemLen(entry[1].len);
    }
    return length;
}

pub fn decodeTxtIntoRlp(dest: []u8, source: []const u8) ![]u8 {
    if (!std.mem.eql(u8, source[0..4], "enr:")) {
        return Error.BadPrefix;
    }

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const size = try decoder.calcSizeForSlice(source[4..]);
    try decoder.decode(dest[0..size], source[4..]);

    return dest[0..size];
}

/// EncodedENR - A lightweight wrapper around raw ENR text representation.
///
/// This type stores the ENR in its encoded string format and provides lazy parsing
/// capabilities. Fields are decoded on-demand when accessed, making it memory-efficient
/// for scenarios where not all ENR data needs to be processed immediately.
/// Methods assume that data is a valid RLP-encoded ENR
pub const EncodedENR = struct {
    data: [max_enr_size]u8,
    len: usize,

    const Self = @This();

    /// Ensures that `data` is a valid ENR
    pub fn init(data: []const u8) Error!Self {
        if (data.len > max_enr_size) return Error.TooLong;

        var self = Self{
            .data = undefined,
            .len = data.len,
        };
        @memcpy(self.data[0..data.len], data);

        try self.verify();
        return self;
    }

    pub fn getData(self: *const Self) []const u8 {
        return self.data[0..self.len];
    }

    pub fn signature(self: *const Self) [signature_size]u8 {
        var outer_reader = RLPReader.init(self.getData());
        const list_data = outer_reader.read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        const sig = list_reader.read(.{.long_string}) catch unreachable;
        return sig[0..signature_size].*;
    }

    pub fn seq(self: *const Self) u64 {
        var outer_reader = RLPReader.init(self.getData());
        const list_data = outer_reader.read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        _ = list_reader.read(.{.long_string}) catch unreachable;

        const seq_bytes = list_reader.read(.{ .single_byte, .short_string }) catch unreachable;
        return std.mem.readVarInt(u64, seq_bytes, .big);
    }

    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        var outer_reader = RLPReader.init(self.getData());
        const list_data = outer_reader.read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        // signature
        _ = list_reader.read(.{.long_string}) catch unreachable;
        // seq
        _ = list_reader.read(.{ .single_byte, .short_string }) catch unreachable;

        while (!list_reader.finished()) {
            const k = list_reader.read(.{ .short_string, .long_string }) catch unreachable;
            if (std.mem.eql(u8, k, key)) {
                return list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;
            } else {
                _ = list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;
            }
        }
        return null;
    }

    pub fn id(self: *const Self) IDScheme {
        return IDScheme.init(self.get("id").?) catch unreachable;
    }

    pub fn publicKey(self: *const Self) PublicKey {
        const id_scheme = self.id();
        return id_scheme.publicKey(self.get(id_scheme.publicKeyKey()).?) catch unreachable;
    }

    pub fn nodeId(self: *const Self) NodeId {
        return self.publicKey().nodeId();
    }

    pub fn verify(self: *const Self) Error!void {
        const data = self.getData();
        // Sanity bounds checks
        if (data.len < 3 + signature_size) {
            return Error.TooShort;
        }
        if (data.len > max_enr_size) {
            return Error.TooLong;
        }

        // The outer rlp must be a long list because the required elements are > 55 bytes
        var outer_reader = RLPReader.init(data);
        const list_data = try outer_reader.read(.{.long_list});
        var list_reader = RLPReader.init(list_data);

        const sig = try list_reader.read(.{.long_string});

        const seq_pos = list_reader.pos;
        _ = try list_reader.read(.{ .single_byte, .short_string });

        // Check the kvs
        // - id key must be present
        // - keys must be unique
        // - keys must be sorted
        var kvs = KVs.init();
        defer kvs.deinit();
        while (!list_reader.finished()) {
            const key = try list_reader.read(.{ .short_string, .long_string });
            const value = try list_reader.read(.{ .single_byte, .short_string, .long_string });
            kvs.append(key, value) catch return Error.BadKVs;
        }

        const id_scheme = try IDScheme.init(kvs.get("id") orelse return Error.BadID);
        const public_key = try id_scheme.publicKey(kvs.get(id_scheme.publicKeyKey()).?);

        // Verify the signature, streaming the signed data to the verifier
        var sig_verifier = try public_key.verifier(sig);

        // signed_data_list = length_prefix + elements
        {
            const elements = list_reader.data[seq_pos..];
            var length_prefix_buf: [2]u8 = undefined;
            var writer = RLPWriter.init(&length_prefix_buf);
            writer.writeListLength(elements.len) catch unreachable;
            const length_prefix = length_prefix_buf[0..writer.pos];

            // write the length prefix
            sig_verifier.update(length_prefix);
            // write the elements
            sig_verifier.update(elements);

            sig_verifier.verify() catch return Error.BadSignature;
        }
    }

    pub fn decodeIntoENR(self: *const Self, enr: *ENR) void {
        var outer_reader = RLPReader.init(self.getData());
        const list_data = outer_reader.read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        const sig = list_reader.read(.{.long_string}) catch unreachable;
        @memcpy(&enr.signature, sig);

        const seq_bytes = list_reader.read(.{ .single_byte, .short_string }) catch unreachable;
        enr.seq = std.mem.readVarInt(u64, seq_bytes, .big);

        enr.kvs = KVs.init();
        while (!list_reader.finished()) {
            const key = list_reader.read(.{ .short_string, .long_string }) catch unreachable;
            const value = list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;

            enr.kvs.put(key, value) catch unreachable;
        }
    }

    pub fn decodeTxtInto(source: []const u8) !Self {
        if (!std.mem.eql(u8, source[0..4], "enr:")) {
            return Error.BadPrefix;
        }

        const decoder = std.base64.url_safe_no_pad.Decoder;
        const size = try decoder.calcSizeForSlice(source[4..]);

        if (size > max_enr_size) return Error.TooLong;

        var buffer: [max_enr_size]u8 = undefined;
        try decoder.decode(buffer[0..size], source[4..]);

        return Self.init(buffer[0..size]);
    }

    pub fn getIp(self: *const Self) !?std.net.Ip4Address {
        if (self.get("ip")) |ip_bytes| {
            if (ip_bytes.len != 4) return error.InvalidLength;
            return std.net.Ip4Address.init(ip_bytes[0..4].*, 0);
        }
        return null;
    }

    pub fn getIpStr(self: *const Self, out: []u8) !?[]const u8 {
        if (self.get("ip")) |ip_bytes| {
            if (ip_bytes.len != 4) return error.InvalidLength;
            const formatted = try std.fmt.bufPrint(out, "{}.{}.{}.{}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] });
            return formatted;
        }
        return null;
    }

    pub fn getUdp(self: *const Self) !?u16 {
        if (self.get("udp")) |udp_bytes| {
            if (udp_bytes.len != 2) return error.InvalidLength;
            return std.mem.readInt(u16, udp_bytes[0..2], .big);
        }
        return null;
    }

    pub fn getPublicKeyStr(self: *const Self, out: []u8, case: std.fmt.Case) ![]const u8 {
        const pk = self.publicKey();
        const serialized = switch (pk) {
            .v4 => |p| p.serialize(),
        };

        const public_key_hex = std.fmt.bytesToHex(serialized, case);
        if (out.len < public_key_hex.len + 2) return error.BufferTooSmall;
        @memcpy(out[0..2], "0x");
        @memcpy(out[2 .. public_key_hex.len + 2], public_key_hex[0..public_key_hex.len]);
        return out[0 .. public_key_hex.len + 2];
    }

    pub fn getSignatureStr(self: *const Self, out: []u8, case: std.fmt.Case) ![]const u8 {
        const signature_hex = std.fmt.bytesToHex(self.signature(), case);
        if (out.len < signature_hex.len + 2) return error.BufferTooSmall;
        @memcpy(out[0..2], "0x");
        @memcpy(out[2 .. signature_hex.len + 2], signature_hex[0..signature_hex.len]);
        return out[0 .. signature_hex.len + 2];
    }
};

test "ENR test vector" {
    const enr_txt = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
    var private_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&private_key, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const kp = try secp256k1.SecretKey.fromSlice(&private_key);

    const public_key = kp.publicKey(secp256k1.getSecp256k1Context().*).serialize();
    var signature: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&signature, "7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c");

    const seq: u64 = 1;
    const id = "v4";
    const ip = "\x7f\x00\x00\x01";
    const udp = "\x76\x5f";

    var decoded_enr: ENR = undefined;
    try ENR.decodeTxtInto(&decoded_enr, enr_txt);
    defer decoded_enr.deinit();

    // std.debug.print("{any}\n", .{decoded_enr});
    // ensure all decoded values match the test vector
    try std.testing.expectEqualSlices(u8, &signature, &decoded_enr.signature);
    try std.testing.expectEqual(seq, decoded_enr.seq);
    try std.testing.expectEqualSlices(u8, &public_key, decoded_enr.kvs.get("secp256k1").?);
    try std.testing.expectEqualSlices(u8, id, decoded_enr.kvs.get("id").?);
    try std.testing.expectEqualSlices(u8, ip, decoded_enr.kvs.get("ip").?);
    try std.testing.expectEqualSlices(u8, udp, decoded_enr.kvs.get("udp").?);
    var ip_out: [16]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1", (try decoded_enr.getIpStr(&ip_out)).?);
    try std.testing.expectEqual(30303, (try decoded_enr.getUdp()).?);
    var public_key_buf: [100]u8 = undefined;
    const public_key_out = try decoded_enr.getPublicKeyStr(&public_key_buf, .lower);
    try std.testing.expectEqualSlices(u8, "0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138", public_key_out);

    try std.testing.expectEqual((try std.net.Address.parseIp4("127.0.0.1", 0)).in, (try decoded_enr.getIp()).?);
    var sig_buf: [150]u8 = undefined;
    const sig_out = try decoded_enr.getSignatureStr(&sig_buf, .lower);
    try std.testing.expectEqualSlices(u8, "0x7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c", sig_out);
    var expected_binary: [max_enr_size]u8 = undefined;
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const expected_size = try decoder.calcSizeForSlice(enr_txt[4..]);
    try decoder.decode(expected_binary[0..expected_size], enr_txt[4..]);

    var txt: [max_enr_size]u8 = undefined;
    const len = decoded_enr.encodedLen();
    try decoded_enr.encodeInto(txt[0..len]);
    try std.testing.expectEqualSlices(u8, txt[0..len], expected_binary[0..expected_size]);

    const expected_txt_len = decoded_enr.encodedTxtLen();
    const actual_txt_len = enr_txt.len;
    try std.testing.expectEqual(actual_txt_len, expected_txt_len);

    var encoded_txt_buf: [1000]u8 = undefined;
    const encoded_txt = try decoded_enr.encodeToTxt(&encoded_txt_buf);
    try std.testing.expectEqualStrings(enr_txt, encoded_txt);

    var small_buf: [10]u8 = undefined;
    const encode_result = decoded_enr.encodeToTxt(&small_buf);
    try std.testing.expectError(error.BufferTooSmall, encode_result);

    var signable_enr = SignableENR.create(KeyPair{ .v4 = kp });
    defer signable_enr.deinit();
    signable_enr.seq = seq;
    try signable_enr.set("ip", ip);
    try signable_enr.set("udp", udp);

    try std.testing.expectEqualSlices(u8, signable_enr.get("id").?, decoded_enr.get("id").?);
    try std.testing.expectEqualSlices(u8, signable_enr.get("ip").?, decoded_enr.get("ip").?);
    try std.testing.expectEqualSlices(u8, signable_enr.get("udp").?, decoded_enr.get("udp").?);
    try std.testing.expectEqual(signable_enr.seq, decoded_enr.seq);
    try std.testing.expectEqualSlices(u8, signable_enr.kvs.get("secp256k1").?, decoded_enr.kvs.get("secp256k1").?);
    var ip_out2: [16]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1", (try signable_enr.getIpStr(&ip_out2)).?);
    try std.testing.expectEqual(30303, (try signable_enr.getUdp()).?);
    var public_key_buf2: [100]u8 = undefined;
    const public_key_out2 = try signable_enr.getPublicKeyStr(&public_key_buf2, .lower);
    try std.testing.expectEqualSlices(u8, "0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138", public_key_out2);
    try std.testing.expectEqual((try std.net.Address.parseIp4("127.0.0.1", 0)).in, (try signable_enr.getIp()).?);
    var sig_buf1: [150]u8 = undefined;
    const sig_out2 = try signable_enr.signStr(&sig_buf1, .lower);
    try std.testing.expectEqualSlices(u8, "0x7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c", sig_out2);

    const x = try signable_enr.sign();
    try std.testing.expectEqualSlices(u8, &signature, &x);

    const signable_txt_len = signable_enr.encodedTxtLen();
    var signable_txt_buf: [1000]u8 = undefined;
    const signable_encoded_txt = try signable_enr.encodeToTxt(&signable_txt_buf);

    try std.testing.expectEqualStrings(enr_txt, signable_encoded_txt);
    try std.testing.expectEqual(enr_txt.len, signable_txt_len);

    const kp1 = try KeyPair.fromSecretKeyString("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var signable_enr1 = SignableENR.create(kp1);
    defer signable_enr1.deinit();
    signable_enr1.seq = seq;
    try signable_enr1.set("ip", ip);
    try signable_enr1.set("udp", udp);

    try std.testing.expectEqualSlices(u8, signable_enr.get("id").?, decoded_enr.get("id").?);
    try std.testing.expectEqualSlices(u8, signable_enr.get("ip").?, decoded_enr.get("ip").?);
    try std.testing.expectEqualSlices(u8, signable_enr.get("udp").?, decoded_enr.get("udp").?);

    var signable_enr2 = try SignableENR.fromSecretKeyString("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    defer signable_enr2.deinit();
    signable_enr2.seq = seq;
    try signable_enr2.set("ip", ip);
    try signable_enr2.set("udp", udp);

    try std.testing.expectEqualSlices(u8, signable_enr2.get("id").?, decoded_enr.get("id").?);
    try std.testing.expectEqualSlices(u8, signable_enr2.get("ip").?, decoded_enr.get("ip").?);
    try std.testing.expectEqualSlices(u8, signable_enr2.get("udp").?, decoded_enr.get("udp").?);

    const encoded_enr = try EncodedENR.decodeTxtInto(enr_txt);
    try std.testing.expectEqualStrings(&decoded_enr.signature, &encoded_enr.signature());
    try std.testing.expectEqual(decoded_enr.seq, encoded_enr.seq());
    try std.testing.expectEqual(decoded_enr.id(), encoded_enr.id());
    try std.testing.expectEqualSlices(u8, encoded_enr.get("ip").?, decoded_enr.get("ip").?);
    try std.testing.expectEqualSlices(u8, encoded_enr.get("udp").?, decoded_enr.get("udp").?);
    var ip_out3: [16]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1", (try encoded_enr.getIpStr(&ip_out3)).?);
    try std.testing.expectEqual(30303, (try encoded_enr.getUdp()).?);
    var public_key_buf3: [100]u8 = undefined;
    const public_key_out3 = try encoded_enr.getPublicKeyStr(&public_key_buf3, .lower);
    try std.testing.expectEqualSlices(u8, "0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138", public_key_out3);
    try std.testing.expectEqual((try std.net.Address.parseIp4("127.0.0.1", 0)).in, (try encoded_enr.getIp()).?);
    var sig_buf3: [150]u8 = undefined;
    const sig_out3 = try encoded_enr.getSignatureStr(&sig_buf3, .lower);
    try std.testing.expectEqualSlices(u8, "0x7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c", sig_out3);
}

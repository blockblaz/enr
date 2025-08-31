// This code originally copy from https://github.com/ChainSafe/zig-discv5/blob/aa2cd1735a575b8ce663914ac6279ad0ba3c4ede/src/rlp.zig
// with bug fixes.
const std = @import("std");

pub const SingleByte = struct {
    data: []const u8,
};
pub const ShortString = struct {
    data: []const u8,
};
pub const LongString = struct {
    data: []const u8,
};
pub const ShortList = struct {
    data: []const u8,
};
pub const LongList = struct {
    data: []const u8,
};
pub const Element = union(enum) {
    single_byte: SingleByte,
    short_string: ShortString,
    long_string: LongString,
    short_list: ShortList,
    long_list: LongList,
};

fn intBitLen(comptime T: type, num: T) u8 {
    return std.math.log2_int(T, num) + 1;
}

fn intByteLen(comptime T: type, num: T) u8 {
    return (intBitLen(T, num) + 7) / 8;
}

pub fn intLen(comptime T: type, num: T) usize {
    comptime {
        const type_info = @typeInfo(T);
        if (type_info != .int or type_info.int.signedness != .unsigned) {
            @compileError("T must be an unsigned integer type");
        }
    }

    return if (num < 128) 1 else 1 + intByteLen(T, num);
}

pub fn elemLen(byte_len: usize) usize {
    if (byte_len < 56) {
        return 1 + byte_len;
    } else {
        return 1 + intByteLen(usize, byte_len) + byte_len;
    }
}

pub const RLPWriter = struct {
    data: []u8,
    pos: usize,

    const WriteError = error{
        BufferTooSmall,
    };

    const Self = @This();

    pub fn init(data: []u8) Self {
        return .{ .data = data, .pos = 0 };
    }

    pub fn writeByte(self: *Self, byte: u8) WriteError!void {
        if (self.pos >= self.data.len) {
            return WriteError.BufferTooSmall;
        }

        self.data[self.pos] = byte;
        self.pos += 1;
    }

    fn writeBytes(self: *Self, bytes: []const u8) WriteError!void {
        if (self.pos + bytes.len > self.data.len) {
            return WriteError.BufferTooSmall;
        }

        std.mem.copyForwards(u8, self.data[self.pos..], bytes);
        self.pos += bytes.len;
    }

    fn writeIntRaw(self: *Self, comptime T: type, value: T, byte_len: u8) WriteError!void {
        // const bytes_in_type = @divExact(@typeInfo(T).Int.bits, 8);
        const bytes_in_type = 8;
        var buffer = [_]u8{0} ** bytes_in_type;
        std.mem.writeInt(u64, &buffer, @as(T, @intCast(value)), .big);
        try self.writeBytes(buffer[bytes_in_type - byte_len ..]);
    }

    fn writeLength(self: *Self, len: usize, prefix: u8) WriteError!void {
        const bits = std.math.log2_int(usize, len) + 1;
        const len_len = (bits + 7) / 8;
        try self.writeByte(prefix + len_len);

        try self.writeIntRaw(usize, len, len_len);
    }

    pub fn writeListLength(self: *Self, len: usize) WriteError!void {
        if (len < 56) {
            try self.writeByte(0xc0 + @as(u8, @intCast(len)));
        } else {
            try self.writeLength(len, 0xf7);
        }
    }

    pub fn writeString(self: *Self, data: []const u8) WriteError!void {
        if (data.len < 56) {
            try self.writeByte(0x80 + @as(u8, @intCast(data.len)));
        } else {
            try self.writeLength(data.len, 0xb7);
        }
        try self.writeBytes(data);
    }

    pub fn writeInt(self: *Self, comptime T: type, value: T) WriteError!void {
        if (value == 0) {
            try self.writeByte(0x80);
        } else if (value < 128) {
            try self.writeByte(@as(u8, @intCast(value)));
        } else {
            const bits = std.math.log2_int(T, value) + 1;
            const len = (bits + 7) / 8;
            try self.writeByte(0x80 + @as(u8, @intCast(len)));

            try self.writeIntRaw(T, value, len);
        }
    }

    pub fn writeElement(self: *Self, element: Element) WriteError!void {
        switch (element) {
            .single_byte => |s| {
                try self.writeByte(s.data[0]);
            },
            .short_string => |s| {
                try self.writeByte(0x80 + s.data.len);
                try self.writeBytes(s.data);
            },
            .long_string => |s| {
                try self.writeLength(s.data.len, 0xb7);
                try self.writeBytes(s.data);
            },
            .short_list => |l| {
                try self.writeByte(0xc0 + l.data.len);
                try self.writeBytes(l.data);
            },
            .long_list => |l| {
                try self.writeLength(l.data.len, 0xf7);
                try self.writeBytes(l.data);
            },
        }
    }
};

pub const RLPReader = struct {
    data: []const u8,
    pos: usize,

    const Self = @This();

    pub const Error = error{ EndOfSlice, InvalidType };

    pub fn init(data: []const u8) Self {
        return .{ .data = data, .pos = 0 };
    }

    pub fn finished(self: *Self) bool {
        return self.pos >= self.data.len;
    }

    fn readByte(self: *Self) Error!u8 {
        if (self.pos >= self.data.len) {
            return Error.EndOfSlice;
        }
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    fn readBytes(self: *Self, size: usize) Error![]const u8 {
        const end_pos = self.pos + size;
        if (end_pos > self.data.len) {
            return Error.EndOfSlice;
        }
        const data = self.data[self.pos..end_pos];
        self.pos = end_pos;
        return data;
    }

    fn readLength(self: *Self, len_len: u8) Error!u32 {
        if (len_len > 8) {
            return Error.EndOfSlice;
        }
        const len_bytes = try self.readBytes(len_len);
        return std.mem.readVarInt(u32, len_bytes, .big);
    }

    pub fn readString(self: *Self) Error![]const u8 {
        const b = try self.readByte();
        if (b < 0x80) {
            return Error.InvalidType;
        } else if (b < 0xb8) {
            const size = b - 0x80;
            return try self.readBytes(size);
        } else if (b < 0xc0) {
            const size_len = b - 0xb7;
            const size = try self.readLength(size_len);
            return try self.readBytes(size);
        } else {
            return Error.InvalidType;
        }
    }

    pub fn readList(self: *Self) Error![]const u8 {
        const b = try self.readByte();
        if (b < 0xc0) {
            return Error.InvalidType;
        } else if (b < 0xf8) {
            const size = b - 0xc0;
            return try self.readBytes(size);
        } else {
            const size_len = b - 0xf7;
            const size = try self.readLength(size_len);
            return try self.readBytes(size);
        }
    }

    /// Read the next rlp element, limited to the provided `element_types`.
    ///
    /// Will error if the next element is not one of the provided types
    pub fn read(self: *Self, comptime element_types: anytype) Error![]const u8 {
        comptime {
            for (element_types) |element_type| {
                switch (element_type) {
                    .single_byte, .short_string, .long_string, .short_list, .long_list => {},
                    else => @compileError("Invalid element_type"),
                }
            }
        }
        const b = try self.readByte();
        inline for (element_types) |element_type| {
            switch (element_type) {
                .single_byte => if (b < 0x80) return self.data[self.pos - 1 .. self.pos],
                .short_string => if (b >= 0x80 and b < 0xb8) return self.readBytes(b - 0x80),
                .long_string => if (b >= 0xb8 and b < 0xc0) return self.readBytes(try self.readLength(b - 0xb7)),
                .short_list => if (b >= 0xc0 and b < 0xf8) return self.readBytes(b - 0xc0),
                .long_list => if (b >= 0xf8) return self.readBytes(try self.readLength(b - 0xf7)),
                else => return Error.InvalidType,
            }
        }
        return Error.InvalidType;
    }

    pub fn readElement(self: *Self) Error!Element {
        const b = try self.readByte();
        if (b < 0x80) {
            return Element{ .single_byte = .{ .data = self.data[self.pos - 1 .. self.pos] } };
        } else if (b < 0xb8) {
            const size = b - 0x80;
            const data = try self.readBytes(size);
            return Element{ .short_string = .{ .data = data } };
        } else if (b < 0xc0) {
            const size_len = b - 0xb7;
            const size = try self.readLength(size_len);
            const data = try self.readBytes(size);
            return Element{ .long_string = .{ .data = data } };
        } else if (b < 0xf8) {
            const size = b - 0xc0;
            const data = try self.readBytes(size);
            return Element{ .short_list = .{ .data = data } };
        } else {
            const size_len = b - 0xf7;
            const size = try self.readLength(size_len);
            const data = try self.readBytes(size);
            return Element{ .long_list = .{ .data = data } };
        }
    }
    pub fn next(self: *Self) ?Element {
        return self.readElement() catch null;
    }
};

test "RLPReader" {
    var buf = [_]u8{0} ** 128;
    var writer = RLPWriter.init(&buf);
    try writer.writeString("hello");
    try writer.writeString("world");

    var reader = RLPReader.init(&buf);
    _ = try reader.read(.{.short_string});
    _ = try reader.read(.{.short_string});
}

const std = @import("std");
const secp256k1 = @import("secp256k1");

pub const SecretKey = secp256k1.SecretKey;
pub const PublicKey = secp256k1.PublicKey;
pub const Message = secp256k1.Message;
pub const Signature = secp256k1.ecdsa.Signature;
pub const Secp256k1 = secp256k1.Secp256k1;
pub const digest_size = 32;

/// Global context for secp256k1 operations
var global_secp_ctx: ?Secp256k1 = null;
var secp_once = std.once(initSecp256k1Context);

/// Initializes the global context for secp256k1 operations.
fn initSecp256k1Context() void {
    global_secp_ctx = Secp256k1.genNew();
}

/// Deinitializes the global context for secp256k1 operations.
pub fn deinitSecp256k1Context() void {
    if (global_secp_ctx) |*ctx| {
        ctx.deinit();
        global_secp_ctx = null;
    }
}

/// Returns a pointer to the global context for secp256k1 operations.
pub fn getSecp256k1Context() *Secp256k1 {
    secp_once.call();
    return &global_secp_ctx.?;
}

/// A streaming verifier for secp256k1 signatures
pub const Verifier = struct {
    hasher: std.crypto.hash.sha3.Keccak256,
    signature: secp256k1.ecdsa.Signature,
    public_key: PublicKey,

    pub fn init(signature: Signature, public_key: PublicKey) Verifier {
        return Verifier{
            .hasher = std.crypto.hash.sha3.Keccak256.init(.{}),
            .signature = signature,
            .public_key = public_key,
        };
    }

    pub fn update(self: *Verifier, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn verify(self: *Verifier) !void {
        var hash: [digest_size]u8 = undefined;
        self.hasher.final(&hash);

        const message = secp256k1.Message.fromDigest(hash);

        try getSecp256k1Context().verifyEcdsa(message, self.signature, self.public_key);
    }
};

test "secp256k1 verify" {
    // taken from enr test vector
    var data_buffer: [1000]u8 = undefined;
    var private_key_buffer: [32]u8 = undefined;
    var public_key_buffer: [64]u8 = undefined;
    var signature_buffer: [64]u8 = undefined;
    const data_hex = "f84201826964827634826970847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31388375647082765f";
    const private_key_hex = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    const public_key_hex = "03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138";
    const signature_hex = "7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c";

    const data = try std.fmt.hexToBytes(&data_buffer, data_hex);
    const private_key = try std.fmt.hexToBytes(&private_key_buffer, private_key_hex);
    const public_key = try std.fmt.hexToBytes(&public_key_buffer, public_key_hex);
    const signature = try std.fmt.hexToBytes(&signature_buffer, signature_hex);

    const sk = try SecretKey.fromSlice(private_key);
    const pk = try PublicKey.fromSlice(public_key);
    const sig = try Signature.fromCompact(signature);

    var hash: [digest_size]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &hash, .{});
    const msg = secp256k1.Message.fromDigest(hash);
    const sig2 = getSecp256k1Context().signEcdsa(&msg, &sk);

    try getSecp256k1Context().verifyEcdsa(msg, sig, pk);
    try std.testing.expectEqualSlices(u8, &sig2.serializeCompact(), &sig.serializeCompact());
}

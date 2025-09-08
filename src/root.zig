const std = @import("std");

// Re-export all public DNS types and functions
pub const packet = @import("packet.zig");
pub const records = @import("records.zig");
pub const transport = @import("transport.zig");
pub const resolver = @import("resolver.zig");
pub const server = @import("server.zig");
pub const cache = @import("cache.zig");
pub const zone = @import("zone.zig");

// Core DNS types
pub const Header = packet.Header;
pub const Question = packet.Question;
pub const ResourceRecord = packet.ResourceRecord;
pub const Message = packet.Message;

// Record types
pub const RecordType = records.RecordType;
pub const RecordClass = records.RecordClass;
pub const Record = records.Record;

// Resolver and server
pub const Resolver = resolver.Resolver;
pub const Server = server.Server;
pub const Cache = cache.Cache;
pub const Zone = zone.Zone;

// Transport types
pub const Transport = transport.Transport;
pub const UdpTransport = transport.UdpTransport;
pub const TcpTransport = transport.TcpTransport;
pub const TlsTransport = transport.TlsTransport;
pub const HttpsTransport = transport.HttpsTransport;
pub const QuicTransport = transport.QuicTransport;

test {
    std.testing.refAllDecls(@This());
}
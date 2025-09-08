const std = @import("std");
const packet = @import("packet.zig");

pub const TransportError = error{
    ConnectionFailed,
    SendFailed,
    ReceiveFailed,
    TimeoutError,
    InvalidResponse,
    TlsError,
    HttpError,
    QuicError,
};

pub const Transport = union(enum) {
    udp: UdpTransport,
    tcp: TcpTransport,
    tls: TlsTransport,
    https: HttpsTransport,
    quic: QuicTransport,

    pub fn query(self: *Transport, allocator: std.mem.Allocator, message: packet.Message, server: []const u8, port: u16) !packet.Message {
        return switch (self.*) {
            .udp => |*transport| transport.query(allocator, message, server, port),
            .tcp => |*transport| transport.query(allocator, message, server, port),
            .tls => |*transport| transport.query(allocator, message, server, port),
            .https => |*transport| transport.query(allocator, message, server, port),
            .quic => |*transport| transport.query(allocator, message, server, port),
        };
    }

    pub fn deinit(self: *Transport) void {
        switch (self.*) {
            .udp => |*transport| transport.deinit(),
            .tcp => |*transport| transport.deinit(),
            .tls => |*transport| transport.deinit(),
            .https => |*transport| transport.deinit(),
            .quic => |*transport| transport.deinit(),
        }
    }
};

pub const UdpTransport = struct {
    socket: ?std.net.Stream = null,
    timeout_ms: u32 = 5000,

    pub fn init() UdpTransport {
        return UdpTransport{};
    }

    pub fn deinit(self: *UdpTransport) void {
        if (self.socket) |socket| {
            socket.close();
            self.socket = null;
        }
    }

    pub fn query(self: *UdpTransport, allocator: std.mem.Allocator, message: packet.Message, server: []const u8, port: u16) !packet.Message {
        _ = self;
        // Create UDP socket
        const address = try std.net.Address.resolveIp(server, port);
        const socket = try std.net.tcpConnectToAddress(address);
        defer socket.close();

        // Encode message
        const query_data = try message.encode(allocator);
        defer allocator.free(query_data);

        // Send query
        _ = try socket.writeAll(query_data);

        // Receive response
        var response_buffer: [4096]u8 = undefined;
        const bytes_read = try socket.read(&response_buffer);
        
        if (bytes_read == 0) return TransportError.InvalidResponse;

        // Decode response
        return try packet.Message.decode(allocator, response_buffer[0..bytes_read]);
    }

    pub fn serve(self: *UdpTransport, allocator: std.mem.Allocator, port: u16, handler: *const fn(packet.Message, std.mem.Allocator) anyerror!packet.Message) !void {
        _ = self;
        const address = try std.net.Address.parseIp("0.0.0.0", port);
        var server = try address.listen(.{});
        defer server.deinit();

        std.log.info("UDP DNS server listening on port {}", .{port});

        while (true) {
            const connection = try server.accept();
            defer connection.stream.close();

            // Handle connection in separate thread for concurrency
            const thread = try std.Thread.spawn(.{}, handleUdpConnection, .{ allocator, connection.stream, handler });
            thread.detach();
        }
    }

    fn handleUdpConnection(allocator: std.mem.Allocator, stream: std.net.Stream, handler: *const fn(packet.Message, std.mem.Allocator) anyerror!packet.Message) void {
        var buffer: [4096]u8 = undefined;
        const bytes_read = stream.read(&buffer) catch return;
        
        if (bytes_read == 0) return;

        const dns_query = packet.Message.decode(allocator, buffer[0..bytes_read]) catch return;
        defer {
            allocator.free(dns_query.questions);
            allocator.free(dns_query.answers);
            allocator.free(dns_query.authorities);
            allocator.free(dns_query.additionals);
        }

        const response = handler(dns_query, allocator) catch return;
        defer {
            allocator.free(response.questions);
            allocator.free(response.answers);
            allocator.free(response.authorities);
            allocator.free(response.additionals);
        }

        const response_data = response.encode(allocator) catch return;
        defer allocator.free(response_data);

        _ = stream.writeAll(response_data) catch return;
    }
};

pub const TcpTransport = struct {
    timeout_ms: u32 = 5000,

    pub fn init() TcpTransport {
        return TcpTransport{};
    }

    pub fn deinit(self: *TcpTransport) void {
        _ = self;
    }

    pub fn query(self: *TcpTransport, allocator: std.mem.Allocator, message: packet.Message, server: []const u8, port: u16) !packet.Message {
        _ = self;
        
        // Create TCP connection
        const address = try std.net.Address.resolveIp(server, port);
        const socket = try std.net.tcpConnectToAddress(address);
        defer socket.close();

        // Encode message
        const query_data = try message.encode(allocator);
        defer allocator.free(query_data);

        // TCP DNS requires length prefix (RFC 1035 4.2.2)
        const length_prefix = [2]u8{
            @intCast((query_data.len >> 8) & 0xFF),
            @intCast(query_data.len & 0xFF),
        };

        // Send length prefix + query
        _ = try socket.writeAll(&length_prefix);
        _ = try socket.writeAll(query_data);

        // Read response length prefix
        var length_buffer: [2]u8 = undefined;
        _ = try socket.read(&length_buffer);
        const response_length = (@as(u16, length_buffer[0]) << 8) | length_buffer[1];

        // Read response data
        const response_buffer = try allocator.alloc(u8, response_length);
        defer allocator.free(response_buffer);
        _ = try socket.read(response_buffer);

        // Decode response
        return try packet.Message.decode(allocator, response_buffer);
    }

    pub fn serve(self: *TcpTransport, allocator: std.mem.Allocator, port: u16, handler: *const fn(packet.Message, std.mem.Allocator) anyerror!packet.Message) !void {
        _ = self;
        
        const address = try std.net.Address.parseIp("0.0.0.0", port);
        var server = try address.listen(.{});
        defer server.deinit();

        std.log.info("TCP DNS server listening on port {}", .{port});

        while (true) {
            const connection = try server.accept();
            defer connection.stream.close();

            // Handle connection in separate thread
            const thread = try std.Thread.spawn(.{}, handleTcpConnection, .{ allocator, connection.stream, handler });
            thread.detach();
        }
    }

    fn handleTcpConnection(allocator: std.mem.Allocator, stream: std.net.Stream, handler: *const fn(packet.Message, std.mem.Allocator) anyerror!packet.Message) void {
        while (true) {
            // Read length prefix
            var length_buffer: [2]u8 = undefined;
            const length_bytes_read = stream.read(&length_buffer) catch return;
            if (length_bytes_read == 0) return; // Connection closed

            const message_length = (@as(u16, length_buffer[0]) << 8) | length_buffer[1];
            if (message_length == 0) return;

            // Read message
            const message_buffer = allocator.alloc(u8, message_length) catch return;
            defer allocator.free(message_buffer);
            
            const message_bytes_read = stream.read(message_buffer) catch return;
            if (message_bytes_read != message_length) return;

            // Decode query
            const dns_query = packet.Message.decode(allocator, message_buffer) catch return;
            defer {
                allocator.free(dns_query.questions);
                allocator.free(dns_query.answers);
                allocator.free(dns_query.authorities);
                allocator.free(dns_query.additionals);
            }

            // Handle query
            const response = handler(dns_query, allocator) catch return;
            defer {
                allocator.free(response.questions);
                allocator.free(response.answers);
                allocator.free(response.authorities);
                allocator.free(response.additionals);
            }

            // Encode response
            const response_data = response.encode(allocator) catch return;
            defer allocator.free(response_data);

            // Send length prefix + response
            const response_length_prefix = [2]u8{
                @intCast((response_data.len >> 8) & 0xFF),
                @intCast(response_data.len & 0xFF),
            };

            _ = stream.writeAll(&response_length_prefix) catch return;
            _ = stream.writeAll(response_data) catch return;
        }
    }
};

pub const TlsTransport = struct {
    timeout_ms: u32 = 5000,
    verify_cert: bool = true,

    pub fn init() TlsTransport {
        return TlsTransport{};
    }

    pub fn deinit(self: *TlsTransport) void {
        _ = self;
    }

    pub fn query(self: *TlsTransport, allocator: std.mem.Allocator, message: packet.Message, server: []const u8, port: u16) !packet.Message {
        _ = self;
        _ = allocator;
        _ = message;
        _ = server;
        _ = port;
        
        // TODO: Implement TLS transport using std.crypto.tls or external TLS library
        // For now, return an error
        return TransportError.TlsError;
    }

    pub fn serve(self: *TlsTransport, allocator: std.mem.Allocator, port: u16, handler: *const fn(packet.Message, std.mem.Allocator) anyerror!packet.Message) !void {
        _ = self;
        _ = allocator;
        _ = port;
        _ = handler;
        
        // TODO: Implement TLS server
        return TransportError.TlsError;
    }
};

pub const HttpsTransport = struct {
    timeout_ms: u32 = 5000,
    verify_cert: bool = true,
    user_agent: []const u8 = "zdns/1.0",

    pub fn init() HttpsTransport {
        return HttpsTransport{};
    }

    pub fn deinit(self: *HttpsTransport) void {
        _ = self;
    }

    pub fn query(self: *HttpsTransport, allocator: std.mem.Allocator, message: packet.Message, server: []const u8, port: u16) !packet.Message {
        _ = self;
        _ = allocator;
        _ = message;
        _ = server;
        _ = port;
        
        // TODO: Implement DNS-over-HTTPS (RFC 8484)
        // This would involve:
        // 1. Encoding DNS message as base64url
        // 2. Making HTTP/2 POST request to /dns-query endpoint
        // 3. Decoding response
        return TransportError.HttpError;
    }

    pub fn serve(self: *HttpsTransport, allocator: std.mem.Allocator, port: u16, handler: *const fn(packet.Message, std.mem.Allocator) anyerror!packet.Message) !void {
        _ = self;
        _ = allocator;
        _ = port;
        _ = handler;
        
        // TODO: Implement HTTPS server for DoH
        return TransportError.HttpError;
    }
};

pub const QuicTransport = struct {
    timeout_ms: u32 = 5000,
    verify_cert: bool = true,

    pub fn init() QuicTransport {
        return QuicTransport{};
    }

    pub fn deinit(self: *QuicTransport) void {
        _ = self;
    }

    pub fn query(self: *QuicTransport, allocator: std.mem.Allocator, message: packet.Message, server: []const u8, port: u16) !packet.Message {
        _ = self;
        _ = allocator;
        _ = message;
        _ = server;
        _ = port;
        
        // TODO: Implement DNS-over-QUIC (RFC 9250) using zquic
        // This would involve:
        // 1. Establishing QUIC connection
        // 2. Opening stream
        // 3. Sending DNS query with length prefix
        // 4. Reading response with length prefix
        return TransportError.QuicError;
    }

    pub fn serve(self: *QuicTransport, allocator: std.mem.Allocator, port: u16, handler: *const fn(packet.Message, std.mem.Allocator) anyerror!packet.Message) !void {
        _ = self;
        _ = allocator;
        _ = port;
        _ = handler;
        
        // TODO: Implement QUIC server for DoQ
        return TransportError.QuicError;
    }
};

// Helper function to create transport from string
pub fn fromString(transport_str: []const u8) !Transport {
    if (std.mem.eql(u8, transport_str, "udp")) {
        return Transport{ .udp = UdpTransport.init() };
    } else if (std.mem.eql(u8, transport_str, "tcp")) {
        return Transport{ .tcp = TcpTransport.init() };
    } else if (std.mem.eql(u8, transport_str, "tls") or std.mem.eql(u8, transport_str, "dot")) {
        return Transport{ .tls = TlsTransport.init() };
    } else if (std.mem.eql(u8, transport_str, "https") or std.mem.eql(u8, transport_str, "doh")) {
        return Transport{ .https = HttpsTransport.init() };
    } else if (std.mem.eql(u8, transport_str, "quic") or std.mem.eql(u8, transport_str, "doq")) {
        return Transport{ .quic = QuicTransport.init() };
    } else {
        return error.UnsupportedTransport;
    }
}

test "transport creation" {
    var udp = try fromString("udp");
    defer udp.deinit();
    
    var tcp = try fromString("tcp");
    defer tcp.deinit();
    
    try std.testing.expectError(error.UnsupportedTransport, fromString("unknown"));
}
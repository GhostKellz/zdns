const std = @import("std");
const packet = @import("packet.zig");
const records = @import("records.zig");
const transport = @import("transport.zig");
const zone = @import("zone.zig");
const resolver = @import("resolver.zig");

pub const ServerError = error{
    InvalidConfig,
    BindFailed,
    ServerStartFailed,
    ZoneNotFound,
    RecordNotFound,
};

pub const ServerConfig = struct {
    bind_address: []const u8 = "0.0.0.0",
    udp_port: u16 = 53,
    tcp_port: u16 = 53,
    tls_port: u16 = 853,
    https_port: u16 = 443,
    quic_port: u16 = 853,
    enable_udp: bool = true,
    enable_tcp: bool = true,
    enable_tls: bool = false,
    enable_https: bool = false,
    enable_quic: bool = false,
    max_concurrent_connections: u32 = 100,
    query_timeout_ms: u32 = 5000,
    enable_recursion: bool = false,
    enable_dnssec: bool = false,
    log_queries: bool = true,
    zones_dir: []const u8 = "zones",
    upstream_servers: []const []const u8 = &[_][]const u8{},
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    zones: std.HashMap([]const u8, zone.Zone, StringHashContext, std.hash_map.default_max_load_percentage),
    resolver_instance: ?resolver.Resolver,
    running: bool,
    
    // Transport instances
    udp_transport: ?transport.UdpTransport,
    tcp_transport: ?transport.TcpTransport,
    tls_transport: ?transport.TlsTransport,
    https_transport: ?transport.HttpsTransport,
    quic_transport: ?transport.QuicTransport,

    const StringHashContext = struct {
        pub fn hash(self: @This(), s: []const u8) u64 {
            _ = self;
            return std.hash_map.hashString(s);
        }
        
        pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
            _ = self;
            return std.mem.eql(u8, a, b);
        }
    };

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Server {
        var server = Server{
            .allocator = allocator,
            .config = config,
            .zones = std.HashMap([]const u8, zone.Zone, StringHashContext, std.hash_map.default_max_load_percentage){},
            .resolver_instance = null,
            .running = false,
            .udp_transport = null,
            .tcp_transport = null,
            .tls_transport = null,
            .https_transport = null,
            .quic_transport = null,
        };

        // Initialize transports based on configuration
        if (config.enable_udp) {
            server.udp_transport = transport.UdpTransport.init();
        }
        
        if (config.enable_tcp) {
            server.tcp_transport = transport.TcpTransport.init();
        }
        
        if (config.enable_tls) {
            server.tls_transport = transport.TlsTransport.init();
        }
        
        if (config.enable_https) {
            server.https_transport = transport.HttpsTransport.init();
        }
        
        if (config.enable_quic) {
            server.quic_transport = transport.QuicTransport.init();
        }

        // Initialize resolver for recursive queries
        if (config.enable_recursion) {
            const resolver_config = resolver.ResolverConfig{
                .servers = config.upstream_servers,
                .enable_recursion = true,
                .enable_cache = true,
            };
            server.resolver_instance = try resolver.Resolver.init(allocator, resolver_config);
        }

        return server;
    }

    pub fn deinit(self: *Server) void {
        self.stop();
        
        // Cleanup zones
        var iterator = self.zones.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.zones.deinit();

        // Cleanup resolver
        if (self.resolver_instance) |*res| {
            res.deinit();
        }

        // Cleanup transports
        if (self.udp_transport) |*t| t.deinit();
        if (self.tcp_transport) |*t| t.deinit();
        if (self.tls_transport) |*t| t.deinit();
        if (self.https_transport) |*t| t.deinit();
        if (self.quic_transport) |*t| t.deinit();
    }

    pub fn loadZone(self: *Server, zone_name: []const u8, zone_file: []const u8) !void {
        const zone_instance = try zone.Zone.fromFile(self.allocator, zone_file);
        const owned_name = try self.allocator.dupe(u8, zone_name);
        try self.zones.put(owned_name, zone_instance);
    }

    pub fn addZone(self: *Server, zone_instance: zone.Zone) !void {
        const zone_name = try self.allocator.dupe(u8, zone_instance.name);
        try self.zones.put(zone_name, zone_instance);
    }

    pub fn removeZone(self: *Server, zone_name: []const u8) void {
        if (self.zones.fetchRemove(zone_name)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit();
        }
    }

    pub fn start(self: *Server) !void {
        if (self.running) return;
        
        self.running = true;
        std.log.info("Starting DNS server on {s}", .{self.config.bind_address});

        var threads = std.ArrayList(std.Thread){};
        defer {
            for (threads.items) |thread| {
                thread.join();
            }
            threads.deinit(self.allocator);
        }

        // Start UDP server
        if (self.config.enable_udp and self.udp_transport != null) {
            const thread = try std.Thread.spawn(.{}, startUdpServer, .{self});
            try threads.append(thread);
        }

        // Start TCP server  
        if (self.config.enable_tcp and self.tcp_transport != null) {
            const thread = try std.Thread.spawn(.{}, startTcpServer, .{self});
            try threads.append(thread);
        }

        // Start TLS server
        if (self.config.enable_tls and self.tls_transport != null) {
            const thread = try std.Thread.spawn(.{}, startTlsServer, .{self});
            try threads.append(thread);
        }

        // Start HTTPS server
        if (self.config.enable_https and self.https_transport != null) {
            const thread = try std.Thread.spawn(.{}, startHttpsServer, .{self});
            try threads.append(thread);
        }

        // Start QUIC server
        if (self.config.enable_quic and self.quic_transport != null) {
            const thread = try std.Thread.spawn(.{}, startQuicServer, .{self});
            try threads.append(thread);
        }

        // Wait for shutdown signal
        while (self.running) {
            std.time.sleep(1000 * 1000 * 1000); // Sleep 1 second
        }
    }

    pub fn stop(self: *Server) void {
        self.running = false;
        std.log.info("Stopping DNS server");
    }

    fn startUdpServer(self: *Server) void {
        if (self.udp_transport) |*udp_transport| {
            udp_transport.serve(self.allocator, self.config.udp_port, handleQuery) catch |err| {
                std.log.err("UDP server error: {}", .{err});
            };
        }
    }

    fn startTcpServer(self: *Server) void {
        if (self.tcp_transport) |*tcp_transport| {
            tcp_transport.serve(self.allocator, self.config.tcp_port, handleQuery) catch |err| {
                std.log.err("TCP server error: {}", .{err});
            };
        }
    }

    fn startTlsServer(self: *Server) void {
        if (self.tls_transport) |*tls_transport| {
            tls_transport.serve(self.allocator, self.config.tls_port, handleQuery) catch |err| {
                std.log.err("TLS server error: {}", .{err});
            };
        }
    }

    fn startHttpsServer(self: *Server) void {
        if (self.https_transport) |*https_transport| {
            https_transport.serve(self.allocator, self.config.https_port, handleQuery) catch |err| {
                std.log.err("HTTPS server error: {}", .{err});
            };
        }
    }

    fn startQuicServer(self: *Server) void {
        if (self.quic_transport) |*quic_transport| {
            quic_transport.serve(self.allocator, self.config.quic_port, handleQuery) catch |err| {
                std.log.err("QUIC server error: {}", .{err});
            };
        }
    }

    // Global query handler (needs to be accessible to transport layer)
    var global_server: ?*Server = null;

    fn handleQuery(query: packet.Message, allocator: std.mem.Allocator) !packet.Message {
        const server = global_server orelse return ServerError.ServerStartFailed;
        return server.processQuery(query, allocator);
    }

    pub fn processQuery(self: *Server, query: packet.Message, allocator: std.mem.Allocator) !packet.Message {
        var response = packet.Message.init(allocator);
        
        // Copy header and set response flags
        response.header = query.header;
        response.header.flags.qr = true; // This is a response
        response.header.flags.ra = self.config.enable_recursion;
        
        if (self.config.log_queries) {
            for (query.questions) |q| {
                std.log.info("Query: {s} {s} {s}", .{ q.name, q.qtype.toString(), q.qclass.toString() });
            }
        }

        // Copy questions to response
        response.questions = try allocator.dupe(packet.Question, query.questions);
        response.header.qdcount = @intCast(response.questions.len);

        // Process each question
        var answers = std.ArrayList(packet.ResourceRecord){};
        var authorities = std.ArrayList(packet.ResourceRecord){};
        var additionals = std.ArrayList(packet.ResourceRecord){};

        for (query.questions) |question| {
            const result = self.resolveQuestion(question, allocator) catch |err| {
                response.header.flags.rcode = switch (err) {
                    ServerError.ZoneNotFound, ServerError.RecordNotFound => 3, // NXDOMAIN
                    else => 2, // SERVFAIL
                };
                continue;
            };

            // Add answers
            for (result.answers) |answer| {
                answers.append(answer) catch continue;
            }

            // Add authorities
            for (result.authorities) |authority| {
                authorities.append(authority) catch continue;
            }

            // Add additionals
            for (result.additionals) |additional| {
                additionals.append(additional) catch continue;
            }
        }

        response.answers = try answers.toOwnedSlice();
        response.authorities = try authorities.toOwnedSlice();
        response.additionals = try additionals.toOwnedSlice();
        
        response.header.ancount = @intCast(response.answers.len);
        response.header.nscount = @intCast(response.authorities.len);
        response.header.arcount = @intCast(response.additionals.len);

        return response;
    }

    fn resolveQuestion(self: *Server, question: packet.Question, allocator: std.mem.Allocator) !QueryResponse {
        // First, try to find in authoritative zones
        if (self.findInZones(question, allocator)) |result| {
            return result;
        }

        // If not found and recursion is enabled, try recursive resolution
        if (self.config.enable_recursion and self.resolver_instance != null) {
            var res = &self.resolver_instance.?;
            const recursive_result = try res.query(question.name, question.qtype);
            
            var query_response = QueryResponse{
                .answers = std.ArrayList(packet.ResourceRecord){},
                .authorities = std.ArrayList(packet.ResourceRecord){},
                .additionals = std.ArrayList(packet.ResourceRecord){},
            };

            // Convert resolver result to server format
            for (recursive_result.answers.items) |*answer| {
                const rr = packet.ResourceRecord{
                    .name = try allocator.dupe(u8, answer.name),
                    .rtype = answer.rtype,
                    .rclass = answer.rclass,
                    .ttl = answer.ttl,
                    .rdata = try allocator.dupe(u8, answer.rdata),
                };
                try query_response.answers.append(rr);
            }

            return query_response;
        }

        return ServerError.RecordNotFound;
    }

    fn findInZones(self: *Server, question: packet.Question, allocator: std.mem.Allocator) ?QueryResponse {
        _ = allocator; // Remove unused parameter warning
        
        const zone_name = self.findZoneForName(question.name) orelse return null;
        const zone_instance = self.zones.get(zone_name) orelse return null;
        
        // Look up record in zone
        _ = zone_instance; // TODO: Implement zone lookup
        
        return null; // Placeholder
    }

    fn findZoneForName(self: *Server, name: []const u8) ?[]const u8 {
        var longest_match: ?[]const u8 = null;
        var longest_length: usize = 0;

        var iterator = self.zones.iterator();
        while (iterator.next()) |entry| {
            const zone_name = entry.key_ptr.*;
            
            // Check if name ends with zone name (is in this zone)
            if (name.len >= zone_name.len) {
                const suffix = name[name.len - zone_name.len..];
                if (std.mem.eql(u8, suffix, zone_name) and zone_name.len > longest_length) {
                    longest_match = zone_name;
                    longest_length = zone_name.len;
                }
            }
        }

        return longest_match;
    }

    pub fn getStats(self: *const Server) ServerStats {
        return ServerStats{
            .zones_loaded = self.zones.count(),
            .queries_processed = 0, // Would need to track this
            .cache_hits = 0, // Would need to track this
            .uptime_seconds = 0, // Would need to track startup time
            .running = self.running,
        };
    }
};

const QueryResponse = struct {
    answers: std.ArrayList(packet.ResourceRecord),
    authorities: std.ArrayList(packet.ResourceRecord),
    additionals: std.ArrayList(packet.ResourceRecord),

    pub fn deinit(self: *QueryResponse, allocator: std.mem.Allocator) void {
        for (self.answers.items) |*rr| {
            allocator.free(rr.name);
            allocator.free(rr.rdata);
        }
        self.answers.deinit(allocator);

        for (self.authorities.items) |*rr| {
            allocator.free(rr.name);
            allocator.free(rr.rdata);
        }
        self.authorities.deinit(allocator);

        for (self.additionals.items) |*rr| {
            allocator.free(rr.name);
            allocator.free(rr.rdata);
        }
        self.additionals.deinit(allocator);
    }
};

pub const ServerStats = struct {
    zones_loaded: usize,
    queries_processed: u64,
    cache_hits: u64,
    uptime_seconds: u64,
    running: bool,
};

// Convenience functions for common server configurations
pub fn createAuthoritativeServer(allocator: std.mem.Allocator, zones_dir: []const u8) !Server {
    const config = ServerConfig{
        .enable_recursion = false,
        .zones_dir = zones_dir,
    };
    
    return Server.init(allocator, config);
}

pub fn createRecursiveServer(allocator: std.mem.Allocator, upstream_servers: []const []const u8) !Server {
    const config = ServerConfig{
        .enable_recursion = true,
        .upstream_servers = upstream_servers,
    };
    
    return Server.init(allocator, config);
}

pub fn createFullServer(allocator: std.mem.Allocator) !Server {
    const config = ServerConfig{
        .enable_udp = true,
        .enable_tcp = true,
        .enable_tls = true,
        .enable_https = true,
        .enable_quic = true,
        .enable_recursion = true,
        .enable_dnssec = true,
    };
    
    return Server.init(allocator, config);
}

test "server creation" {
    const allocator = std.testing.allocator;
    
    var server = try Server.init(allocator, ServerConfig{});
    defer server.deinit();
    
    try std.testing.expect(!server.running);
    try std.testing.expectEqual(@as(usize, 0), server.zones.count());
}

test "server stats" {
    const allocator = std.testing.allocator;
    
    var server = try Server.init(allocator, ServerConfig{});
    defer server.deinit();
    
    const stats = server.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.zones_loaded);
    try std.testing.expect(!stats.running);
}
const std = @import("std");
const zdns = @import("zdns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "query")) {
        try handleQuery(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "server")) {
        try handleServer(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "zone")) {
        try handleZone(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "version")) {
        try printVersion();
    } else if (std.mem.eql(u8, command, "help")) {
        try printUsage();
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        try printUsage();
    }
}

fn printUsage() !void {
    const usage =
        \\zdns - Zig DNS Library and Tools
        \\
        \\Usage: zdns <command> [options]
        \\
        \\Commands:
        \\  query <name> [type] [server]  - Query DNS record
        \\  server [options]              - Start DNS server
        \\  zone <command> [options]      - Zone management
        \\  version                       - Show version
        \\  help                          - Show this help
        \\
        \\Query Examples:
        \\  zdns query example.com                    # Query A record
        \\  zdns query example.com AAAA               # Query AAAA record  
        \\  zdns query example.com MX 1.1.1.1         # Query MX via specific server
        \\
        \\Server Examples:
        \\  zdns server                               # Start server on default ports
        \\  zdns server --port 5353                   # Start on custom port
        \\  zdns server --recursive                   # Enable recursion
        \\
        \\Zone Examples:
        \\  zdns zone list                            # List loaded zones
        \\  zdns zone load example.com zones/example.com.zone
        \\  zdns zone create example.com
        \\
    ;
    
    std.debug.print("{s}", .{usage});
}

fn printVersion() !void {
    std.debug.print("zdns 0.1.0 - Zig DNS Library\n", .{});
}

fn handleQuery(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len == 0) {
        std.debug.print("Error: Query name required\n", .{});
        return;
    }

    const name = args[0];
    const record_type = if (args.len > 1) parseRecordType(args[1]) orelse zdns.RecordType.A else zdns.RecordType.A;
    const server = if (args.len > 2) args[2] else null;

    std.debug.print("Querying {s} for {s} record...\n", .{ name, record_type.toString() });

    var config = zdns.resolver.ResolverConfig{};
    if (server) |srv| {
        const servers = [_][]const u8{srv};
        config.servers = &servers;
    }

    var resolver = try zdns.Resolver.init(allocator, config);
    defer resolver.deinit();

    const result = resolver.query(name, record_type) catch |err| {
        switch (err) {
            zdns.resolver.ResolverError.NameNotFound => {
                std.debug.print("Name not found: {s}\n", .{name});
                return;
            },
            zdns.resolver.ResolverError.ServerFailure => {
                std.debug.print("Server failure\n", .{});
                return;
            },
            zdns.resolver.ResolverError.TimeoutError => {
                std.debug.print("Query timeout\n", .{});
                return;
            },
            else => {
                std.debug.print("Query failed: {}\n", .{err});
                return;
            },
        }
    };

    defer {
        var mut_result = result;
        mut_result.deinit(allocator);
    }

    // Print results
    std.debug.print("\n");
    std.debug.print("Query: {s} {s} {s}\n", .{ name, record_type.toString(), zdns.RecordClass.IN.toString() });
    std.debug.print("Status: {s}\n", .{if (result.wasSuccessful()) "SUCCESS" else "FAILED"});
    std.debug.print("Authoritative: {}\n", .{result.isAuthoritative()});
    std.debug.print("\n");

    if (result.answers.items.len > 0) {
        std.debug.print("Answers ({}):\n", .{result.answers.items.len});
        for (result.answers.items) |*answer| {
            const rdata_str = try answer.toString(allocator);
            defer allocator.free(rdata_str);
            std.debug.print("  {s} {} {s} {s} {s}\n", .{
                answer.name,
                answer.ttl,
                answer.rclass.toString(),
                answer.rtype.toString(),
                rdata_str,
            });
        }
        std.debug.print("\n");
    }

    if (result.authorities.items.len > 0) {
        std.debug.print("Authority ({}):\n", .{result.authorities.items.len});
        for (result.authorities.items) |*auth| {
            const rdata_str = try auth.toString(allocator);
            defer allocator.free(rdata_str);
            std.debug.print("  {s} {} {s} {s} {s}\n", .{
                auth.name,
                auth.ttl,
                auth.rclass.toString(),
                auth.rtype.toString(),
                rdata_str,
            });
        }
        std.debug.print("\n");
    }

    if (result.additionals.items.len > 0) {
        std.debug.print("Additional ({}):\n", .{result.additionals.items.len});
        for (result.additionals.items) |*add| {
            const rdata_str = try add.toString(allocator);
            defer allocator.free(rdata_str);
            std.debug.print("  {s} {} {s} {s} {s}\n", .{
                add.name,
                add.ttl,
                add.rclass.toString(),
                add.rtype.toString(),
                rdata_str,
            });
        }
    }
}

fn handleServer(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    var config = zdns.server.ServerConfig{};
    
    // Parse server options
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        
        if (std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                const port = std.fmt.parseInt(u16, args[i + 1], 10) catch {
                    std.debug.print("Invalid port: {s}\n", .{args[i + 1]});
                    return;
                };
                config.udp_port = port;
                config.tcp_port = port;
                i += 2;
            } else {
                std.debug.print("--port requires a value\n", .{});
                return;
            }
        } else if (std.mem.eql(u8, arg, "--recursive")) {
            config.enable_recursion = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--bind")) {
            if (i + 1 < args.len) {
                config.bind_address = args[i + 1];
                i += 2;
            } else {
                std.debug.print("--bind requires a value\n", .{});
                return;
            }
        } else if (std.mem.eql(u8, arg, "--tls")) {
            config.enable_tls = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--https")) {
            config.enable_https = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--quic")) {
            config.enable_quic = true;
            i += 1;
        } else {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return;
        }
    }

    std.debug.print("Starting zdns server...\n", .{});
    std.debug.print("UDP port: {}\n", .{config.udp_port});
    std.debug.print("TCP port: {}\n", .{config.tcp_port});
    if (config.enable_tls) std.debug.print("TLS port: {}\n", .{config.tls_port});
    if (config.enable_https) std.debug.print("HTTPS port: {}\n", .{config.https_port});
    if (config.enable_quic) std.debug.print("QUIC port: {}\n", .{config.quic_port});
    std.debug.print("Recursion: {}\n", .{config.enable_recursion});
    std.debug.print("\n");

    var server = try zdns.Server.init(allocator, config);
    defer server.deinit();

    // Set up signal handling for graceful shutdown
    const signal_handler = struct {
        var srv: ?*zdns.Server = null;
        
        fn handler(sig: i32) callconv(.C) void {
            _ = sig;
            if (srv) |s| {
                s.stop();
            }
        }
    };
    
    signal_handler.srv = &server;
    _ = std.os.sigaction(std.os.SIG.INT, &std.os.Sigaction{
        .handler = .{ .handler = signal_handler.handler },
        .mask = std.os.empty_sigset,
        .flags = 0,
    }, null);

    try server.start();
}

fn handleZone(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len == 0) {
        std.debug.print("Zone command required (list, load, create, etc.)\n", .{});
        return;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "list")) {
        std.debug.print("No zones loaded.\n"); // TODO: Implement zone listing
    } else if (std.mem.eql(u8, subcommand, "load")) {
        if (args.len < 3) {
            std.debug.print("Usage: zdns zone load <zone_name> <zone_file>\n", .{});
            return;
        }
        
        const zone_name = args[1];
        const zone_file = args[2];
        
        std.debug.print("Loading zone {s} from {s}...\n", .{ zone_name, zone_file });
        
        var zone = zdns.Zone.fromFile(allocator, zone_file) catch |err| {
            std.debug.print("Failed to load zone: {}\n", .{err});
            return;
        };
        defer zone.deinit();
        
        const stats = zone.getStats();
        std.debug.print("Zone loaded successfully:\n", .{});
        std.debug.print("  Name: {s}\n", .{stats.name});
        std.debug.print("  Records: {}\n", .{stats.total_records});
        std.debug.print("  Has SOA: {}\n", .{stats.has_soa});
        
    } else if (std.mem.eql(u8, subcommand, "create")) {
        if (args.len < 2) {
            std.debug.print("Usage: zdns zone create <zone_name>\n", .{});
            return;
        }
        
        const zone_name = args[1];
        std.debug.print("Creating zone: {s}\n", .{zone_name});
        
        var zone = zdns.Zone.init(allocator, zone_name);
        defer zone.deinit();
        
        // Create basic SOA record
        const soa = zdns.records.SOARecord{
            .mname = try allocator.dupe(u8, zone_name),
            .rname = try std.fmt.allocPrint(allocator, "admin.{s}", .{zone_name}),
            .serial = @as(u32, @intCast(std.time.timestamp())),
            .refresh = 7200,
            .retry = 3600,
            .expire = 604800,
            .minimum = 86400,
        };
        defer allocator.free(soa.mname);
        defer allocator.free(soa.rname);
        
        try zone.setSOA(soa);
        
        std.debug.print("Zone created with basic SOA record.\n", .{});
        
    } else {
        std.debug.print("Unknown zone command: {s}\n", .{subcommand});
    }
}

fn parseRecordType(type_str: []const u8) ?zdns.RecordType {
    // Simple string matching instead of reflection
    if (std.mem.eql(u8, type_str, "A")) return zdns.RecordType.A;
    if (std.mem.eql(u8, type_str, "AAAA")) return zdns.RecordType.AAAA;
    if (std.mem.eql(u8, type_str, "NS")) return zdns.RecordType.NS;
    if (std.mem.eql(u8, type_str, "CNAME")) return zdns.RecordType.CNAME;
    if (std.mem.eql(u8, type_str, "SOA")) return zdns.RecordType.SOA;
    if (std.mem.eql(u8, type_str, "PTR")) return zdns.RecordType.PTR;
    if (std.mem.eql(u8, type_str, "MX")) return zdns.RecordType.MX;
    if (std.mem.eql(u8, type_str, "TXT")) return zdns.RecordType.TXT;
    if (std.mem.eql(u8, type_str, "SRV")) return zdns.RecordType.SRV;
    if (std.mem.eql(u8, type_str, "ANY")) return zdns.RecordType.ANY;
    return null;
}

// Simple demo function to show zdns in action
fn demo() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== zdns Demo ===\n\n");

    // 1. Create a resolver
    std.debug.print("1. Creating resolver...\n");
    var resolver = try zdns.Resolver.init(allocator, zdns.resolver.ResolverConfig{
        .servers = &[_][]const u8{"8.8.8.8"},
        .enable_cache = true,
    });
    defer resolver.deinit();
    std.debug.print("   ✓ Resolver created\n\n");

    // 2. Create a zone
    std.debug.print("2. Creating zone...\n");
    var zone = zdns.Zone.init(allocator, "example.local");
    defer zone.deinit();
    
    // Add some records
    const a_record = [_]u8{ 192, 168, 1, 100 };
    try zone.addRecord("www.example.local", zdns.RecordType.A, zdns.RecordClass.IN, 3600, &a_record);
    
    const ns_rdata = try std.fmt.allocPrint(allocator, "ns1.example.local");
    defer allocator.free(ns_rdata);
    try zone.addRecord("example.local", zdns.RecordType.NS, zdns.RecordClass.IN, 86400, ns_rdata);
    
    std.debug.print("   ✓ Zone created with {} records\n\n", .{zone.getAllRecords().items.len});

    // 3. Show zone stats
    const stats = zone.getStats();
    std.debug.print("3. Zone Statistics:\n");
    std.debug.print("   Name: {s}\n", .{stats.name});
    std.debug.print("   Total Records: {}\n", .{stats.total_records});
    std.debug.print("   Has SOA: {}\n", .{stats.has_soa});
    std.debug.print("\n");

    // 4. Create cache
    std.debug.print("4. Creating cache...\n");
    var cache = zdns.Cache.init(allocator, 100);
    defer cache.deinit();
    
    const cache_stats = cache.getStats();
    std.debug.print("   ✓ Cache created (max size: {})\n\n", .{cache_stats.max_size});

    std.debug.print("=== Demo Complete ===\n");
}

test "main tests" {
    std.testing.refAllDecls(@This());
}
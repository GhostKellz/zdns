const std = @import("std");
const packet = @import("packet.zig");
const records = @import("records.zig");
const transport = @import("transport.zig");
const cache = @import("cache.zig");

pub const ResolverError = error{
    NoResponse,
    ServerFailure,
    NameNotFound,
    NotImplemented,
    Refused,
    InvalidQuery,
    TimeoutError,
    MaxRedirectsExceeded,
};

pub const ResolverConfig = struct {
    servers: []const []const u8 = &[_][]const u8{ "8.8.8.8", "1.1.1.1" },
    port: u16 = 53,
    timeout_ms: u32 = 5000,
    retries: u8 = 3,
    enable_cache: bool = true,
    cache_max_size: usize = 1000,
    enable_recursion: bool = true,
    enable_dnssec: bool = false,
    transport_type: []const u8 = "udp",
    max_redirects: u8 = 10,
};

pub const Resolver = struct {
    allocator: std.mem.Allocator,
    config: ResolverConfig,
    cache_instance: ?cache.Cache,
    transport_instance: transport.Transport,
    query_id: u16,

    pub fn init(allocator: std.mem.Allocator, config: ResolverConfig) !Resolver {
        var cache_instance: ?cache.Cache = null;
        if (config.enable_cache) {
            cache_instance = cache.Cache.init(allocator, config.cache_max_size);
        }

        const transport_instance = try transport.fromString(config.transport_type);

        return Resolver{
            .allocator = allocator,
            .config = config,
            .cache_instance = cache_instance,
            .transport_instance = transport_instance,
            .query_id = 1,
        };
    }

    pub fn deinit(self: *Resolver) void {
        if (self.cache_instance) |*cache_inst| {
            cache_inst.deinit();
        }
        self.transport_instance.deinit();
    }

    pub fn query(self: *Resolver, name: []const u8, qtype: records.RecordType) !QueryResult {
        return self.queryClass(name, qtype, records.RecordClass.IN);
    }

    pub fn queryClass(self: *Resolver, name: []const u8, qtype: records.RecordType, qclass: records.RecordClass) !QueryResult {
        // Check cache first
        if (self.cache_instance) |*cache_inst| {
            if (cache_inst.get(name, qtype, qclass)) |cached_result| {
                return cached_result;
            }
        }

        // Perform actual DNS query
        const result = try self.performQuery(name, qtype, qclass);

        // Cache the result
        if (self.cache_instance) |*cache_inst| {
            cache_inst.put(name, qtype, qclass, result);
        }

        return result;
    }

    fn performQuery(self: *Resolver, name: []const u8, qtype: records.RecordType, qclass: records.RecordClass) !QueryResult {
        // Create query message
        var query_message = packet.Message.init(self.allocator);
        defer query_message.deinit(self.allocator);

        // Set header
        query_message.header.id = self.getNextQueryId();
        query_message.header.flags.rd = self.config.enable_recursion;
        query_message.header.qdcount = 1;

        // Create question
        const question = packet.Question.init(name, qtype, qclass);
        const questions = try self.allocator.alloc(packet.Question, 1);
        questions[0] = question;
        query_message.questions = questions;

        // Try each server with retries
        for (self.config.servers) |server| {
            var retry_count: u8 = 0;
            while (retry_count < self.config.retries) {
                retry_count += 1;

                const response = self.transport_instance.query(
                    self.allocator,
                    query_message,
                    server,
                    self.config.port,
                ) catch |err| {
                    if (retry_count >= self.config.retries) {
                        return err;
                    }
                    continue;
                };

                defer {
                    self.allocator.free(response.questions);
                    self.allocator.free(response.answers);
                    self.allocator.free(response.authorities);
                    self.allocator.free(response.additionals);
                }

                // Check response code
                switch (response.header.flags.rcode) {
                    0 => {}, // NOERROR
                    1 => return ResolverError.InvalidQuery, // FORMERR
                    2 => return ResolverError.ServerFailure, // SERVFAIL
                    3 => return ResolverError.NameNotFound, // NXDOMAIN
                    4 => return ResolverError.NotImplemented, // NOTIMP
                    5 => return ResolverError.Refused, // REFUSED
                    else => return ResolverError.ServerFailure,
                }

                // Convert response to QueryResult
                return try self.parseResponse(response, name, qtype, qclass);
            }
        }

        return ResolverError.NoResponse;
    }

    fn parseResponse(self: *Resolver, response: packet.Message, original_name: []const u8, original_type: records.RecordType, original_class: records.RecordClass) !QueryResult {
        var result = QueryResult{
            .name = try self.allocator.dupe(u8, original_name),
            .qtype = original_type,
            .qclass = original_class,
            .answers = std.ArrayList(ResourceRecord){},
            .authorities = std.ArrayList(ResourceRecord){},
            .additionals = std.ArrayList(ResourceRecord){},
            .rcode = response.header.flags.rcode,
            .authoritative = response.header.flags.aa,
            .truncated = response.header.flags.tc,
        };

        // Parse answers
        for (response.answers) |rr| {
            const record = ResourceRecord{
                .name = try self.allocator.dupe(u8, rr.name),
                .rtype = rr.rtype,
                .rclass = rr.rclass,
                .ttl = rr.ttl,
                .rdata = try self.allocator.dupe(u8, rr.rdata),
                .parsed = null, // Will be parsed on demand
            };
            try result.answers.append(self.allocator, record);
        }

        // Parse authorities
        for (response.authorities) |rr| {
            const record = ResourceRecord{
                .name = try self.allocator.dupe(u8, rr.name),
                .rtype = rr.rtype,
                .rclass = rr.rclass,
                .ttl = rr.ttl,
                .rdata = try self.allocator.dupe(u8, rr.rdata),
                .parsed = null,
            };
            try result.authorities.append(self.allocator, record);
        }

        // Parse additionals
        for (response.additionals) |rr| {
            const record = ResourceRecord{
                .name = try self.allocator.dupe(u8, rr.name),
                .rtype = rr.rtype,
                .rclass = rr.rclass,
                .ttl = rr.ttl,
                .rdata = try self.allocator.dupe(u8, rr.rdata),
                .parsed = null,
            };
            try result.additionals.append(self.allocator, record);
        }

        return result;
    }

    fn getNextQueryId(self: *Resolver) u16 {
        self.query_id += 1;
        return self.query_id;
    }

    // Recursive resolution
    pub fn resolve(self: *Resolver, name: []const u8, qtype: records.RecordType) !QueryResult {
        if (!self.config.enable_recursion) {
            return self.query(name, qtype);
        }

        // Start from root servers
        var current_servers = try self.allocator.dupe([]const u8, &[_][]const u8{
            "198.41.0.4",   // a.root-servers.net
            "199.9.14.201", // b.root-servers.net
            "192.33.4.12",  // c.root-servers.net
        });
        defer self.allocator.free(current_servers);

        var labels = std.ArrayList([]const u8){};
        defer {
            for (labels.items) |label| {
                self.allocator.free(label);
            }
            labels.deinit(self.allocator);
        }

        // Split name into labels
        const name_copy = try self.allocator.dupe(u8, name);
        defer self.allocator.free(name_copy);

        var it = std.mem.split(u8, name_copy, ".");
        while (it.next()) |label| {
            if (label.len > 0) {
                try labels.append(self.allocator, try self.allocator.dupe(u8, label));
            }
        }

        // Reverse labels (start from TLD)
        std.mem.reverse([]const u8, labels.items);

        var redirect_count: u8 = 0;
        const current_name = try self.allocator.dupe(u8, name);
        defer self.allocator.free(current_name);

        while (redirect_count < self.config.max_redirects) {
            redirect_count += 1;

            // Query current servers
            for (current_servers) |server| {
                const result = self.queryServer(current_name, qtype, server) catch continue;
                
                // If we got an answer, return it
                if (result.answers.items.len > 0) {
                    return result;
                }

                // Check for delegation (NS records in authority section)
                if (result.authorities.items.len > 0) {
                    // Look for NS records
                    var new_servers = std.ArrayList([]const u8){};
                    defer {
                        for (new_servers.items) |srv| {
                            self.allocator.free(srv);
                        }
                        new_servers.deinit(self.allocator);
                    }

                    for (result.authorities.items) |auth| {
                        if (auth.rtype == records.RecordType.NS) {
                            const ns_record = records.NSRecord.fromRdata(auth.rdata, self.allocator) catch continue;
                            defer self.allocator.free(ns_record.nsdname);
                            try new_servers.append(self.allocator, try self.allocator.dupe(u8, ns_record.nsdname));
                        }
                    }

                    if (new_servers.items.len > 0) {
                        // Resolve NS names to IP addresses
                        var ip_servers = std.ArrayList([]const u8){};
                        defer {
                            for (ip_servers.items) |srv| {
                                self.allocator.free(srv);
                            }
                            ip_servers.deinit(self.allocator);
                        }

                        for (new_servers.items) |ns_name| {
                            const a_result = self.queryServer(ns_name, records.RecordType.A, server) catch continue;
                            defer a_result.deinit(self.allocator);

                            for (a_result.answers.items) |answer| {
                                if (answer.rtype == records.RecordType.A) {
                                    const a_record = records.ARecord.fromRdata(answer.rdata) catch continue;
                                    const ip_str = try a_record.toString(self.allocator);
                                    try ip_servers.append(self.allocator, ip_str);
                                }
                            }
                        }

                        if (ip_servers.items.len > 0) {
                            // Update current servers and continue
                            for (current_servers) |srv| {
                                self.allocator.free(srv);
                            }
                            self.allocator.free(current_servers);
                            current_servers = try ip_servers.toOwnedSlice(self.allocator);
                            break;
                        }
                    }
                }

                result.deinit(self.allocator);
            }
        }

        return ResolverError.MaxRedirectsExceeded;
    }

    fn queryServer(self: *Resolver, name: []const u8, qtype: records.RecordType, server: []const u8) !QueryResult {
        // Create a temporary resolver config for this specific server
        var temp_config = self.config;
        const temp_servers = [_][]const u8{server};
        temp_config.servers = &temp_servers;
        temp_config.enable_recursion = false; // Don't recurse when doing iterative queries

        return self.performQuery(name, qtype, records.RecordClass.IN);
    }
};

pub const QueryResult = struct {
    name: []const u8,
    qtype: records.RecordType,
    qclass: records.RecordClass,
    answers: std.ArrayList(ResourceRecord),
    authorities: std.ArrayList(ResourceRecord),
    additionals: std.ArrayList(ResourceRecord),
    rcode: u4,
    authoritative: bool,
    truncated: bool,

    pub fn deinit(self: *QueryResult, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        
        for (self.answers.items) |*record| {
            record.deinit(allocator);
        }
        self.answers.deinit(allocator);
        
        for (self.authorities.items) |*record| {
            record.deinit(allocator);
        }
        self.authorities.deinit(allocator);
        
        for (self.additionals.items) |*record| {
            record.deinit(allocator);
        }
        self.additionals.deinit(allocator);
    }

    pub fn getAnswers(self: *QueryResult, allocator: std.mem.Allocator, rtype: records.RecordType) std.ArrayList(*ResourceRecord) {
        var result = std.ArrayList(*ResourceRecord).init(allocator);
        
        for (self.answers.items) |*record| {
            if (record.rtype == rtype) {
                result.append(allocator, record) catch continue;
            }
        }
        
        return result;
    }

    pub fn hasAnswer(self: *const QueryResult) bool {
        return self.answers.items.len > 0;
    }

    pub fn isAuthoritative(self: *const QueryResult) bool {
        return self.authoritative;
    }

    pub fn wasSuccessful(self: *const QueryResult) bool {
        return self.rcode == 0;
    }
};

pub const ResourceRecord = struct {
    name: []const u8,
    rtype: records.RecordType,
    rclass: records.RecordClass,
    ttl: u32,
    rdata: []const u8,
    parsed: ?records.Record,

    pub fn deinit(self: *ResourceRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.rdata);
    }

    pub fn getParsedRecord(self: *ResourceRecord, allocator: std.mem.Allocator) !records.Record {
        if (self.parsed) |parsed| {
            return parsed;
        }

        const parsed = try records.Record.fromRdata(self.rtype, self.rdata, allocator);
        self.parsed = parsed;
        return parsed;
    }

    pub fn toString(self: *ResourceRecord, allocator: std.mem.Allocator) ![]u8 {
        const parsed = try self.getParsedRecord(allocator);
        
        return switch (parsed) {
            .A => |record| record.toString(allocator),
            .AAAA => |record| record.toString(allocator),
            .NS => |record| allocator.dupe(u8, record.nsdname),
            .CNAME => |record| allocator.dupe(u8, record.cname),
            .PTR => |record| allocator.dupe(u8, record.ptrdname),
            .MX => |record| std.fmt.allocPrint(allocator, "{} {s}", .{ record.preference, record.exchange }),
            .TXT => |record| allocator.dupe(u8, record.text),
            else => std.fmt.allocPrint(allocator, "[{s} record]", .{@tagName(parsed)}),
        };
    }
};

// Convenience functions
pub fn resolveA(allocator: std.mem.Allocator, name: []const u8) ![]std.net.Address {
    var resolver = try Resolver.init(allocator, ResolverConfig{});
    defer resolver.deinit();

    const result = try resolver.query(name, records.RecordType.A);
    defer {
        var mut_result = result;
        mut_result.deinit(allocator);
    }

    var addresses = std.ArrayList(std.net.Address){};
    defer addresses.deinit(allocator);

    for (result.answers.items) |*record| {
        if (record.rtype == records.RecordType.A) {
            const a_record = try records.ARecord.fromRdata(record.rdata);
            const addr = std.net.Address.initIp4(a_record.address, 0);
            try addresses.append(allocator, addr);
        }
    }

    return try addresses.toOwnedSlice(allocator);
}

pub fn resolveAAAA(allocator: std.mem.Allocator, name: []const u8) ![]std.net.Address {
    var resolver = try Resolver.init(allocator, ResolverConfig{});
    defer resolver.deinit();

    const result = try resolver.query(name, records.RecordType.AAAA);
    defer {
        var mut_result = result;
        mut_result.deinit(allocator);
    }

    var addresses = std.ArrayList(std.net.Address){};
    defer addresses.deinit(allocator);

    for (result.answers.items) |*record| {
        if (record.rtype == records.RecordType.AAAA) {
            const aaaa_record = try records.AAAARecord.fromRdata(record.rdata);
            const addr = std.net.Address.initIp6(aaaa_record.address, 0, 0, 0);
            try addresses.append(allocator, addr);
        }
    }

    return try addresses.toOwnedSlice(allocator);
}

test "resolver creation" {
    const allocator = std.testing.allocator;
    
    var resolver = try Resolver.init(allocator, ResolverConfig{});
    defer resolver.deinit();
    
    try std.testing.expect(resolver.config.enable_cache);
    try std.testing.expectEqual(@as(u16, 53), resolver.config.port);
}

test "query id generation" {
    const allocator = std.testing.allocator;
    
    var resolver = try Resolver.init(allocator, ResolverConfig{});
    defer resolver.deinit();
    
    const id1 = resolver.getNextQueryId();
    const id2 = resolver.getNextQueryId();
    
    try std.testing.expect(id2 > id1);
}
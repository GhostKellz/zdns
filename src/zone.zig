const std = @import("std");
const records = @import("records.zig");
const packet = @import("packet.zig");

pub const ZoneError = error{
    InvalidZoneFile,
    ParseError,
    RecordNotFound,
    ZoneNotFound,
    DuplicateRecord,
    InvalidSOA,
};

pub const Zone = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    soa: ?records.SOARecord,
    records: std.HashMap(ZoneKey, std.ArrayList(ZoneRecord), ZoneKeyContext, std.hash_map.default_max_load_percentage),
    origin: []const u8,
    ttl: u32,
    
    const ZoneKeyContext = struct {
        pub fn hash(self: @This(), key: ZoneKey) u64 {
            _ = self;
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(key.name);
            hasher.update(std.mem.asBytes(&key.rtype));
            hasher.update(std.mem.asBytes(&key.rclass));
            return hasher.final();
        }
        
        pub fn eql(self: @This(), a: ZoneKey, b: ZoneKey) bool {
            _ = self;
            return std.mem.eql(u8, a.name, b.name) and 
                   a.rtype == b.rtype and 
                   a.rclass == b.rclass;
        }
    };

    pub fn init(allocator: std.mem.Allocator, name: []const u8) Zone {
        return Zone{
            .allocator = allocator,
            .name = allocator.dupe(u8, name) catch unreachable,
            .soa = null,
            .records = std.HashMap(ZoneKey, std.ArrayList(ZoneRecord), ZoneKeyContext, std.hash_map.default_max_load_percentage).init(allocator),
            .origin = allocator.dupe(u8, name) catch unreachable,
            .ttl = 3600, // Default TTL
        };
    }

    pub fn deinit(self: *Zone) void {
        self.allocator.free(self.name);
        self.allocator.free(self.origin);
        
        var iterator = self.records.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.name);
            for (entry.value_ptr.items) |*record| {
                record.deinit(self.allocator);
            }
            entry.value_ptr.deinit(self.allocator);
        }
        self.records.deinit();
    }

    pub fn fromFile(allocator: std.mem.Allocator, file_path: []const u8) !Zone {
        const content = try std.fs.cwd().readFileAlloc(file_path, allocator, @enumFromInt(1024 * 1024)); // 1MB max
        defer allocator.free(content);
        
        return try parseZoneFile(allocator, content);
    }

    pub fn addRecord(self: *Zone, name: []const u8, rtype: records.RecordType, rclass: records.RecordClass, ttl: u32, rdata: []const u8) !void {
        const key = ZoneKey{
            .name = try self.allocator.dupe(u8, name),
            .rtype = rtype,
            .rclass = rclass,
        };

        const record = ZoneRecord{
            .name = try self.allocator.dupe(u8, name),
            .rtype = rtype,
            .rclass = rclass,
            .ttl = ttl,
            .rdata = try self.allocator.dupe(u8, rdata),
        };

        const result = try self.records.getOrPut(key);
        if (!result.found_existing) {
            result.value_ptr.* = std.ArrayList(ZoneRecord){};
        } else {
            // Free the duplicate key
            self.allocator.free(key.name);
        }
        
        try result.value_ptr.append(self.allocator, record);
    }

    pub fn removeRecord(self: *Zone, name: []const u8, rtype: records.RecordType, rclass: records.RecordClass) void {
        const key = ZoneKey{
            .name = name,
            .rtype = rtype,
            .rclass = rclass,
        };

        if (self.records.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key.name);
            for (kv.value.items) |*record| {
                record.deinit(self.allocator);
            }
            kv.value.deinit();
        }
    }

    pub fn lookup(self: *Zone, name: []const u8, rtype: records.RecordType, rclass: records.RecordClass) ?[]const ZoneRecord {
        const key = ZoneKey{
            .name = name,
            .rtype = rtype,
            .rclass = rclass,
        };

        if (self.records.get(key)) |record_list| {
            return record_list.items;
        }
        
        return null;
    }

    pub fn lookupAny(self: *Zone, allocator: std.mem.Allocator, name: []const u8) std.ArrayList(ZoneRecord) {
        var result = std.ArrayList(ZoneRecord).init(allocator);
        
        var iterator = self.records.iterator();
        while (iterator.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.name, name)) {
                for (entry.value_ptr.items) |record| {
                    result.append(allocator, record) catch continue;
                }
            }
        }
        
        return result;
    }

    pub fn hasRecord(self: *Zone, name: []const u8, rtype: records.RecordType, rclass: records.RecordClass) bool {
        return self.lookup(name, rtype, rclass) != null;
    }

    pub fn getSOA(self: *Zone) ?records.SOARecord {
        return self.soa;
    }

    pub fn setSOA(self: *Zone, soa: records.SOARecord) !void {
        self.soa = soa;
        
        // Add SOA record to records map
        const soa_rdata = try soa.toRdata(self.allocator);
        defer self.allocator.free(soa_rdata);
        
        try self.addRecord(self.name, records.RecordType.SOA, records.RecordClass.IN, soa.minimum, soa_rdata);
    }

    pub fn incrementSerial(self: *Zone) void {
        if (self.soa) |*soa| {
            soa.serial += 1;
        }
    }

    pub fn getAllRecords(self: *Zone, allocator: std.mem.Allocator) std.ArrayList(ZoneRecord) {
        var result = std.ArrayList(ZoneRecord).init(allocator);
        
        var iterator = self.records.iterator();
        while (iterator.next()) |entry| {
            for (entry.value_ptr.items) |record| {
                result.append(allocator, record) catch continue;
            }
        }
        
        return result;
    }

    pub fn getStats(self: *const Zone) ZoneStats {
        var record_count: usize = 0;
        var type_counts = std.EnumArray(records.RecordType, usize).initFill(0);
        
        var iterator = self.records.iterator();
        while (iterator.next()) |entry| {
            record_count += entry.value_ptr.items.len;
            for (entry.value_ptr.items) |record| {
                type_counts.set(record.rtype, type_counts.get(record.rtype) + 1);
            }
        }
        
        return ZoneStats{
            .name = self.name,
            .total_records = record_count,
            .type_counts = type_counts,
            .has_soa = self.soa != null,
        };
    }

    // Zone transfer support
    pub fn transferZone(self: *Zone, writer: anytype) !void {
        // AXFR - Full zone transfer
        // Start with SOA
        if (self.soa) |soa| {
            const soa_rr = packet.ResourceRecord{
                .name = self.name,
                .rtype = records.RecordType.SOA,
                .rclass = records.RecordClass.IN,
                .ttl = soa.minimum,
                .rdata = try soa.toRdata(self.allocator),
            };
            defer self.allocator.free(soa_rr.rdata);
            try soa_rr.encode(self.allocator, writer);
        }

        // Transfer all other records
        var iterator = self.records.iterator();
        while (iterator.next()) |entry| {
            for (entry.value_ptr.items) |record| {
                if (record.rtype != records.RecordType.SOA) { // SOA already sent
                    const rr = packet.ResourceRecord{
                        .name = record.name,
                        .rtype = record.rtype,
                        .rclass = record.rclass,
                        .ttl = record.ttl,
                        .rdata = record.rdata,
                    };
                    try rr.encode(self.allocator, writer);
                }
            }
        }

        // End with SOA again
        if (self.soa) |soa| {
            const soa_rr = packet.ResourceRecord{
                .name = self.name,
                .rtype = records.RecordType.SOA,
                .rclass = records.RecordClass.IN,
                .ttl = soa.minimum,
                .rdata = try soa.toRdata(self.allocator),
            };
            defer self.allocator.free(soa_rr.rdata);
            try soa_rr.encode(self.allocator, writer);
        }
    }
};

pub const ZoneKey = struct {
    name: []const u8,
    rtype: records.RecordType,
    rclass: records.RecordClass,
};

pub const ZoneRecord = struct {
    name: []const u8,
    rtype: records.RecordType,
    rclass: records.RecordClass,
    ttl: u32,
    rdata: []const u8,

    pub fn deinit(self: *ZoneRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.rdata);
    }

    pub fn toParsed(self: *const ZoneRecord, allocator: std.mem.Allocator) !records.Record {
        return records.Record.fromRdata(self.rtype, self.rdata, allocator);
    }
};

pub const ZoneStats = struct {
    name: []const u8,
    total_records: usize,
    type_counts: std.EnumArray(records.RecordType, usize),
    has_soa: bool,
};

// Zone file parsing (simplified DNS zone file format)
fn parseZoneFile(allocator: std.mem.Allocator, content: []const u8) !Zone {
    var zone = Zone.init(allocator, "example.com"); // Default, will be overridden
    var current_name: []const u8 = "";
    var current_ttl: u32 = 3600;
    
    var lines = std.mem.splitSequence(u8, content, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        
        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == ';') continue;
        
        // Handle $ORIGIN directive
        if (std.mem.startsWith(u8, trimmed, "$ORIGIN")) {
            var parts = std.mem.splitSequence(u8, trimmed, " ");
            _ = parts.next(); // Skip $ORIGIN
            if (parts.next()) |origin| {
                zone.allocator.free(zone.origin);
                zone.origin = try allocator.dupe(u8, std.mem.trim(u8, origin, " \t"));
            }
            continue;
        }
        
        // Handle $TTL directive
        if (std.mem.startsWith(u8, trimmed, "$TTL")) {
            var parts = std.mem.splitSequence(u8, trimmed, " ");
            _ = parts.next(); // Skip $TTL
            if (parts.next()) |ttl_str| {
                current_ttl = std.fmt.parseInt(u32, std.mem.trim(u8, ttl_str, " \t"), 10) catch current_ttl;
            }
            continue;
        }
        
        // Parse resource record
        if (parseResourceRecord(allocator, trimmed, current_name, current_ttl)) |parsed| {
            current_name = parsed.name;
            current_ttl = parsed.ttl;
            
            // Handle SOA records specially
            if (parsed.rtype == records.RecordType.SOA) {
                const soa = try records.SOARecord.fromRdata(parsed.rdata, allocator);
                try zone.setSOA(soa);
                
                // Update zone name if this is the first SOA
                if (std.mem.eql(u8, zone.name, "example.com")) {
                    zone.allocator.free(zone.name);
                    zone.name = try allocator.dupe(u8, parsed.name);
                }
            }
            
            try zone.addRecord(parsed.name, parsed.rtype, parsed.rclass, parsed.ttl, parsed.rdata);
            
            allocator.free(parsed.name);
            allocator.free(parsed.rdata);
        } else |_| {
            // Skip invalid lines
            continue;
        }
    }
    
    return zone;
}

const ParsedRecord = struct {
    name: []const u8,
    rtype: records.RecordType,
    rclass: records.RecordClass,
    ttl: u32,
    rdata: []const u8,
};

fn parseResourceRecord(allocator: std.mem.Allocator, line: []const u8, current_name: []const u8, default_ttl: u32) !ParsedRecord {
    var parts = std.mem.splitSequence(u8, line, " ");
    
    // Parse name (or use current name if line starts with whitespace)
    var name: []const u8 = undefined;
    if (line[0] == ' ' or line[0] == '\t') {
        name = try allocator.dupe(u8, current_name);
    } else {
        name = try allocator.dupe(u8, std.mem.trim(u8, parts.next().?, " \t"));
    }
    
    // Parse optional TTL and class
    var ttl: u32 = default_ttl;
    var rclass = records.RecordClass.IN;
    var rtype_str: []const u8 = undefined;
    
    const next_part = std.mem.trim(u8, parts.next().?, " \t");
    
    // Check if it's a number (TTL) or record type
    if (std.fmt.parseInt(u32, next_part, 10) catch null) |parsed_ttl| {
        ttl = parsed_ttl;
        
        // Next should be class or type
        const next_next = std.mem.trim(u8, parts.next().?, " \t");
        if (std.mem.eql(u8, next_next, "IN") or std.mem.eql(u8, next_next, "CH") or std.mem.eql(u8, next_next, "HS")) {
            rclass = parseRecordClass(next_next);
            rtype_str = std.mem.trim(u8, parts.next().?, " \t");
        } else {
            rtype_str = next_next;
        }
    } else {
        rtype_str = next_part;
    }
    
    const rtype = parseRecordType(rtype_str) orelse return error.ParseError;
    
    // Parse record data
    var rdata_parts = std.ArrayList(u8){};
    defer rdata_parts.deinit(allocator);
    
    while (parts.next()) |part| {
        const trimmed_part = std.mem.trim(u8, part, " \t");
        if (trimmed_part.len > 0) {
            if (rdata_parts.items.len > 0) {
                try rdata_parts.append(allocator, ' ');
            }
            try rdata_parts.appendSlice(allocator, trimmed_part);
        }
    }
    
    // Convert rdata based on record type
    const rdata = try parseRecordData(allocator, rtype, rdata_parts.items);
    
    return ParsedRecord{
        .name = name,
        .rtype = rtype,
        .rclass = rclass,
        .ttl = ttl,
        .rdata = rdata,
    };
}

fn parseRecordType(type_str: []const u8) ?records.RecordType {
    inline for (@typeInfo(records.RecordType).@"enum".fields) |field| {
        if (std.mem.eql(u8, type_str, field.name)) {
            return @enumFromInt(field.value);
        }
    }
    return null;
}

fn parseRecordClass(class_str: []const u8) records.RecordClass {
    if (std.mem.eql(u8, class_str, "IN")) return records.RecordClass.IN;
    if (std.mem.eql(u8, class_str, "CH")) return records.RecordClass.CH;
    if (std.mem.eql(u8, class_str, "HS")) return records.RecordClass.HS;
    return records.RecordClass.IN; // Default
}

fn parseRecordData(allocator: std.mem.Allocator, rtype: records.RecordType, data: []const u8) ![]u8 {
    switch (rtype) {
        .A => {
            // Parse IPv4 address
            var parts = std.mem.splitSequence(u8, data, ".");
            var bytes: [4]u8 = undefined;
            var i: usize = 0;
            while (parts.next()) |part| {
                if (i >= 4) return error.ParseError;
                bytes[i] = try std.fmt.parseInt(u8, part, 10);
                i += 1;
            }
            if (i != 4) return error.ParseError;
            return allocator.dupe(u8, &bytes);
        },
        .AAAA => {
            // Parse IPv6 address (simplified)
            var result: [16]u8 = undefined;
            _ = try std.net.Address.parseIp6(data, 0);
            // TODO: Extract the actual bytes from the address
            return allocator.dupe(u8, &result);
        },
        .NS, .CNAME, .PTR => {
            // Domain names - encode as DNS name
            return encodeDnsName(data, allocator);
        },
        .MX => {
            // Priority + domain name
            var parts = std.mem.splitSequence(u8, data, " ");
            const priority_str = parts.next() orelse return error.ParseError;
            const exchange = parts.next() orelse return error.ParseError;
            
            const priority = try std.fmt.parseInt(u16, priority_str, 10);
            const encoded_exchange = try encodeDnsName(exchange, allocator);
            defer allocator.free(encoded_exchange);
            
            var result = try allocator.alloc(u8, 2 + encoded_exchange.len);
            std.mem.writeInt(u16, result[0..2], priority, .big);
            std.mem.copyForwards(u8, result[2..], encoded_exchange);
            return result;
        },
        .TXT => {
            // Text record - length-prefixed strings
            if (data.len > 255) return error.ParseError;
            var result = try allocator.alloc(u8, data.len + 1);
            result[0] = @intCast(data.len);
            std.mem.copyForwards(u8, result[1..], data);
            return result;
        },
        else => {
            // For other types, just return the raw data
            return allocator.dupe(u8, data);
        }
    }
}

fn encodeDnsName(name: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (name.len == 0 or (name.len == 1 and name[0] == '.')) {
        return allocator.dupe(u8, &[_]u8{0});
    }

    var result = std.ArrayList(u8){};
    defer result.deinit(allocator);

    var i: usize = 0;
    while (i < name.len) {
        const label_start = i;
        while (i < name.len and name[i] != '.') {
            i += 1;
        }
        
        const label_len = i - label_start;
        if (label_len > 63) return error.InvalidName;
        
        try result.append(allocator, @intCast(label_len));
        try result.appendSlice(allocator, name[label_start..i]);
        
        if (i < name.len) i += 1; // Skip the dot
    }
    
    try result.append(allocator, 0); // Null terminator
    return result.toOwnedSlice(allocator);
}

// Zone storage backends
pub const ZoneStorage = union(enum) {
    memory: MemoryStorage,
    file: FileStorage,
    // sql: SqlStorage, // TODO: Implement SQL storage

    pub fn loadZone(self: *ZoneStorage, allocator: std.mem.Allocator, zone_name: []const u8) !Zone {
        return switch (self.*) {
            .memory => |*storage| storage.loadZone(allocator, zone_name),
            .file => |*storage| storage.loadZone(allocator, zone_name),
            // .sql => |*storage| storage.loadZone(allocator, zone_name),
        };
    }

    pub fn saveZone(self: *ZoneStorage, zone: *Zone) !void {
        return switch (self.*) {
            .memory => |*storage| storage.saveZone(zone),
            .file => |*storage| storage.saveZone(zone),
            // .sql => |*storage| storage.saveZone(zone),
        };
    }
};

pub const MemoryStorage = struct {
    zones: std.HashMap([]const u8, Zone, StringContext, std.hash_map.default_max_load_percentage),

    const StringContext = struct {
        pub fn hash(self: @This(), s: []const u8) u64 {
            _ = self;
            return std.hash_map.hashString(s);
        }
        
        pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
            _ = self;
            return std.mem.eql(u8, a, b);
        }
    };

    pub fn init(allocator: std.mem.Allocator) MemoryStorage {
        _ = allocator;
        return MemoryStorage{
            .zones = std.HashMap([]const u8, Zone, StringContext, std.hash_map.default_max_load_percentage){},
        };
    }

    pub fn loadZone(self: *MemoryStorage, allocator: std.mem.Allocator, zone_name: []const u8) !Zone {
        _ = allocator;
        return self.zones.get(zone_name) orelse ZoneError.ZoneNotFound;
    }

    pub fn saveZone(self: *MemoryStorage, zone: *Zone) !void {
        try self.zones.put(zone.name, zone.*);
    }
};

pub const FileStorage = struct {
    base_dir: []const u8,

    pub fn init(base_dir: []const u8) FileStorage {
        return FileStorage{
            .base_dir = base_dir,
        };
    }

    pub fn loadZone(self: *FileStorage, allocator: std.mem.Allocator, zone_name: []const u8) !Zone {
        var path_buffer: [1024]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "{s}/{s}.zone", .{ self.base_dir, zone_name });
        return Zone.fromFile(allocator, path);
    }

    pub fn saveZone(self: *FileStorage, zone: *Zone) !void {
        var path_buffer: [1024]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "{s}/{s}.zone", .{ self.base_dir, zone.name });
        
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        
        var writer = file.writer();
        
        // Write zone file format
        try writer.print("$ORIGIN {s}\n", .{zone.origin});
        try writer.print("$TTL {}\n", .{zone.ttl});
        
        if (zone.soa) |soa| {
            try writer.print("{s} IN SOA {s} {s} {} {} {} {} {}\n", .{
                zone.name, soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
            });
        }
        
        var iterator = zone.records.iterator();
        while (iterator.next()) |entry| {
            for (entry.value_ptr.items) |record| {
                if (record.rtype != records.RecordType.SOA) {
                    try writer.print("{s} {} IN {s} ", .{ record.name, record.ttl, record.rtype.toString() });
                    // TODO: Format rdata properly for each record type
                    try writer.print("[rdata]\n");
                }
            }
        }
    }
};

test "zone creation" {
    const allocator = std.testing.allocator;
    
    var zone = Zone.init(allocator, "example.com");
    defer zone.deinit();
    
    try std.testing.expectEqualStrings("example.com", zone.name);
    try std.testing.expect(zone.soa == null);
}

test "zone record management" {
    const allocator = std.testing.allocator;
    
    var zone = Zone.init(allocator, "example.com");
    defer zone.deinit();
    
    // Add a record
    const a_record = [_]u8{ 192, 168, 1, 1 };
    try zone.addRecord("www.example.com", records.RecordType.A, records.RecordClass.IN, 3600, &a_record);
    
    // Look it up
    const found = zone.lookup("www.example.com", records.RecordType.A, records.RecordClass.IN);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(usize, 1), found.?.len);
}
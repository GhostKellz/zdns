const std = @import("std");
const records = @import("records.zig");

pub const CacheError = error{
    EntryNotFound,
    EntryExpired,
    CacheFull,
};

pub const CacheEntry = struct {
    key: CacheKey,
    value: CacheValue,
    expiry_time: i64, // Unix timestamp when entry expires
    access_time: i64, // For LRU eviction

    pub fn isExpired(self: *const CacheEntry) bool {
        const now = std.time.timestamp();
        return now >= self.expiry_time;
    }

    pub fn updateAccessTime(self: *CacheEntry) void {
        self.access_time = std.time.timestamp();
    }
};

pub const CacheKey = struct {
    name: []const u8,
    qtype: records.RecordType,
    qclass: records.RecordClass,

    pub fn hash(self: CacheKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.name);
        hasher.update(std.mem.asBytes(&self.qtype));
        hasher.update(std.mem.asBytes(&self.qclass));
        return hasher.final();
    }

    pub fn eql(self: CacheKey, other: CacheKey) bool {
        return std.mem.eql(u8, self.name, other.name) and 
               self.qtype == other.qtype and 
               self.qclass == other.qclass;
    }
};

pub const CacheValue = struct {
    answers: []CachedRecord,
    authorities: []CachedRecord,
    additionals: []CachedRecord,
    rcode: u4,
    authoritative: bool,
    negative: bool, // For negative caching (RFC 2308)

    pub fn deinit(self: *CacheValue, allocator: std.mem.Allocator) void {
        for (self.answers) |*record| {
            record.deinit(allocator);
        }
        allocator.free(self.answers);

        for (self.authorities) |*record| {
            record.deinit(allocator);
        }
        allocator.free(self.authorities);

        for (self.additionals) |*record| {
            record.deinit(allocator);
        }
        allocator.free(self.additionals);
    }
};

pub const CachedRecord = struct {
    name: []const u8,
    rtype: records.RecordType,
    rclass: records.RecordClass,
    ttl: u32,
    rdata: []const u8,
    cache_time: i64, // When this record was cached

    pub fn deinit(self: *CachedRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.rdata);
    }

    pub fn getRemainingTtl(self: *const CachedRecord) u32 {
        const now = std.time.timestamp();
        const elapsed = @as(u32, @intCast(@max(0, now - self.cache_time)));
        if (elapsed >= self.ttl) return 0;
        return self.ttl - elapsed;
    }

    pub fn isExpired(self: *const CachedRecord) bool {
        return self.getRemainingTtl() == 0;
    }
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    entries: std.HashMap(u64, CacheEntry, HashContext, std.hash_map.default_max_load_percentage),
    max_size: usize,
    negative_cache_ttl: u32, // TTL for negative cache entries (seconds)

    const HashContext = struct {
        pub fn hash(self: @This(), key: u64) u64 {
            _ = self;
            return key;
        }
        
        pub fn eql(self: @This(), a: u64, b: u64) bool {
            _ = self;
            return a == b;
        }
    };

    pub fn init(allocator: std.mem.Allocator, max_size: usize) Cache {
        return Cache{
            .allocator = allocator,
            .entries = std.HashMap(u64, CacheEntry, HashContext, std.hash_map.default_max_load_percentage){ 
                .unmanaged = .{}, 
                .allocator = allocator,
                .ctx = HashContext{}
            },
            .max_size = max_size,
            .negative_cache_ttl = 300, // 5 minutes default
        };
    }

    pub fn deinit(self: *Cache) void {
        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.key.name);
            entry.value_ptr.value.deinit(self.allocator);
        }
        self.entries.deinit();
    }

    pub fn put(self: *Cache, name: []const u8, qtype: records.RecordType, qclass: records.RecordClass, result: anytype) void {
        // Make space if needed
        if (self.entries.count() >= self.max_size) {
            self.evictOldest() catch return;
        }

        const key = CacheKey{
            .name = self.allocator.dupe(u8, name) catch return,
            .qtype = qtype,
            .qclass = qclass,
        };

        // Determine minimum TTL for cache expiry
        var min_ttl: u32 = if (result.answers.items.len > 0) std.math.maxInt(u32) else self.negative_cache_ttl;
        
        // Convert result to cache format
        var answers = self.allocator.alloc(CachedRecord, result.answers.items.len) catch return;
        var authorities = self.allocator.alloc(CachedRecord, result.authorities.items.len) catch return;
        var additionals = self.allocator.alloc(CachedRecord, result.additionals.items.len) catch return;

        const now = std.time.timestamp();

        // Cache answers
        for (result.answers.items, 0..) |*record, i| {
            answers[i] = CachedRecord{
                .name = self.allocator.dupe(u8, record.name) catch return,
                .rtype = record.rtype,
                .rclass = record.rclass,
                .ttl = record.ttl,
                .rdata = self.allocator.dupe(u8, record.rdata) catch return,
                .cache_time = now,
            };
            min_ttl = @min(min_ttl, record.ttl);
        }

        // Cache authorities
        for (result.authorities.items, 0..) |*record, i| {
            authorities[i] = CachedRecord{
                .name = self.allocator.dupe(u8, record.name) catch return,
                .rtype = record.rtype,
                .rclass = record.rclass,
                .ttl = record.ttl,
                .rdata = self.allocator.dupe(u8, record.rdata) catch return,
                .cache_time = now,
            };
        }

        // Cache additionals
        for (result.additionals.items, 0..) |*record, i| {
            additionals[i] = CachedRecord{
                .name = self.allocator.dupe(u8, record.name) catch return,
                .rtype = record.rtype,
                .rclass = record.rclass,
                .ttl = record.ttl,
                .rdata = self.allocator.dupe(u8, record.rdata) catch return,
                .cache_time = now,
            };
        }

        const value = CacheValue{
            .answers = answers,
            .authorities = authorities,
            .additionals = additionals,
            .rcode = result.rcode,
            .authoritative = result.authoritative,
            .negative = result.answers.items.len == 0 and result.rcode == 3, // NXDOMAIN
        };

        const entry = CacheEntry{
            .key = key,
            .value = value,
            .expiry_time = now + @as(i64, min_ttl),
            .access_time = now,
        };

        const hash_value = key.hash();
        self.entries.put(hash_value, entry) catch return;
    }

    pub fn get(self: *Cache, name: []const u8, qtype: records.RecordType, qclass: records.RecordClass) ?@import("resolver.zig").QueryResult {
        const key = CacheKey{
            .name = name,
            .qtype = qtype,
            .qclass = qclass,
        };

        const hash_value = key.hash();
        
        if (self.entries.getPtr(hash_value)) |entry| {
            // Check if expired
            if (entry.isExpired()) {
                // Remove expired entry
                self.allocator.free(entry.key.name);
                entry.value.deinit(self.allocator);
                _ = self.entries.remove(hash_value);
                return null;
            }

            // Update access time for LRU
            entry.updateAccessTime();

            // Convert back to QueryResult format
            const QueryResult = @import("resolver.zig").QueryResult;
            const ResourceRecord = @import("resolver.zig").ResourceRecord;

            var result = QueryResult{
                .name = self.allocator.dupe(u8, name) catch return null,
                .qtype = qtype,
                .qclass = qclass,
                .answers = std.ArrayList(ResourceRecord){},
                .authorities = std.ArrayList(ResourceRecord){},
                .additionals = std.ArrayList(ResourceRecord){},
                .rcode = entry.value.rcode,
                .authoritative = entry.value.authoritative,
                .truncated = false,
            };

            // Convert cached answers
            for (entry.value.answers) |*cached_record| {
                if (cached_record.isExpired()) continue;
                
                const record = ResourceRecord{
                    .name = self.allocator.dupe(u8, cached_record.name) catch continue,
                    .rtype = cached_record.rtype,
                    .rclass = cached_record.rclass,
                    .ttl = cached_record.getRemainingTtl(),
                    .rdata = self.allocator.dupe(u8, cached_record.rdata) catch continue,
                    .parsed = null,
                };
                result.answers.append(self.allocator, record) catch continue;
            }

            // Convert cached authorities
            for (entry.value.authorities) |*cached_record| {
                if (cached_record.isExpired()) continue;
                
                const record = ResourceRecord{
                    .name = self.allocator.dupe(u8, cached_record.name) catch continue,
                    .rtype = cached_record.rtype,
                    .rclass = cached_record.rclass,
                    .ttl = cached_record.getRemainingTtl(),
                    .rdata = self.allocator.dupe(u8, cached_record.rdata) catch continue,
                    .parsed = null,
                };
                result.authorities.append(self.allocator, record) catch continue;
            }

            // Convert cached additionals
            for (entry.value.additionals) |*cached_record| {
                if (cached_record.isExpired()) continue;
                
                const record = ResourceRecord{
                    .name = self.allocator.dupe(u8, cached_record.name) catch continue,
                    .rtype = cached_record.rtype,
                    .rclass = cached_record.rclass,
                    .ttl = cached_record.getRemainingTtl(),
                    .rdata = self.allocator.dupe(u8, cached_record.rdata) catch continue,
                    .parsed = null,
                };
                result.additionals.append(self.allocator, record) catch continue;
            }

            return result;
        }

        return null;
    }

    pub fn remove(self: *Cache, name: []const u8, qtype: records.RecordType, qclass: records.RecordClass) void {
        const key = CacheKey{
            .name = name,
            .qtype = qtype,
            .qclass = qclass,
        };

        const hash_value = key.hash();
        
        if (self.entries.fetchRemove(hash_value)) |kv| {
            self.allocator.free(kv.value.key.name);
            var mut_value = kv.value.value;
            mut_value.deinit(self.allocator);
        }
    }

    pub fn clear(self: *Cache) void {
        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.key.name);
            entry.value_ptr.value.deinit(self.allocator);
        }
        self.entries.clearRetainingCapacity();
    }

    pub fn size(self: *const Cache) usize {
        return self.entries.count();
    }

    pub fn cleanupExpired(self: *Cache) void {
        var to_remove = std.ArrayList(u64){};
        defer to_remove.deinit(self.allocator);

        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |hash_value| {
            if (self.entries.fetchRemove(hash_value)) |kv| {
                self.allocator.free(kv.value.key.name);
                var mut_value = kv.value.value;
            mut_value.deinit(self.allocator);
            }
        }
    }

    fn evictOldest(self: *Cache) !void {
        if (self.entries.count() == 0) return;

        var oldest_time: i64 = std.math.maxInt(i64);
        var oldest_hash: u64 = 0;

        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.access_time < oldest_time) {
                oldest_time = entry.value_ptr.access_time;
                oldest_hash = entry.key_ptr.*;
            }
        }

        if (self.entries.fetchRemove(oldest_hash)) |kv| {
            self.allocator.free(kv.value.key.name);
            var mut_value = kv.value.value;
            mut_value.deinit(self.allocator);
        }
    }

    // Statistics
    pub fn getStats(self: *const Cache) CacheStats {
        var expired_count: usize = 0;
        var negative_count: usize = 0;

        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                expired_count += 1;
            }
            if (entry.value_ptr.value.negative) {
                negative_count += 1;
            }
        }

        return CacheStats{
            .total_entries = self.entries.count(),
            .expired_entries = expired_count,
            .negative_entries = negative_count,
            .max_size = self.max_size,
            .hit_ratio = 0.0, // Would need to track hits/misses
        };
    }
};

pub const CacheStats = struct {
    total_entries: usize,
    expired_entries: usize,
    negative_entries: usize,
    max_size: usize,
    hit_ratio: f64,
};

// Negative caching implementation (RFC 2308)
pub fn putNegativeEntry(cache: *Cache, name: []const u8, qtype: records.RecordType, qclass: records.RecordClass, rcode: u4, soa_ttl: u32) void {
    const key = CacheKey{
        .name = cache.allocator.dupe(u8, name) catch return,
        .qtype = qtype,
        .qclass = qclass,
    };

    // Use SOA minimum TTL for negative caching, or default
    const ttl = if (soa_ttl > 0) soa_ttl else cache.negative_cache_ttl;

    const value = CacheValue{
        .answers = &[_]CachedRecord{},
        .authorities = &[_]CachedRecord{},
        .additionals = &[_]CachedRecord{},
        .rcode = rcode,
        .authoritative = false,
        .negative = true,
    };

    const now = std.time.timestamp();
    const entry = CacheEntry{
        .key = key,
        .value = value,
        .expiry_time = now + @as(i64, ttl),
        .access_time = now,
    };

    const hash_value = key.hash();
    cache.entries.put(hash_value, entry) catch return;
}

test "cache basic operations" {
    const allocator = std.testing.allocator;
    
    var cache = Cache.init(allocator, 10);
    defer cache.deinit();
    
    try std.testing.expectEqual(@as(usize, 0), cache.size());
    
    // Test cache stats
    const stats = cache.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.total_entries);
    try std.testing.expectEqual(@as(usize, 10), stats.max_size);
}

test "cache key hashing" {
    const key1 = CacheKey{
        .name = "example.com",
        .qtype = records.RecordType.A,
        .qclass = records.RecordClass.IN,
    };
    
    const key2 = CacheKey{
        .name = "example.com",
        .qtype = records.RecordType.A,
        .qclass = records.RecordClass.IN,
    };
    
    const key3 = CacheKey{
        .name = "different.com",
        .qtype = records.RecordType.A,
        .qclass = records.RecordClass.IN,
    };
    
    try std.testing.expect(key1.eql(key2));
    try std.testing.expect(!key1.eql(key3));
    
    try std.testing.expectEqual(key1.hash(), key2.hash());
    try std.testing.expect(key1.hash() != key3.hash());
}
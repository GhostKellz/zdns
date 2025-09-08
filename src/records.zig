const std = @import("std");

pub const RecordType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41, // EDNS(0)
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    CDS = 59,
    CDNSKEY = 60,
    CAA = 257,
    
    // Query types
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,

    pub fn toString(self: RecordType) []const u8 {
        return switch (self) {
            .A => "A",
            .NS => "NS",
            .CNAME => "CNAME",
            .SOA => "SOA",
            .PTR => "PTR",
            .MX => "MX",
            .TXT => "TXT",
            .AAAA => "AAAA",
            .SRV => "SRV",
            .OPT => "OPT",
            .DS => "DS",
            .RRSIG => "RRSIG",
            .NSEC => "NSEC",
            .DNSKEY => "DNSKEY",
            .NSEC3 => "NSEC3",
            .NSEC3PARAM => "NSEC3PARAM",
            .TLSA => "TLSA",
            .CDS => "CDS",
            .CDNSKEY => "CDNSKEY",
            .CAA => "CAA",
            .AXFR => "AXFR",
            .MAILB => "MAILB",
            .MAILA => "MAILA",
            .ANY => "ANY",
        };
    }
};

pub const RecordClass = enum(u16) {
    IN = 1,   // Internet
    CS = 2,   // CSNET
    CH = 3,   // CHAOS
    HS = 4,   // Hesiod
    ANY = 255, // Any class

    pub fn toString(self: RecordClass) []const u8 {
        return switch (self) {
            .IN => "IN",
            .CS => "CS",
            .CH => "CH",
            .HS => "HS",
            .ANY => "ANY",
        };
    }
};

pub const Record = union(RecordType) {
    A: ARecord,
    NS: NSRecord,
    CNAME: CNAMERecord,
    SOA: SOARecord,
    PTR: PTRRecord,
    MX: MXRecord,
    TXT: TXTRecord,
    AAAA: AAAARecord,
    SRV: SRVRecord,
    OPT: OPTRecord,
    DS: DSRecord,
    RRSIG: RRSIGRecord,
    NSEC: NSECRecord,
    DNSKEY: DNSKEYRecord,
    NSEC3: NSEC3Record,
    NSEC3PARAM: NSEC3Record, // Same structure as NSEC3
    TLSA: TLSARecord,
    CDS: DSRecord,
    CDNSKEY: DNSKEYRecord,
    CAA: CAARecord,
    
    // Query types - these don't have record data  
    AXFR: void,
    MAILB: void,
    MAILA: void,
    ANY: void,

    pub fn fromRdata(rtype: RecordType, rdata: []const u8, allocator: std.mem.Allocator) !Record {
        return switch (rtype) {
            .A => Record{ .A = try ARecord.fromRdata(rdata) },
            .AAAA => Record{ .AAAA = try AAAARecord.fromRdata(rdata) },
            .NS => Record{ .NS = try NSRecord.fromRdata(rdata, allocator) },
            .CNAME => Record{ .CNAME = try CNAMERecord.fromRdata(rdata, allocator) },
            .MX => Record{ .MX = try MXRecord.fromRdata(rdata, allocator) },
            .TXT => Record{ .TXT = try TXTRecord.fromRdata(rdata, allocator) },
            .PTR => Record{ .PTR = try PTRRecord.fromRdata(rdata, allocator) },
            .SOA => Record{ .SOA = try SOARecord.fromRdata(rdata, allocator) },
            .SRV => Record{ .SRV = try SRVRecord.fromRdata(rdata, allocator) },
            .DS => Record{ .DS = try DSRecord.fromRdata(rdata, allocator) },
            .RRSIG => Record{ .RRSIG = try RRSIGRecord.fromRdata(rdata, allocator) },
            .DNSKEY => Record{ .DNSKEY = try DNSKEYRecord.fromRdata(rdata, allocator) },
            .NSEC => Record{ .NSEC = try NSECRecord.fromRdata(rdata, allocator) },
            .NSEC3 => Record{ .NSEC3 = try NSEC3Record.fromRdata(rdata, allocator) },
            .NSEC3PARAM => Record{ .NSEC3PARAM = try NSEC3Record.fromRdata(rdata, allocator) },
            .TLSA => Record{ .TLSA = try TLSARecord.fromRdata(rdata, allocator) },
            .CDS => Record{ .CDS = try DSRecord.fromRdata(rdata, allocator) },
            .CDNSKEY => Record{ .CDNSKEY = try DNSKEYRecord.fromRdata(rdata, allocator) },
            .CAA => Record{ .CAA = try CAARecord.fromRdata(rdata, allocator) },
            .OPT => Record{ .OPT = try OPTRecord.fromRdata(rdata, allocator) },
            .AXFR, .MAILB, .MAILA, .ANY => @panic("Query types don't have record data"),
        };
    }

    pub fn toRdata(self: Record, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .A => |record| record.toRdata(allocator),
            .AAAA => |record| record.toRdata(allocator),
            .NS => |record| record.toRdata(allocator),
            .CNAME => |record| record.toRdata(allocator),
            .MX => |record| record.toRdata(allocator),
            .TXT => |record| record.toRdata(allocator),
            .PTR => |record| record.toRdata(allocator),
            .SOA => |record| record.toRdata(allocator),
            .SRV => |record| record.toRdata(allocator),
            .DS => |record| record.toRdata(allocator),
            .RRSIG => |record| record.toRdata(allocator),
            .DNSKEY => |record| record.toRdata(allocator),
            .NSEC => |record| record.toRdata(allocator),
            .NSEC3 => |record| record.toRdata(allocator),
            .NSEC3PARAM => |record| record.toRdata(allocator),
            .TLSA => |record| record.toRdata(allocator),
            .CDS => |record| record.toRdata(allocator),
            .CDNSKEY => |record| record.toRdata(allocator),
            .CAA => |record| record.toRdata(allocator),
            .OPT => |record| record.toRdata(allocator),
            .AXFR, .MAILB, .MAILA, .ANY => &[_]u8{},
        };
    }
};

// Basic record types
pub const ARecord = struct {
    address: [4]u8,

    pub fn fromRdata(rdata: []const u8) !ARecord {
        if (rdata.len != 4) return error.InvalidRdata;
        return ARecord{ .address = rdata[0..4].* };
    }

    pub fn toRdata(self: ARecord, allocator: std.mem.Allocator) ![]u8 {
        return allocator.dupe(u8, &self.address);
    }

    pub fn toString(self: ARecord, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{}.{}.{}.{}", .{ self.address[0], self.address[1], self.address[2], self.address[3] });
    }
};

pub const AAAARecord = struct {
    address: [16]u8,

    pub fn fromRdata(rdata: []const u8) !AAAARecord {
        if (rdata.len != 16) return error.InvalidRdata;
        return AAAARecord{ .address = rdata[0..16].* };
    }

    pub fn toRdata(self: AAAARecord, allocator: std.mem.Allocator) ![]u8 {
        return allocator.dupe(u8, &self.address);
    }

    pub fn toString(self: AAAARecord, allocator: std.mem.Allocator) ![]u8 {
        const groups = std.mem.bytesToValue([8]u16, &self.address);
        return std.fmt.allocPrint(allocator, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{
            std.mem.bigToNative(u16, groups[0]),
            std.mem.bigToNative(u16, groups[1]),
            std.mem.bigToNative(u16, groups[2]),
            std.mem.bigToNative(u16, groups[3]),
            std.mem.bigToNative(u16, groups[4]),
            std.mem.bigToNative(u16, groups[5]),
            std.mem.bigToNative(u16, groups[6]),
            std.mem.bigToNative(u16, groups[7]),
        });
    }
};

pub const NSRecord = struct {
    nsdname: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !NSRecord {
        const name = try decodeDnsName(rdata, 0, allocator);
        return NSRecord{ .nsdname = name.name };
    }

    pub fn toRdata(self: NSRecord, allocator: std.mem.Allocator) ![]u8 {
        return encodeDnsName(self.nsdname, allocator);
    }
};

pub const CNAMERecord = struct {
    cname: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !CNAMERecord {
        const name = try decodeDnsName(rdata, 0, allocator);
        return CNAMERecord{ .cname = name.name };
    }

    pub fn toRdata(self: CNAMERecord, allocator: std.mem.Allocator) ![]u8 {
        return encodeDnsName(self.cname, allocator);
    }
};

pub const MXRecord = struct {
    preference: u16,
    exchange: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !MXRecord {
        if (rdata.len < 2) return error.InvalidRdata;
        const preference = std.mem.readInt(u16, rdata[0..2], .big);
        const name = try decodeDnsName(rdata, 2, allocator);
        return MXRecord{
            .preference = preference,
            .exchange = name.name,
        };
    }

    pub fn toRdata(self: MXRecord, allocator: std.mem.Allocator) ![]u8 {
        const encoded_name = try encodeDnsName(self.exchange, allocator);
        defer allocator.free(encoded_name);
        
        var result = try allocator.alloc(u8, 2 + encoded_name.len);
        std.mem.writeInt(u16, result[0..2], self.preference, .big);
        std.mem.copyForwards(u8, result[2..], encoded_name);
        return result;
    }
};

pub const TXTRecord = struct {
    text: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !TXTRecord {
        if (rdata.len == 0) return TXTRecord{ .text = "" };
        
        var result = std.ArrayList(u8){};
        defer result.deinit(allocator);
        
        var offset: usize = 0;
        while (offset < rdata.len) {
            const len = rdata[offset];
            offset += 1;
            if (offset + len > rdata.len) return error.InvalidRdata;
            
            try result.appendSlice(rdata[offset..offset + len]);
            offset += len;
            
            if (offset < rdata.len) try result.append(' ');
        }
        
        return TXTRecord{ .text = try result.toOwnedSlice() };
    }

    pub fn toRdata(self: TXTRecord, allocator: std.mem.Allocator) ![]u8 {
        if (self.text.len == 0) return allocator.alloc(u8, 0);
        
        var result = std.ArrayList(u8){};
        defer result.deinit(allocator);
        
        // For now, treat the entire text as a single string
        if (self.text.len > 255) return error.TextTooLong;
        
        try result.append(@intCast(self.text.len));
        try result.appendSlice(self.text);
        
        return result.toOwnedSlice();
    }
};

pub const PTRRecord = struct {
    ptrdname: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !PTRRecord {
        const name = try decodeDnsName(rdata, 0, allocator);
        return PTRRecord{ .ptrdname = name.name };
    }

    pub fn toRdata(self: PTRRecord, allocator: std.mem.Allocator) ![]u8 {
        return encodeDnsName(self.ptrdname, allocator);
    }
};

pub const SOARecord = struct {
    mname: []const u8,
    rname: []const u8,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !SOARecord {
        var offset: usize = 0;
        
        const mname_result = try decodeDnsName(rdata, offset, allocator);
        offset = mname_result.new_offset;
        
        const rname_result = try decodeDnsName(rdata, offset, allocator);
        offset = rname_result.new_offset;
        
        if (offset + 20 > rdata.len) return error.InvalidRdata;
        
        return SOARecord{
            .mname = mname_result.name,
            .rname = rname_result.name,
            .serial = std.mem.readInt(u32, rdata[offset..offset+4], .big),
            .refresh = std.mem.readInt(u32, rdata[offset+4..offset+8], .big),
            .retry = std.mem.readInt(u32, rdata[offset+8..offset+12], .big),
            .expire = std.mem.readInt(u32, rdata[offset+12..offset+16], .big),
            .minimum = std.mem.readInt(u32, rdata[offset+16..offset+20], .big),
        };
    }

    pub fn toRdata(self: SOARecord, allocator: std.mem.Allocator) ![]u8 {
        const mname_encoded = try encodeDnsName(self.mname, allocator);
        defer allocator.free(mname_encoded);
        const rname_encoded = try encodeDnsName(self.rname, allocator);
        defer allocator.free(rname_encoded);
        
        var result = try allocator.alloc(u8, mname_encoded.len + rname_encoded.len + 20);
        var offset: usize = 0;
        
        std.mem.copyForwards(u8, result[offset..], mname_encoded);
        offset += mname_encoded.len;
        
        std.mem.copyForwards(u8, result[offset..], rname_encoded);
        offset += rname_encoded.len;
        
        std.mem.writeInt(u32, result[offset..offset+4], self.serial, .big);
        std.mem.writeInt(u32, result[offset+4..offset+8], self.refresh, .big);
        std.mem.writeInt(u32, result[offset+8..offset+12], self.retry, .big);
        std.mem.writeInt(u32, result[offset+12..offset+16], self.expire, .big);
        std.mem.writeInt(u32, result[offset+16..offset+20], self.minimum, .big);
        
        return result;
    }
};

pub const SRVRecord = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !SRVRecord {
        if (rdata.len < 6) return error.InvalidRdata;
        
        const priority = std.mem.readInt(u16, rdata[0..2], .big);
        const weight = std.mem.readInt(u16, rdata[2..4], .big);
        const port = std.mem.readInt(u16, rdata[4..6], .big);
        
        const name = try decodeDnsName(rdata, 6, allocator);
        
        return SRVRecord{
            .priority = priority,
            .weight = weight,
            .port = port,
            .target = name.name,
        };
    }

    pub fn toRdata(self: SRVRecord, allocator: std.mem.Allocator) ![]u8 {
        const encoded_name = try encodeDnsName(self.target, allocator);
        defer allocator.free(encoded_name);
        
        var result = try allocator.alloc(u8, 6 + encoded_name.len);
        std.mem.writeInt(u16, result[0..2], self.priority, .big);
        std.mem.writeInt(u16, result[2..4], self.weight, .big);
        std.mem.writeInt(u16, result[4..6], self.port, .big);
        std.mem.copyForwards(u8, result[6..], encoded_name);
        return result;
    }
};

// DNSSEC record types (simplified implementations)
pub const DSRecord = struct {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !DSRecord {
        if (rdata.len < 4) return error.InvalidRdata;
        return DSRecord{
            .key_tag = std.mem.readInt(u16, rdata[0..2], .big),
            .algorithm = rdata[2],
            .digest_type = rdata[3],
            .digest = try allocator.dupe(u8, rdata[4..]),
        };
    }

    pub fn toRdata(self: DSRecord, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, 4 + self.digest.len);
        std.mem.writeInt(u16, result[0..2], self.key_tag, .big);
        result[2] = self.algorithm;
        result[3] = self.digest_type;
        std.mem.copyForwards(u8, result[4..], self.digest);
        return result;
    }
};

pub const RRSIGRecord = struct {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signers_name: []const u8,
    signature: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !RRSIGRecord {
        if (rdata.len < 18) return error.InvalidRdata;
        
        const name_result = try decodeDnsName(rdata, 18, allocator);
        
        return RRSIGRecord{
            .type_covered = std.mem.readInt(u16, rdata[0..2], .big),
            .algorithm = rdata[2],
            .labels = rdata[3],
            .original_ttl = std.mem.readInt(u32, rdata[4..8], .big),
            .signature_expiration = std.mem.readInt(u32, rdata[8..12], .big),
            .signature_inception = std.mem.readInt(u32, rdata[12..16], .big),
            .key_tag = std.mem.readInt(u16, rdata[16..18], .big),
            .signers_name = name_result.name,
            .signature = try allocator.dupe(u8, rdata[name_result.new_offset..]),
        };
    }

    pub fn toRdata(self: RRSIGRecord, allocator: std.mem.Allocator) ![]u8 {
        const encoded_name = try encodeDnsName(self.signers_name, allocator);
        defer allocator.free(encoded_name);
        
        var result = try allocator.alloc(u8, 18 + encoded_name.len + self.signature.len);
        var offset: usize = 0;
        
        std.mem.writeInt(u16, result[offset..offset+2], self.type_covered, .big);
        result[offset+2] = self.algorithm;
        result[offset+3] = self.labels;
        std.mem.writeInt(u32, result[offset+4..offset+8], self.original_ttl, .big);
        std.mem.writeInt(u32, result[offset+8..offset+12], self.signature_expiration, .big);
        std.mem.writeInt(u32, result[offset+12..offset+16], self.signature_inception, .big);
        std.mem.writeInt(u16, result[offset+16..offset+18], self.key_tag, .big);
        offset += 18;
        
        std.mem.copyForwards(u8, result[offset..], encoded_name);
        offset += encoded_name.len;
        
        std.mem.copyForwards(u8, result[offset..], self.signature);
        
        return result;
    }
};

pub const DNSKEYRecord = struct {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !DNSKEYRecord {
        if (rdata.len < 4) return error.InvalidRdata;
        return DNSKEYRecord{
            .flags = std.mem.readInt(u16, rdata[0..2], .big),
            .protocol = rdata[2],
            .algorithm = rdata[3],
            .public_key = try allocator.dupe(u8, rdata[4..]),
        };
    }

    pub fn toRdata(self: DNSKEYRecord, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, 4 + self.public_key.len);
        std.mem.writeInt(u16, result[0..2], self.flags, .big);
        result[2] = self.protocol;
        result[3] = self.algorithm;
        std.mem.copyForwards(u8, result[4..], self.public_key);
        return result;
    }
};

pub const NSECRecord = struct {
    next_domain_name: []const u8,
    type_bit_maps: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !NSECRecord {
        const name_result = try decodeDnsName(rdata, 0, allocator);
        return NSECRecord{
            .next_domain_name = name_result.name,
            .type_bit_maps = try allocator.dupe(u8, rdata[name_result.new_offset..]),
        };
    }

    pub fn toRdata(self: NSECRecord, allocator: std.mem.Allocator) ![]u8 {
        const encoded_name = try encodeDnsName(self.next_domain_name, allocator);
        defer allocator.free(encoded_name);
        
        var result = try allocator.alloc(u8, encoded_name.len + self.type_bit_maps.len);
        std.mem.copyForwards(u8, result[0..encoded_name.len], encoded_name);
        std.mem.copyForwards(u8, result[encoded_name.len..], self.type_bit_maps);
        return result;
    }
};

pub const NSEC3Record = struct {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt_length: u8,
    salt: []const u8,
    hash_length: u8,
    next_hashed_owner_name: []const u8,
    type_bit_maps: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !NSEC3Record {
        if (rdata.len < 5) return error.InvalidRdata;
        
        var offset: usize = 0;
        const hash_algorithm = rdata[offset]; offset += 1;
        const flags = rdata[offset]; offset += 1;
        const iterations = std.mem.readInt(u16, rdata[offset..offset+2], .big); offset += 2;
        const salt_length = rdata[offset]; offset += 1;
        
        if (offset + salt_length + 1 > rdata.len) return error.InvalidRdata;
        
        const salt = try allocator.dupe(u8, rdata[offset..offset + salt_length]);
        offset += salt_length;
        
        const hash_length = rdata[offset]; offset += 1;
        if (offset + hash_length > rdata.len) return error.InvalidRdata;
        
        const next_hashed_owner_name = try allocator.dupe(u8, rdata[offset..offset + hash_length]);
        offset += hash_length;
        
        const type_bit_maps = try allocator.dupe(u8, rdata[offset..]);
        
        return NSEC3Record{
            .hash_algorithm = hash_algorithm,
            .flags = flags,
            .iterations = iterations,
            .salt_length = salt_length,
            .salt = salt,
            .hash_length = hash_length,
            .next_hashed_owner_name = next_hashed_owner_name,
            .type_bit_maps = type_bit_maps,
        };
    }

    pub fn toRdata(self: NSEC3Record, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, 5 + self.salt.len + 1 + self.next_hashed_owner_name.len + self.type_bit_maps.len);
        var offset: usize = 0;
        
        result[offset] = self.hash_algorithm; offset += 1;
        result[offset] = self.flags; offset += 1;
        std.mem.writeInt(u16, result[offset..offset+2], self.iterations, .big); offset += 2;
        result[offset] = self.salt_length; offset += 1;
        std.mem.copyForwards(u8, result[offset..], self.salt); offset += self.salt.len;
        result[offset] = self.hash_length; offset += 1;
        std.mem.copyForwards(u8, result[offset..], self.next_hashed_owner_name); offset += self.next_hashed_owner_name.len;
        std.mem.copyForwards(u8, result[offset..], self.type_bit_maps);
        
        return result;
    }
};

pub const TLSARecord = struct {
    cert_usage: u8,
    selector: u8,
    matching_type: u8,
    cert_association_data: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !TLSARecord {
        if (rdata.len < 3) return error.InvalidRdata;
        return TLSARecord{
            .cert_usage = rdata[0],
            .selector = rdata[1],
            .matching_type = rdata[2],
            .cert_association_data = try allocator.dupe(u8, rdata[3..]),
        };
    }

    pub fn toRdata(self: TLSARecord, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, 3 + self.cert_association_data.len);
        result[0] = self.cert_usage;
        result[1] = self.selector;
        result[2] = self.matching_type;
        std.mem.copyForwards(u8, result[3..], self.cert_association_data);
        return result;
    }
};

pub const CAARecord = struct {
    flags: u8,
    tag: []const u8,
    value: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !CAARecord {
        if (rdata.len < 2) return error.InvalidRdata;
        
        const flags = rdata[0];
        const tag_length = rdata[1];
        
        if (2 + tag_length > rdata.len) return error.InvalidRdata;
        
        const tag = try allocator.dupe(u8, rdata[2..2 + tag_length]);
        const value = try allocator.dupe(u8, rdata[2 + tag_length..]);
        
        return CAARecord{
            .flags = flags,
            .tag = tag,
            .value = value,
        };
    }

    pub fn toRdata(self: CAARecord, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, 2 + self.tag.len + self.value.len);
        result[0] = self.flags;
        result[1] = @intCast(self.tag.len);
        std.mem.copyForwards(u8, result[2..], self.tag);
        std.mem.copyForwards(u8, result[2 + self.tag.len..], self.value);
        return result;
    }
};

pub const OPTRecord = struct {
    options: []const u8,

    pub fn fromRdata(rdata: []const u8, allocator: std.mem.Allocator) !OPTRecord {
        return OPTRecord{
            .options = try allocator.dupe(u8, rdata),
        };
    }

    pub fn toRdata(self: OPTRecord, allocator: std.mem.Allocator) ![]u8 {
        return allocator.dupe(u8, self.options);
    }
};

// Helper functions for DNS name encoding/decoding
fn encodeDnsName(name: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (name.len == 0 or (name.len == 1 and name[0] == '.')) {
        return allocator.dupe(u8, &[_]u8{0}); // Root domain
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
        
        try result.append(@intCast(label_len));
        try result.appendSlice(name[label_start..i]);
        
        if (i < name.len) i += 1; // Skip the dot
    }
    
    try result.append(0); // Null terminator
    return result.toOwnedSlice();
}

fn decodeDnsName(data: []const u8, offset: usize, allocator: std.mem.Allocator) !struct { name: []u8, new_offset: usize } {
    var result = std.ArrayList(u8){};
    defer result.deinit(allocator);
    
    var pos = offset;
    var jumped = false;
    var jump_pos: usize = 0;
    
    while (pos < data.len) {
        const len = data[pos];
        
        if (len == 0) {
            pos += 1;
            break;
        }
        
        if ((len & 0xC0) == 0xC0) { // Compression pointer
            if (!jumped) {
                jump_pos = pos + 2;
                jumped = true;
            }
            pos = (@as(usize, len & 0x3F) << 8) | data[pos + 1];
            continue;
        }
        
        pos += 1;
        if (pos + len > data.len) return error.InvalidPacket;
        
        if (result.items.len > 0) try result.append('.');
        try result.appendSlice(data[pos..pos + len]);
        pos += len;
    }
    
    const final_pos = if (jumped) jump_pos else pos;
    return .{ .name = try result.toOwnedSlice(), .new_offset = final_pos };
}

test "A record encoding" {
    const allocator = std.testing.allocator;
    
    const record = ARecord{ .address = [_]u8{ 192, 168, 1, 1 } };
    const rdata = try record.toRdata(allocator);
    defer allocator.free(rdata);
    
    const decoded = try ARecord.fromRdata(rdata);
    try std.testing.expectEqualSlices(u8, &record.address, &decoded.address);
}

test "MX record encoding" {
    const allocator = std.testing.allocator;
    
    const record = MXRecord{
        .preference = 10,
        .exchange = "mail.example.com",
    };
    
    const rdata = try record.toRdata(allocator);
    defer allocator.free(rdata);
    
    const decoded = try MXRecord.fromRdata(rdata, allocator);
    defer allocator.free(decoded.exchange);
    
    try std.testing.expectEqual(record.preference, decoded.preference);
    try std.testing.expectEqualStrings(record.exchange, decoded.exchange);
}
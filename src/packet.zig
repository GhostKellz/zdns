const std = @import("std");
const records = @import("records.zig");

pub const DnsError = error{
    InvalidPacket,
    PacketTooSmall,
    PacketTooLarge,
    InvalidCompression,
    InvalidName,
    UnsupportedRecordType,
    OutOfMemory,
};

pub const Header = packed struct {
    id: u16,
    flags: Flags,
    qdcount: u16, // Question count
    ancount: u16, // Answer count  
    nscount: u16, // Authority record count
    arcount: u16, // Additional record count

    pub const Flags = packed struct {
        rd: bool,       // Recursion desired
        tc: bool,       // Truncated
        aa: bool,       // Authoritative answer
        opcode: u4,     // Operation code
        qr: bool,       // Query/Response flag
        rcode: u4,      // Response code
        cd: bool,       // Checking disabled
        ad: bool,       // Authenticated data
        z: bool,        // Reserved (must be zero)
        ra: bool,       // Recursion available
    };

    pub fn init() Header {
        return Header{
            .id = 0,
            .flags = Flags{
                .rd = false,
                .tc = false,
                .aa = false,
                .opcode = 0,
                .qr = false,
                .rcode = 0,
                .cd = false,
                .ad = false,
                .z = false,
                .ra = false,
            },
            .qdcount = 0,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };
    }

    pub fn toBytes(self: Header) [12]u8 {
        var result: [12]u8 = undefined;
        std.mem.writeInt(u16, result[0..2], self.id, .big);
        std.mem.writeInt(u16, result[2..4], @as(u16, @bitCast(self.flags)), .big);
        std.mem.writeInt(u16, result[4..6], self.qdcount, .big);
        std.mem.writeInt(u16, result[6..8], self.ancount, .big);
        std.mem.writeInt(u16, result[8..10], self.nscount, .big);
        std.mem.writeInt(u16, result[10..12], self.arcount, .big);
        return result;
    }

    pub fn fromBytes(bytes: []const u8) !Header {
        if (bytes.len < 12) return DnsError.PacketTooSmall;
        
        return Header{
            .id = std.mem.readInt(u16, bytes[0..2][0..2], .big),
            .flags = @bitCast(std.mem.readInt(u16, bytes[2..4][0..2], .big)),
            .qdcount = std.mem.readInt(u16, bytes[4..6][0..2], .big),
            .ancount = std.mem.readInt(u16, bytes[6..8][0..2], .big),
            .nscount = std.mem.readInt(u16, bytes[8..10][0..2], .big),
            .arcount = std.mem.readInt(u16, bytes[10..12][0..2], .big),
        };
    }
};

pub const Question = struct {
    name: []const u8,
    qtype: records.RecordType,
    qclass: records.RecordClass,

    pub fn init(name: []const u8, qtype: records.RecordType, qclass: records.RecordClass) Question {
        return Question{
            .name = name,
            .qtype = qtype,
            .qclass = qclass,
        };
    }

    pub fn encodedSize(self: Question, allocator: std.mem.Allocator) !usize {
        const encoded_name = try encodeName(self.name, allocator);
        defer allocator.free(encoded_name);
        return encoded_name.len + 4; // name + type (2) + class (2)
    }

    pub fn encode(self: Question, allocator: std.mem.Allocator) ![]u8 {
        const encoded_name = try encodeName(self.name, allocator);
        defer allocator.free(encoded_name);
        
        const result = try allocator.alloc(u8, encoded_name.len + 4);
        @memcpy(result[0..encoded_name.len], encoded_name);
        std.mem.writeInt(u16, result[encoded_name.len..encoded_name.len + 2][0..2], @intFromEnum(self.qtype), .big);
        std.mem.writeInt(u16, result[encoded_name.len + 2..encoded_name.len + 4][0..2], @intFromEnum(self.qclass), .big);
        
        return result;
    }
};

pub const ResourceRecord = struct {
    name: []const u8,
    rtype: records.RecordType,
    rclass: records.RecordClass,
    ttl: u32,
    rdata: []const u8,

    pub fn init(name: []const u8, rtype: records.RecordType, rclass: records.RecordClass, ttl: u32, rdata: []const u8) ResourceRecord {
        return ResourceRecord{
            .name = name,
            .rtype = rtype,
            .rclass = rclass,
            .ttl = ttl,
            .rdata = rdata,
        };
    }

    pub fn encodedSize(self: ResourceRecord, allocator: std.mem.Allocator) !usize {
        const encoded_name = try encodeName(self.name, allocator);
        defer allocator.free(encoded_name);
        return encoded_name.len + 10 + self.rdata.len; // name + type(2) + class(2) + ttl(4) + rdlength(2) + rdata
    }

    pub fn encode(self: ResourceRecord, allocator: std.mem.Allocator) ![]u8 {
        const encoded_name = try encodeName(self.name, allocator);
        defer allocator.free(encoded_name);
        
        const result = try allocator.alloc(u8, encoded_name.len + 10 + self.rdata.len);
        @memcpy(result[0..encoded_name.len], encoded_name);
        var offset = encoded_name.len;
        
        std.mem.writeInt(u16, result[offset..offset + 2][0..2], @intFromEnum(self.rtype), .big);
        offset += 2;
        std.mem.writeInt(u16, result[offset..offset + 2][0..2], @intFromEnum(self.rclass), .big);
        offset += 2;
        std.mem.writeInt(u32, result[offset..offset + 4][0..4], self.ttl, .big);
        offset += 4;
        std.mem.writeInt(u16, result[offset..offset + 2][0..2], @intCast(self.rdata.len), .big);
        offset += 2;
        @memcpy(result[offset..offset + self.rdata.len], self.rdata);
        
        return result;
    }
};

pub const Message = struct {
    header: Header,
    questions: []const Question,
    answers: []const ResourceRecord,
    authorities: []const ResourceRecord,
    additionals: []const ResourceRecord,

    pub fn init(allocator: std.mem.Allocator) Message {
        _ = allocator;
        return Message{
            .header = Header.init(),
            .questions = &[_]Question{},
            .answers = &[_]ResourceRecord{},
            .authorities = &[_]ResourceRecord{},
            .additionals = &[_]ResourceRecord{},
        };
    }

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.questions);
        allocator.free(self.answers);
        allocator.free(self.authorities);
        allocator.free(self.additionals);
    }

    pub fn encode(self: Message, allocator: std.mem.Allocator) ![]u8 {
        var size: usize = 12; // Header size

        // Calculate total size needed
        for (self.questions) |q| {
            size += try q.encodedSize(allocator);
        }
        for (self.answers) |rr| {
            size += try rr.encodedSize(allocator);
        }
        for (self.authorities) |rr| {
            size += try rr.encodedSize(allocator);
        }
        for (self.additionals) |rr| {
            size += try rr.encodedSize(allocator);
        }

        const result = try allocator.alloc(u8, size);
        var buffer_index: usize = 0;

        // Encode header
        const header_bytes = self.header.toBytes();
        @memcpy(result[buffer_index..buffer_index + header_bytes.len], &header_bytes);
        buffer_index += header_bytes.len;

        // Encode sections
        for (self.questions) |q| {
            const encoded = try q.encode(allocator);
            @memcpy(result[buffer_index..buffer_index + encoded.len], encoded);
            buffer_index += encoded.len;
            allocator.free(encoded);
        }
        for (self.answers) |rr| {
            const encoded = try rr.encode(allocator);
            @memcpy(result[buffer_index..buffer_index + encoded.len], encoded);
            buffer_index += encoded.len;
            allocator.free(encoded);
        }
        for (self.authorities) |rr| {
            const encoded = try rr.encode(allocator);
            @memcpy(result[buffer_index..buffer_index + encoded.len], encoded);
            buffer_index += encoded.len;
            allocator.free(encoded);
        }
        for (self.additionals) |rr| {
            const encoded = try rr.encode(allocator);
            @memcpy(result[buffer_index..buffer_index + encoded.len], encoded);
            buffer_index += encoded.len;
            allocator.free(encoded);
        }

        return result;
    }

    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !Message {
        if (data.len < 12) return DnsError.PacketTooSmall;

        const header = try Header.fromBytes(data[0..12]);
        var offset: usize = 12;

        // Decode questions
        var questions = try allocator.alloc(Question, header.qdcount);
        for (0..header.qdcount) |i| {
            const result = try decodeQuestion(data, offset);
            questions[i] = result.question;
            offset = result.new_offset;
        }

        // Decode answers
        var answers = try allocator.alloc(ResourceRecord, header.ancount);
        for (0..header.ancount) |i| {
            const result = try decodeResourceRecord(allocator, data, offset);
            answers[i] = result.rr;
            offset = result.new_offset;
        }

        // Decode authorities
        var authorities = try allocator.alloc(ResourceRecord, header.nscount);
        for (0..header.nscount) |i| {
            const result = try decodeResourceRecord(allocator, data, offset);
            authorities[i] = result.rr;
            offset = result.new_offset;
        }

        // Decode additionals
        var additionals = try allocator.alloc(ResourceRecord, header.arcount);
        for (0..header.arcount) |i| {
            const result = try decodeResourceRecord(allocator, data, offset);
            additionals[i] = result.rr;
            offset = result.new_offset;
        }

        return Message{
            .header = header,
            .questions = questions,
            .answers = answers,
            .authorities = authorities,
            .additionals = additionals,
        };
    }
};

// DNS name encoding (RFC 1035)
fn encodeName(name: []const u8, allocator: std.mem.Allocator) ![]u8 {
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
        if (label_len > 63) return DnsError.InvalidName;
        
        try result.append(allocator, @intCast(label_len));
        try result.appendSlice(allocator, name[label_start..i]);
        
        if (i < name.len) i += 1; // Skip the dot
    }
    
    try result.append(allocator, 0); // Null terminator
    return try result.toOwnedSlice(allocator);
}

fn decodeName(data: []const u8, offset: usize, allocator: std.mem.Allocator) !struct { name: []u8, new_offset: usize } {
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
        if (pos + len > data.len) return DnsError.InvalidPacket;
        
        if (result.items.len > 0) try result.append(allocator, '.');
        try result.appendSlice(allocator, data[pos..pos + len]);
        pos += len;
    }
    
    const final_pos = if (jumped) jump_pos else pos;
    return .{ .name = try result.toOwnedSlice(allocator), .new_offset = final_pos };
}

fn decodeQuestion(data: []const u8, offset: usize) !struct { question: Question, new_offset: usize } {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    const name_result = try decodeName(data, offset, allocator);
    var pos = name_result.new_offset;
    
    if (pos + 4 > data.len) return DnsError.PacketTooSmall;
    
    const qtype: records.RecordType = @enumFromInt(std.mem.readInt(u16, data[pos..pos+2][0..2], .big));
    const qclass: records.RecordClass = @enumFromInt(std.mem.readInt(u16, data[pos+2..pos+4][0..2], .big));
    pos += 4;
    
    return .{
        .question = Question{
            .name = name_result.name,
            .qtype = qtype,
            .qclass = qclass,
        },
        .new_offset = pos,
    };
}

fn decodeResourceRecord(allocator: std.mem.Allocator, data: []const u8, offset: usize) !struct { rr: ResourceRecord, new_offset: usize } {
    const name_result = try decodeName(data, offset, allocator);
    var pos = name_result.new_offset;
    
    if (pos + 10 > data.len) return DnsError.PacketTooSmall;
    
    const rtype: records.RecordType = @enumFromInt(std.mem.readInt(u16, data[pos..pos+2][0..2], .big));
    const rclass: records.RecordClass = @enumFromInt(std.mem.readInt(u16, data[pos+2..pos+4][0..2], .big));
    const ttl = std.mem.readInt(u32, data[pos+4..pos+8][0..4], .big);
    const rdlength = std.mem.readInt(u16, data[pos+8..pos+10][0..2], .big);
    pos += 10;
    
    if (pos + rdlength > data.len) return DnsError.PacketTooSmall;
    
    const rdata = try allocator.dupe(u8, data[pos..pos + rdlength]);
    pos += rdlength;
    
    return .{
        .rr = ResourceRecord{
            .name = name_result.name,
            .rtype = rtype,
            .rclass = rclass,
            .ttl = ttl,
            .rdata = rdata,
        },
        .new_offset = pos,
    };
}

test "header encode/decode" {
    var header = Header.init();
    header.id = 0x1234;
    header.flags.qr = true;
    header.qdcount = 1;

    const bytes = header.toBytes();
    const decoded = try Header.fromBytes(&bytes);

    try std.testing.expectEqual(header.id, decoded.id);
    try std.testing.expectEqual(header.flags.qr, decoded.flags.qr);
    try std.testing.expectEqual(header.qdcount, decoded.qdcount);
}

test "name encoding" {
    const allocator = std.testing.allocator;
    
    const encoded = try encodeName("example.com", allocator);
    defer allocator.free(encoded);
    
    const expected = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}
# zdns

<div align="center">
  <img src="assets/icons/zdns.png" alt="zdns icon" width="128" height="128">

**Zig DNS & Resolver Library**  
*Fast. Async. Secure.*

</div>

---

[![Zig](https://img.shields.io/badge/Zig-v0.16-yellow?logo=zig&logoColor=white)](https://ziglang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/ghostmesh-io/zdns/ci.yml?branch=main&logo=github)](https://github.com/ghostmesh-io/zdns/actions)
[![DNS Protocol](https://img.shields.io/badge/Protocol-DNS-blue?logo=cloudflare&logoColor=white)](https://tools.ietf.org/html/rfc1035)
[![Security](https://img.shields.io/badge/Secure-DoH%20%7C%20DoT%20%7C%20DoQ-green?logo=shield)](https://datatracker.ietf.org/doc/html/rfc8484)
[![Async](https://img.shields.io/badge/Async-First-purple?logo=zig&logoColor=white)](https://ziglang.org/)  

---

## Overview

**zdns** is a Zig-native implementation of the DNS protocol.  
It is designed for speed, async-first usage, and modern DNS transports, making it ideal for resolvers, authoritative servers, and embedded systems.

Unlike C-based stacks, `zdns` is safe, memory-predictable, and integrates directly with other GhostStack protocols (`zquic`, `zcrypto`, `zauth`).

---

## Features

- 📡 Classic DNS over UDP & TCP  
- 🔐 Secure transports:
  - DNS-over-TLS (DoT)  
  - DNS-over-HTTPS (DoH)  
  - DNS-over-QUIC (DoQ via `zquic`)  
- 🔄 Async query model via `zsync`  
- 🛠 Authoritative + Recursive resolver support  
- 🧩 DNSSEC validation  
- 🌐 Pluggable storage backends (file, memory, SQL, distributed KV)  

---

## Example (Resolver)

```zig
const std = @import("std");
const zdns = @import("zdns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!gpa.deinit());
    const allocator = &gpa.allocator;

    var resolver = try zdns.Resolver.init(allocator, .{
        .bootstrap_servers = &[_][]const u8{"1.1.1.1", "8.8.8.8"},
    });
    defer resolver.deinit();

    const response = try resolver.query("example.com", .A);
    std.debug.print("example.com -> {any}\n", .{response});
}
```

---

## Use Cases

✅ **Stub resolver** for apps and services  
✅ **Recursive resolver** with caching  
✅ **Authoritative DNS server** for zones  
✅ **DNSSEC-enabled** security stack  
✅ **Integrated DNS** for VPN/overlay networks (Bolt, GhostMesh, Surge)  

---

## Vision

**zdns** is not just another resolver.  
It's a modern DNS engine designed to:

🔒 **Be secure by default**  
📦 **Run as a library or standalone server**  
🌐 **Power next-gen overlay networks and secure infrastructure**  

---

## Quick Start

### Installation

Add `zdns` to your `build.zig.zon`:

```zig
.{
    .name = "my-app",
    .version = "0.1.0",
    .dependencies = .{
        .zdns = .{
            .url = "https://github.com/ghostmesh-io/zdns/archive/main.tar.gz",
            .hash = "...",
        },
    },
}
```

### Basic Usage

```zig
const std = @import("std");
const zdns = @import("zdns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var resolver = try zdns.Resolver.init(gpa.allocator(), .{});
    defer resolver.deinit();
    
    const result = try resolver.query("example.com", .A);
    std.debug.print("Resolved: {}\n", .{result});
}
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

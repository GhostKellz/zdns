# TODO – zdns

Implementation roadmap for the Zig DNS & Resolver Library.

---

## Phase 1 – Core DNS
- [ ] DNS packet encoder/decoder
- [ ] Support A, AAAA, CNAME, MX, TXT, NS, PTR record types
- [ ] UDP transport (client + server)
- [ ] TCP transport (client + server)
- [ ] Basic recursive resolver
- [ ] Stub resolver API

---

## Phase 2 – Secure Transports
- [ ] DNS-over-TLS (DoT)
- [ ] DNS-over-HTTPS (DoH)
- [ ] DNS-over-QUIC (DoQ via `zquic`)
- [ ] Bootstrap resolver for encrypted transports

---

## Phase 3 – Authoritative Server
- [ ] Zone file parser
- [ ] Zone storage backends:
  - [ ] In-memory
  - [ ] Filesystem
  - [ ] SQL/Postgres backend
- [ ] Zone transfer support (AXFR/IXFR)
- [ ] Dynamic updates

---

## Phase 4 – Advanced Resolver
- [ ] Caching resolver with TTL management
- [ ] Negative caching (RFC 2308)
- [ ] Forwarding resolver mode
- [ ] DNSSEC validation
- [ ] DNS64/NAT64 support

---

## Phase 5 – Ecosystem Integration
- [ ] Service discovery integration (`zdns` + `zquic`)
- [ ] Private DNS zones authenticated via `zauth`
- [ ] Integration with Bolt & Surge for service naming
- [ ] Metrics & observability hooks (Prometheus-style)

---

## Phase 6 – Stretch Goals
- [ ] EDNS(0) + advanced extensions
- [ ] DNS-over-GRPC (experimental)
- [ ] Multi-tenant DNS zones
- [ ] High-availability resolver cluster mode


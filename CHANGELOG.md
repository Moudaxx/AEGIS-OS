# Changelog

## [4.1.0] - 2026-10-26

### Security
- **Removed hardcoded server credentials.** `aegis-admin-token` / `aegis-secret-token` granted admin to anyone who read the source. Tokens now come from `AEGIS_*_TOKEN` env vars (or a random one-time admin token), stored as SHA-256 hashes. Demo tokens require `AEGIS_DEMO_TOKENS=1`.
- `Authorization: Bearer` header support (legacy `auth_token` body field still accepted).
- `/api/v1/audit`, `/api/v1/dashboard`, `/api/v1/agents` and `/mcp/tools/list` now require authentication.
- Prompts are no longer written to the audit log (previously blocked prompts were logged in full); a hash fingerprint is logged instead. Audit file is created with mode 0600.
- Fixed a panic (remote DoS) when logging non-ASCII prompts: the old code sliced by byte index.
- Input filter now normalizes before matching: zero-width chars, full-width letters, homoglyphs, separators; tag-character smuggling and bidi overrides are blocked. MCP tool params are filtered too.
- `serve-tls` fails closed instead of silently falling back to plaintext HTTP.
- Gemini API key moved from URL query string to `x-goog-api-key` header.
- 64 KB request body limit; shared HTTP client with timeouts; upstream error text truncated.
- `aegis-audit.log` was not actually git-ignored (missing newline in `.gitignore`); fixed.

### Changed
- `/api/v1/redteam` runs a real 19-probe corpus (16 attacks + 3 benign controls) against the live filter and returns per-probe results. Previously it returned a hardcoded 100%. Dashboard and `/metrics` report the last real score.
- Version reported by `/health`, `/version` and `/metrics` comes from `Cargo.toml` (now 4.1.0).

### Tests
- 16 new unit/HTTP tests that exercise the real router, auth and filter code (`cargo test`).

## [4.0.0] - 2026-03-06

### Added
- 12 security layers fully implemented
- 5 AI backends: NVIDIA NIM, Claude, Gemini, Groq, OpenAI
- Real HTTP server with Axum (11 endpoints)
- MCP Server with tool execution and auth
- REST API with JWT authentication
- Prometheus /metrics endpoint
- A2A Gateway with trust levels
- Red Team Engine (16 automated attack tests)
- State Integrity Monitor with drift detection
- Runtime Risk Scoring (4 dimensions, 17 event types)
- Audit Logger with SIEM export (Sentinel, SecOps, Splunk)
- API Gateway with rate limiting
- Tool Router (15 tools including Kali)
- Policy Engine (5 rules)
- Docker Compose (AEGIS + Prometheus + Grafana)
- Oracle DB connector with SQL Firewall
- ROS2 Gatekeeper with safety limits
- Telemetry collector with Prometheus output
- 75 integration tests (100% pass)
- 16 Red Team tests (100% blocked)
- CI/CD with GitHub Actions

### Security
- Path traversal protection in Filesystem Jail
- Exact-match network egress (no partial contains)
- Credential revoke flag (audit trail)
- Wildcard capability tokens
- 21 prompt injection patterns
- Hidden control character detection
- SQL Firewall for database queries
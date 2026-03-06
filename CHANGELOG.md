# Changelog

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
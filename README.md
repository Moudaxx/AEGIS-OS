# AEGIS OS™ — Secure AI Agent Platform
# ⛊ AEGIS OS v4.0

### Secure Agent & Robot Execution Platform

[![CI](https://github.com/Moudaxx/aegis-os/actions/workflows/ci.yml/badge.svg)](https://github.com/Moudaxx/aegis-os/actions)
[![Rust](https://img.shields.io/badge/Rust-1.85-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Security](https://img.shields.io/badge/Red%20Team-16%2F16%20Blocked-brightgreen)]()
[![AI](https://img.shields.io/badge/AI-5%20Backends-blue)]()

---

AEGIS OS is a security-first execution platform for AI agents. It enforces **12 security layers** around every agent — from WASM sandboxing to runtime risk scoring.
```
cargo run -- serve    # Start HTTP server on :8401
cargo run -- run --name my-agent --provider groq
cargo run -- red-team # 16/16 attacks blocked
```

---

## Architecture — 12 Security Layers
```
┌──────────────────────────────────────────────┐
│  1. CLI / API Gateway / MCP Server / A2A     │
│  2. AI Inference (NIM+Claude+Gemini+Groq+OAI)│
│  3. Policy Engine + Guardrails (5 rules)     │
│  4. Input Sanitization (21 patterns)         │
│  5. Skill Vetting Pipeline                   │
│  6. API Gateway + Rate Limiting (11 routes)  │
│  7. Tool Router (15 tools + Kali)            │
│  8. MCP Client/Server + A2A Gateway          │
│  9. WASM Sandbox + Filesystem Jail           │
│ 10. State Integrity Monitor + Drift Detection│
│ 11. Credential Vault + Capability Tokens     │
│ 12. Runtime Risk Scoring (4D) + Audit + SIEM │
└──────────────────────────────────────────────┘
```

## AI Backends

| Provider | Model | Status |
|----------|-------|--------|
| **NVIDIA NIM** | meta/llama-3.1-8b-instruct | ✅ |
| **Groq** | llama-3.3-70b-versatile | ✅ |
| **OpenAI** | gpt-4o-mini | ✅ |
| **Google Gemini** | gemini-2.5-flash-lite | ✅ |
| **Anthropic Claude** | claude-haiku-4-5 | ✅ |

## HTTP API (Real Server)

Start the server:
```bash
cargo run -- serve              # Starts on :8401
cargo run -- serve --port 8080  # Custom port
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /health | No | Health check |
| GET | /version | No | Version info |
| GET | /metrics | No | Prometheus metrics |
| POST | /mcp/tools/list | No | List MCP tools |
| POST | /mcp/tools/call | Yes | Execute MCP tool |
| POST | /api/v1/agents/run | Yes | Start an agent |
| POST | /api/v1/agents/stop | Yes | Stop agents |
| GET | /api/v1/agents | No | List agents |
| POST | /api/v1/inference | Yes | AI inference |
| POST | /api/v1/redteam | Yes | Red Team scan |
| GET | /api/v1/audit | No | Audit logs |

### Examples
```bash
# Health
curl http://localhost:8401/health

# Start agent
curl -X POST http://localhost:8401/api/v1/agents/run \
  -H "Content-Type: application/json" \
  -d '{"name":"my-agent","provider":"groq","auth_token":"aegis-secret-token"}'

# Red Team scan
curl -X POST http://localhost:8401/api/v1/redteam \
  -H "Content-Type: application/json" \
  -d '{"auth_token":"aegis-secret-token"}'

# Prometheus metrics
curl http://localhost:8401/metrics
```

## Quick Start

### Prerequisites
- Rust 1.85+
- At least one API key (Groq is free and fast)

### Setup
```bash
git clone https://github.com/Moudaxx/aegis-os.git
cd aegis-os
cp .env.example .env    # Add your API keys
cargo build
```

### Run
```bash
# Full 12-layer agent execution
cargo run -- run --name my-agent --provider groq

# HTTP server mode
cargo run -- serve

# Red Team security scan
cargo run -- red-team

# Version info
cargo run -- version
```

### Docker
```bash
docker compose up -d          # AEGIS + Prometheus + Grafana
open http://localhost:3000     # Grafana dashboard
open http://localhost:9090     # Prometheus
```
## AI Security Framework

AEGIS OS maps directly to recognized AI security standards:
```
AEGIS Module                 →  AI Security Domain
════════════════════════════════════════════════
12-Layer Architecture        →  Secure AI Systems Design
Credential Isolation + RBAC  →  Zero Trust for AI Agents
Red Team + MCP-Kali          →  AI Red Teaming
Audit Logger + SIEM          →  AI Governance & Compliance
MCP Security + Allowlist     →  LLM Tool Security
Input Sanitization           →  Prompt Injection Defense
RAG Security Guard           →  RAG Poisoning Protection
Privacy Filter               →  AI Output Privacy
Extraction Detector          →  Model Extraction Defense
Skill Vetting                →  AI Supply Chain Security
```

**Standards:** NIST AI RMF ✅ | OWASP LLM Top 10 (10/10) ✅ | MAESTRO ✅ | Stanford AIUC-1 ✅

See [AI-SECURITY-FRAMEWORK.md](AI-SECURITY-FRAMEWORK.md) for full mapping.

## Security Test Results
```
Integration Tests:  75/75  (100%)
Red Team Tests:     16/16  (100%)

✅ Prompt Injection      — InputSanitizer (21 patterns)
✅ Path Traversal        — FilesystemJail (13 blocked patterns)
✅ Data Exfiltration     — NetworkEgress (exact match + blocklist)
✅ Credential Theft      — CredentialVault (revoke + TTL)
✅ Privilege Escalation  — CapabilityTokens (wildcards)
✅ Skill Tampering       — SkillVetter (static + deps + sandbox)
✅ Sandbox Escape        — WasmSandbox (wasmtime)
✅ State Tampering       — StateMonitor (SHA256 + drift)
✅ Network Escape        — NetworkEgress (port allowlist)
✅ Denial of Service     — ApiGateway (rate limiting)
```

## Project Structure
```
aegis-os/
├── src/
│   ├── main.rs              # Entry point — 12 layers
│   ├── server/mod.rs        # HTTP server (Axum) — 11 endpoints
│   ├── cli/mod.rs           # CLI — 9 commands
│   ├── orchestrator/mod.rs  # Agent lifecycle
│   ├── inference/mod.rs     # 5 AI backends
│   ├── isolation/mod.rs     # WASM + FS jail + network egress
│   ├── credentials/mod.rs   # Capability tokens + vault
│   ├── sanitization/mod.rs  # Input sanitization
│   ├── skill_vetting/mod.rs # Skill vetting pipeline
│   ├── tool_router/mod.rs   # Tool router (15 tools)
│   ├── guardrails/mod.rs    # Policy engine (5 rules)
│   ├── mcp/mod.rs           # MCP client + server
│   ├── a2a/mod.rs           # A2A gateway
│   ├── state/mod.rs         # State integrity monitor
│   ├── risk/mod.rs          # Runtime risk scoring
│   ├── audit/mod.rs         # Audit logger + SIEM
│   ├── gateway/mod.rs       # API gateway
│   ├── redteam/mod.rs       # Red team engine
│   ├── database/mod.rs      # Oracle DB connector
│   ├── ros2/mod.rs          # ROS2 gatekeeper
│   └── telemetry/mod.rs     # Prometheus metrics
├── tests/
│   └── security_integration.rs  # 75 tests
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
└── aegis.toml               # Configuration
```

## Environment Variables

| Variable | Source | Required |
|----------|--------|----------|
| `NVIDIA_NIM_API_KEY` | build.nvidia.com | Optional |
| `GROQ_API_KEY` | console.groq.com | Recommended (free) |
| `OPENAI_API_KEY` | platform.openai.com | Optional |
| `GOOGLE_AI_API_KEY` | aistudio.google.com | Optional |
| `ANTHROPIC_API_KEY` | console.anthropic.com | Optional |

## Roadmap

| Phase | Status |
|-------|--------|
| MVP — 12 layers + 5 AI backends | ✅ Complete |
| HTTP Server — Real API | ✅ Complete |
| Docker + Prometheus + Grafana | ✅ Complete |
| CI/CD — GitHub Actions | ✅ Complete |
| Multi-agent runtime | Planned |
| TLS/mTLS | Planned |
| RBAC | Planned |
| Kubernetes Helm chart | Planned |
| SaaS — AEGIS Cloud | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## Security

See [SECURITY.md](SECURITY.md)

## License

MIT — See [LICENSE](LICENSE)

---

<p align="center">
  <b>⛊ AEGIS OS</b> — Because AI agents deserve security too.
</p>

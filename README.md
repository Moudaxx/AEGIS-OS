# ⛊ AEGIS OS v4.1

**Autonomous AI Agent Security Platform — Built in Rust**

[![Release](https://img.shields.io/github/v/release/Moudaxx/AEGIS-OS)](https://github.com/Moudaxx/AEGIS-OS/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-135%2F135-brightgreen)]()
[![OWASP](https://img.shields.io/badge/OWASP_LLM_Top_10-10%2F10-brightgreen)](AI-SECURITY-FRAMEWORK.md)

> 88% of organizations reported AI agent security incidents. AEGIS OS is the first autonomous security platform that discovers, tests, and protects AI agents — automatically.

## What is AEGIS OS?

AEGIS OS is an open-source autonomous security platform for AI agents. It wraps every agent in **12 security layers**, discovers new agents on your network, tests them continuously, learns from attacks, and generates reports — all without human intervention.
```bash
cargo run -- autonomous     # Autonomous 24/7 security daemon
cargo run -- serve          # HTTP server on :8401
cargo run -- serve-tls      # HTTPS on :8443
cargo run -- red-team       # 16 attack vectors tested
```

## Autonomous Mode — Works Alone
```
$ cargo run -- autonomous --cycles 3

[DAEMON] ═══ Cycle 1 ═══
[DAEMON] Phase 1: Discovery — Found 3 agents (OpenClaw, Goose, MCP)
[DAEMON] Phase 2: Testing — 15 tests × 3 agents = 45 tests
[DAEMON] Phase 3: Analysis — 1 threat: OpenClaw (9 CVEs)
[DAEMON] Phase 4: Blocking — OpenClaw auto-blocked
[DAEMON] Phase 5: Learning — 1 new rule generated
[DAEMON] Phase 6: Report — Daily report generated
[DAEMON] ═══ Cycle 1 Complete ═══
```

### 6-Phase Autonomous Cycle

| Phase | Engine | What it does |
|-------|--------|-------------|
| 1. Discover | Discovery Engine | Scans ports, MCP servers, Docker containers |
| 2. Test | Continuous Testing | 15 security tests per agent |
| 3. Analyze | Threat Analysis | Risk scoring + known CVE matching |
| 4. Block | Auto-Block | Blocks agents above risk threshold |
| 5. Learn | Adaptive Learning | Creates new rules from attacks |
| 6. Report | Autonomous Reporter | Daily/weekly/incident reports |

## 32 Security Modules

| Category | Modules |
|----------|---------|
| **Core** | CLI, Server (Axum), Orchestrator, Gateway |
| **AI** | 9 backends: NIM, Groq, OpenAI, Gemini, Claude, Cosmos, Ollama, Mistral, DeepSeek |
| **Security** | Input Sanitization, Skill Vetting, Guardrails, Isolation, Credentials, Risk Scoring |
| **AI Security** | RAG Security Guard, Privacy Filter, Extraction Detector, Hallucination Detector, AI Watermark |
| **Protocols** | MCP Client/Server (20 tools), A2A Gateway, MCP-Kali (12 pentest tools) |
| **Autonomous** | Discovery Engine, Continuous Testing, Adaptive Learning, Autonomous Reporter, Autonomous Daemon |
| **Infrastructure** | Database, ROS2, Telemetry, Audit Logger |

## 12 Security Layers
```
Layer 1:  API Gateway + TLS/HTTPS + RBAC (4 roles)
Layer 2:  AI Inference (9 backends + fallback chain)
Layer 3:  Policy Engine + Guardrails
Layer 4:  Input Sanitization (21 injection patterns)
Layer 5:  Skill Vetting Pipeline (static + deps + sandbox)
Layer 6:  Rate Limiting + DDoS Protection
Layer 7:  Tool Router + MCP Bridge (20 tools)
Layer 8:  MCP Server + A2A Gateway
Layer 9:  WASM Sandbox + Filesystem Jail
Layer 10: State Integrity Monitor (SHA256 + drift)
Layer 11: Credential Vault + Capability Tokens + TTL
Layer 12: Risk Scoring (4D) + Audit + SIEM Export
```

## 9 AI Backends

| Provider | Model | Status |
|----------|-------|--------|
| NVIDIA NIM | Llama 3.1 8B | ✅ Verified |
| Groq | Llama 3.3 70B | ✅ Verified |
| OpenAI | GPT-4o-mini | ✅ Verified |
| Google Gemini | 2.5 Flash Lite | ✅ Verified |
| Anthropic Claude | Haiku 4.5 | ✅ Ready |
| NVIDIA Cosmos | Reason 7B | ✅ Built |
| Ollama | Local models | ✅ Built |
| Mistral | Small Latest | ✅ Built |
| DeepSeek | Chat | ✅ Built |

## Security Test Results
```
Integration Tests:    75/75   (100%) ✅
Advanced Security:    60/60   (100%) ✅
Red Team Tests:       16/16   (100%) ✅
OWASP LLM Top 10:    10/10   (100%) ✅
Total:               151 tests — all passing
```

### What's Tested

| Test Suite | Tests | Coverage |
|------------|-------|----------|
| Capability Tokens | 12 | Wildcards, TTL, expiry |
| Credential Vault | 8 | Store, revoke, TTL |
| Skill Vetting | 6 | Static analysis, deps, sandbox |
| Input Sanitization | 11 | 21 injection patterns |
| Filesystem Jail | 12 | Traversal, blocked paths |
| Network Egress | 12 | Allowlist, blocklist, ports |
| Risk Scoring | 3 | Normal → suspicious → compromised |
| AI Backend | 4 | Sanitize → AI → verify |
| Attack Simulation | 7 | Multi-stage attack chain |
| RAG Security | 7 | Poisoning, injection, trust |
| Privacy Filter | 16 | API keys, tokens, PII |
| Extraction Detection | 9 | Probing, system prompt theft |
| Hallucination | 8 | Overconfidence, impossible claims |
| Watermark | 8 | Stamp, verify, tamper detection |
| Kali Authorization | 6 | Target allowlist |
| Combined Attack | 6 | RAG + extraction + leak + tamper |

## 12 HTTP Endpoints
```bash
# Start server
cargo run -- serve          # HTTP :8401
cargo run -- serve-tls      # HTTPS :8443
```

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/api/v1/agents/run` | POST | Admin, Operator | Run agent |
| `/api/v1/agents/stop` | POST | Admin, Operator | Stop agent |
| `/api/v1/agents/list` | GET | All | List agents |
| `/api/v1/agents/status` | GET | All | Agent status |
| `/api/v1/inference` | POST | Admin, Operator, Agent | AI inference |
| `/api/v1/redteam` | POST | Admin | Red team test |
| `/api/v1/tools` | POST | Admin, Operator, Agent | Execute tool |
| `/api/v1/audit` | GET | Admin, Operator, Viewer | Audit logs |
| `/api/v1/metrics` | GET | All | Prometheus metrics |
| `/api/v1/dashboard` | GET | All | Dashboard JSON |
| `/mcp/tools/*` | POST | MCP Auth | MCP tool calls |

## Quick Start
```bash
git clone https://github.com/Moudaxx/AEGIS-OS.git
cd AEGIS-OS
cp .env.example .env  # Add your API keys
cargo build
cargo run -- autonomous --cycles 3  # Watch it work alone!
```

## Docker
```bash
docker-compose up -d  # AEGIS + Prometheus + Grafana
```

## RBAC — 4 Roles

| Role | Run | Stop | Inference | Red Team | Audit | Config |
|------|-----|------|-----------|----------|-------|--------|
| Admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Operator | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| Viewer | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Agent | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |

## AI Security Framework

| Standard | Coverage |
|----------|----------|
| OWASP LLM Top 10 | **10/10** |
| NIST AI RMF | Aligned |
| OWASP MAESTRO | Aligned |

See [AI-SECURITY-FRAMEWORK.md](AI-SECURITY-FRAMEWORK.md) for full mapping.

## Related Projects

- **[AEGIS Pay](https://github.com/Moudaxx/AEGIS-Pay)** — Secure Payment Layer for AI Agents (x402 + EIP-3009 + USDC)

## Tech Stack

Rust, Axum, Tokio, Wasmtime, Docker, Prometheus, Grafana, GitHub Actions

## License

MIT — See [LICENSE](LICENSE)

## Links

- 🌐 Website: [moudaxx.github.io/AEGIS-OS](https://moudaxx.github.io/AEGIS-OS/)
- 📄 Security Framework: [AI-SECURITY-FRAMEWORK.md](AI-SECURITY-FRAMEWORK.md)
- 💰 AEGIS Pay: [github.com/Moudaxx/AEGIS-Pay](https://github.com/Moudaxx/AEGIS-Pay)

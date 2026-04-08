# AEGIS OS v4.1

Autonomous AI agent security platform built in Rust.

[![Release](https://img.shields.io/github/v/release/Moudaxx/AEGIS-OS)](https://github.com/Moudaxx/AEGIS-OS/releases)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Security Integration Tests](https://img.shields.io/badge/Security_Integration-79%2F79-brightgreen)](tests/security_integration.rs)
[![Advanced Security Tests](https://img.shields.io/badge/Advanced_Security-60%2F60-brightgreen)](tests/advanced_security.rs)
[![OWASP](https://img.shields.io/badge/OWASP_LLM_Top_10-10%2F10-brightgreen)](AI-SECURITY-FRAMEWORK.md)

AEGIS OS protects AI agents with layered controls for sanitization, isolation, policy enforcement, runtime monitoring, red-team simulation, and reporting.

## Highlights

- 12 security layers spanning gateway, policy, sandboxing, credentials, runtime risk, and audit.
- Autonomous security loop with discovery, testing, analysis, blocking, learning, and reporting.
- Rust CLI plus HTTP/TLS server powered by Axum.
- Multi-provider AI inference support for NVIDIA NIM, Groq, OpenAI, Gemini, Claude, Ollama, Mistral, DeepSeek, and Cosmos.
- Security-focused modules for RAG poisoning checks, privacy filtering, extraction detection, hallucination detection, and watermarking.

## Commands

```bash
cargo run -- autonomous     # Autonomous security daemon
cargo run -- serve          # HTTP server on :8401
cargo run -- serve-tls      # HTTPS server on :8443
cargo run -- red-team       # Run the red-team simulation suite
```

## Autonomous Workflow

1. Discover AI agents across supported environments.
2. Run continuous security tests and simulations.
3. Score threats and match known attack patterns.
4. Block risky agents automatically when thresholds are exceeded.
5. Learn from incidents and generate new rules.
6. Produce JSON/HTML reports for operators.

## Test Coverage

The repository currently contains 139 documented test assertions across the two main Rust integration suites:

- `tests/security_integration.rs`: 79 checks
- `tests/advanced_security.rs`: 60 checks

These suites cover capability tokens, credential handling, skill vetting, input sanitization, filesystem/network controls, runtime risk scoring, RAG security, privacy filtering, extraction detection, hallucination detection, watermarking, and combined attack scenarios.

## HTTP Surface

```bash
cargo run -- serve
cargo run -- serve-tls
```

Key routes include:

- `GET /health`
- `POST /api/v1/agents/run`
- `POST /api/v1/agents/stop`
- `GET /api/v1/agents/list`
- `GET /api/v1/agents/status`
- `POST /api/v1/inference`
- `POST /api/v1/redteam`
- `POST /api/v1/tools`
- `GET /api/v1/audit`
- `GET /api/v1/metrics`
- `GET /api/v1/dashboard`
- `POST /mcp/tools/*`

## Quick Start

```bash
git clone https://github.com/Moudaxx/AEGIS-OS.git
cd AEGIS-OS
cp .env.example .env
cargo build
cargo run -- autonomous --cycles 3
```

## Docker

```bash
docker-compose up -d
```

## Continuous Development

The repository includes built-in automation for continuous improvement:

- `AEGIS CI` runs on every push and pull request to check formatting, linting, tests, release builds, and the Docker image.
- `AEGIS Maintenance` runs every 6 hours, uploads a repository health report, and opens a GitHub issue if scheduled checks fail.
- `Dependabot` keeps Cargo, GitHub Actions, and Docker dependencies moving forward weekly.

See [docs/continuous-development.md](docs/continuous-development.md) for the full operating model and the remaining setup needed for fully autonomous code-writing agents.

## License

AEGIS OS uses the dual-license terms described in [LICENSE](LICENSE):

- Open-source and non-commercial use: `AGPL-3.0`
- Commercial or SaaS use: commercial license required

See [COMMERCIAL.md](COMMERCIAL.md) for commercial terms.

## Related Project

- [AEGIS Pay](https://github.com/Moudaxx/AEGIS-Pay)

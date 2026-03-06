# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AEGIS OS, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email: [Add your security email]
2. Include: description, steps to reproduce, potential impact
3. We will respond within 48 hours
4. We will work with you to understand and fix the issue

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.0.x   | ✅        |
| < 4.0   | ❌        |

## Security Measures

AEGIS OS implements 12 security layers:
- WASM Sandbox isolation
- Filesystem jail with path traversal protection
- Network egress allowlist
- Capability-based access control
- Credential vault with TTL and revocation
- Skill vetting pipeline
- Input sanitization (21 injection patterns)
- Policy engine with rate limiting
- State integrity monitoring
- Runtime risk scoring (4 dimensions)
- Audit logging with SIEM export
- Red Team automated testing (16 attack vectors)

## Security Tests
```bash
# Run integration tests (75 tests)
cargo test --test security_integration -- --nocapture

# Run Red Team scan (16 attack vectors)
cargo run -- red-team
```
# NIST AI RMF — AEGIS OS Mapping

## Framework Alignment

### GOVERN (Governance)
| NIST Requirement | AEGIS Module | Status |
|-----------------|-------------|--------|
| Risk management policies | Policy Engine (5 rules) | ✅ |
| Roles and responsibilities | RBAC (4 roles) | ✅ |
| Compliance documentation | AI-SECURITY-FRAMEWORK.md | ✅ |
| Audit capabilities | Persistent Audit Logger | ✅ |

### MAP (Context)
| NIST Requirement | AEGIS Module | Status |
|-----------------|-------------|--------|
| AI system inventory | Agent registry + status | ✅ |
| Risk identification | Risk Scoring (4 dimensions) | ✅ |
| Stakeholder engagement | Dashboard endpoint | ✅ |
| Impact assessment | Red Team reports | ✅ |

### MEASURE (Assessment)
| NIST Requirement | AEGIS Module | Status |
|-----------------|-------------|--------|
| Performance metrics | Prometheus (13 metrics) | ✅ |
| Security testing | Red Team (16 attacks) | ✅ |
| Bias detection | Output validation | ✅ |
| Continuous monitoring | Grafana dashboard | ✅ |

### MANAGE (Response)
| NIST Requirement | AEGIS Module | Status |
|-----------------|-------------|--------|
| Incident response | Auto PAUSE/KILL | ✅ |
| Risk mitigation | 12-layer defense | ✅ |
| Communication | SIEM export (Sentinel) | ✅ |
| Continuous improvement | Red Team + Audit review | ✅ |

## AI Agent Standards Initiative (February 2026)

NIST launched the AI Agent Standards Initiative with 3 pillars:

1. **Industry-led standards** → AEGIS implements OWASP + MAESTRO controls
2. **Open-source protocols** → AEGIS supports MCP + A2A
3. **Security research** → AEGIS Red Team provides ongoing testing

## Stanford AIUC-1 Alignment

| Requirement | AEGIS Module |
|------------|-------------|
| Sandboxed execution | WASM + Filesystem Jail |
| Scoped credentials | Capability Tokens + TTL |
| Runtime policy | Policy Engine + RBAC |
| Audit logging | Persistent Audit + SIEM |

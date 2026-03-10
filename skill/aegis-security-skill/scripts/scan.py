#!/usr/bin/env python3
"""AEGIS Security Scanner — Quick scan for AI security issues"""

import sys
import json
import re
from datetime import datetime

# ─── Prompt Injection Patterns ───
INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|your)\s+instructions",
    r"disregard\s+(your|all)\s+instructions",
    r"you\s+are\s+now\s+",
    r"new\s+instructions\s*:",
    r"system\s+prompt\s*:",
    r"reveal\s+your",
    r"admin\s+override",
    r"sudo\s+mode",
    r"developer\s+mode",
    r"DAN\s+mode",
    r"jailbreak",
    r"bypass\s+(your\s+)?filters",
    r"<script>",
    r"javascript\s*:",
    r"data:text/html",
    r"[\x00-\x1f]",
    r"INST\]",
    r"<<SYS>>",
    r"\|im_start\|",
    r"base64[:\s]",
    r"forget\s+(your\s+)?rules",
]

# ─── Privacy Patterns ───
PRIVACY_PATTERNS = [
    (r"nvapi-[A-Za-z0-9]{20,}", "NVIDIA API Key"),
    (r"sk-ant-[A-Za-z0-9]{20,}", "Anthropic API Key"),
    (r"sk-proj-[A-Za-z0-9]{20,}", "OpenAI API Key"),
    (r"gsk_[A-Za-z0-9]{20,}", "Groq API Key"),
    (r"AIzaSy[A-Za-z0-9_-]{33}", "Google API Key"),
    (r"xoxb-[0-9]{10,}", "Slack Bot Token"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Token"),
    (r"glpat-[A-Za-z0-9_-]{20}", "GitLab Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"eyJhbG[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token"),
    (r"BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE", "Private Key"),
    (r"password\s*[=:]\s*['\"]?\S+", "Password in plaintext"),
]

# ─── Hallucination Indicators ───
HALLUCINATION_PATTERNS = [
    (r"i\s+am\s+100%\s+certain", "Overconfidence"),
    (r"this\s+is\s+absolutely\s+true", "Overconfidence"),
    (r"i\s+can\s+guarantee", "Overconfidence"),
    (r"published\s+in\s+the\s+journal\s+of", "Fabricated reference"),
    (r"according\s+to\s+a\s+study\s+by", "Possible fabrication"),
    (r"i\s+can\s+access\s+the\s+internet", "Impossible claim"),
    (r"i\s+can\s+see\s+your\s+screen", "Impossible claim"),
    (r"i\s+have\s+feelings", "Impossible claim"),
]


def scan_injection(text):
    """Scan text for prompt injection patterns"""
    findings = []
    text_lower = text.lower()
    for i, pattern in enumerate(INJECTION_PATTERNS, 1):
        if re.search(pattern, text_lower, re.IGNORECASE):
            findings.append({
                "pattern_id": i,
                "pattern": pattern,
                "severity": "HIGH",
                "category": "Prompt Injection (OWASP LLM01)"
            })
    return findings


def scan_privacy(text):
    """Scan text for PII and secrets"""
    findings = []
    for pattern, name in PRIVACY_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            findings.append({
                "type": name,
                "count": len(matches),
                "severity": "CRITICAL" if "Key" in name or "Private" in name else "HIGH",
                "category": "Data Exposure"
            })
    return findings


def scan_hallucination(text):
    """Scan AI output for hallucination indicators"""
    findings = []
    text_lower = text.lower()
    for pattern, indicator in HALLUCINATION_PATTERNS:
        if re.search(pattern, text_lower):
            findings.append({
                "indicator": indicator,
                "severity": "MEDIUM",
                "category": "Hallucination Risk"
            })
    return findings


def full_scan(text, scan_type="all"):
    """Run security scan"""
    results = {
        "timestamp": datetime.now().isoformat(),
        "input_length": len(text),
        "scan_type": scan_type,
        "domains": {},
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
    }

    if scan_type in ("all", "injection"):
        injection = scan_injection(text)
        results["domains"]["prompt_injection"] = {
            "status": "FAIL" if injection else "PASS",
            "findings": injection,
            "patterns_checked": len(INJECTION_PATTERNS)
        }
        for f in injection:
            results["summary"][f["severity"].lower()] = results["summary"].get(f["severity"].lower(), 0) + 1

    if scan_type in ("all", "privacy"):
        privacy = scan_privacy(text)
        results["domains"]["privacy"] = {
            "status": "FAIL" if privacy else "PASS",
            "findings": privacy,
            "patterns_checked": len(PRIVACY_PATTERNS)
        }
        for f in privacy:
            results["summary"][f["severity"].lower()] = results["summary"].get(f["severity"].lower(), 0) + 1

    if scan_type in ("all", "hallucination"):
        halluc = scan_hallucination(text)
        results["domains"]["hallucination"] = {
            "status": "WARNING" if halluc else "PASS",
            "findings": halluc,
            "patterns_checked": len(HALLUCINATION_PATTERNS)
        }
        for f in halluc:
            results["summary"][f["severity"].lower()] = results["summary"].get(f["severity"].lower(), 0) + 1

    total_issues = sum(results["summary"].values())
    results["overall_score"] = max(0, 100 - (total_issues * 15))
    results["overall_status"] = "PASS" if total_issues == 0 else "FAIL" if results["summary"]["critical"] > 0 or results["summary"]["high"] > 0 else "WARNING"

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <text_or_file> [scan_type]")
        print("  scan_type: all, injection, privacy, hallucination")
        sys.exit(1)

    input_arg = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "all"

    # Check if input is a file
    try:
        with open(input_arg, 'r') as f:
            text = f.read()
    except (FileNotFoundError, IsADirectoryError):
        text = input_arg

    results = full_scan(text, scan_type)
    print(json.dumps(results, indent=2))

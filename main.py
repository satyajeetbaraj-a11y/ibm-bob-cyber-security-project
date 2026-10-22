#!/usr/bin/env python3
"""
Passive Header & CORS Auditor
Checks HTTP security headers, cookie attributes, and CORS configuration.
Supports CLI and web modes.
"""
from __future__ import annotations

__version__ = "1.0.0"

import argparse
import csv
import html as html_mod
import io
import json
import socket
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any

# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)


RULES: dict[str, Rule] = {
    r.rule_id: r for r in [
        Rule(
            rule_id="H001",
            title="Missing Strict-Transport-Security",
            severity="HIGH",
            description="The Strict-Transport-Security (HSTS) header was not found. "
                        "Without it, browsers may connect over plain HTTP.",
            remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        ),
        Rule(
            rule_id="H002",
            title="Missing X-Content-Type-Options",
            severity="MEDIUM",
            description="X-Content-Type-Options: nosniff was not found. "
                        "Browsers may MIME-sniff responses away from the declared content-type.",
            remediation="Add: X-Content-Type-Options: nosniff",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
        ),
        Rule(
            rule_id="H003",
            title="Missing X-Frame-Options",
            severity="MEDIUM",
            description="X-Frame-Options was not found. The page could be embedded in a frame "
                        "and used in click-jacking attacks.",
            remediation="Add: X-Frame-Options: DENY (or SAMEORIGIN)",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
        ),
        Rule(
            rule_id="H004",
            title="Missing Content-Security-Policy",
            severity="HIGH",
            description="No Content-Security-Policy header was found. "
                        "CSP restricts resource loading and mitigates XSS.",
            remediation="Define a CSP suited to the application's needs.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
        ),
        Rule(
            rule_id="H005",
            title="Missing Referrer-Policy",
            severity="LOW",
            description="Referrer-Policy was not found. Browsers may leak the full URL "
                        "in the Referer header to third parties.",
            remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
        ),
        Rule(
            rule_id="H006",
            title="Missing Permissions-Policy",
            severity="LOW",
            description="Permissions-Policy (formerly Feature-Policy) was not found. "
                        "Without it the browser may grant access to powerful APIs.",
            remediation="Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
        ),
        Rule(
            rule_id="H007",
            title="Server header exposes version",
            severity="LOW",
            description="The Server response header discloses software version information "
                        "that can assist an attacker in targeting known vulnerabilities.",
            remediation="Configure the server to suppress or genericise the Server header.",
            references=["https://owasp.org/www-project-secure-headers/"],
        ),
        Rule(
            rule_id="H008",
            title="X-Powered-By header present",
            severity="LOW",
            description="X-Powered-By reveals the application framework or runtime version.",
            remediation="Remove the X-Powered-By header from the server configuration.",
            references=["https://owasp.org/www-project-secure-headers/"],
        ),
        Rule(
            rule_id="H009",
            title="HSTS max-age too short",
            severity="MEDIUM",
            description="Strict-Transport-Security max-age is less than 1 year (31536000 seconds). "
                        "A short max-age reduces protection.",
            remediation="Set max-age to at least 31536000.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        ),
        Rule(
            rule_id="H010",
            title="CSP allows unsafe-inline scripts",
            severity="HIGH",
            description="Content-Security-Policy includes 'unsafe-inline' for script-src, "
                        "significantly weakening XSS protection.",
            remediation="Remove 'unsafe-inline' from script-src and use nonces or hashes instead.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"],
        ),
        Rule(
            rule_id="H011",
            title="CSP allows unsafe-eval",
            severity="HIGH",
            description="Content-Security-Policy includes 'unsafe-eval', allowing eval() and "
                        "related functions which are frequently exploited in XSS attacks.",
            remediation="Remove 'unsafe-eval' from script-src.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"],
        ),
        Rule(
            rule_id="C001",
            title="Cookie missing Secure flag",
            severity="HIGH",
            description="One or more cookies are set without the Secure attribute. "
                        "They may be transmitted over unencrypted connections.",
            remediation="Add the Secure attribute to all cookies.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
        ),
        Rule(
            rule_id="C002",
            title="Cookie missing HttpOnly flag",
            severity="MEDIUM",
            description="One or more cookies lack the HttpOnly attribute. "
                        "They can be read by JavaScript, aiding XSS cookie theft.",
            remediation="Add the HttpOnly attribute to session and authentication cookies.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
        ),
        Rule(
            rule_id="C003",
            title="Cookie SameSite not set or Lax/None",
            severity="MEDIUM",
            description="One or more cookies do not use SameSite=Strict. "
                        "SameSite=None exposes cookies to CSRF; missing SameSite defaults vary by browser.",
            remediation="Set SameSite=Strict on session cookies where cross-site requests are not needed.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
        ),
        Rule(
            rule_id="R001",
            title="CORS wildcard Access-Control-Allow-Origin",
            severity="HIGH",
            description="The server returns Access-Control-Allow-Origin: * "
                        "allowing any origin to read the response.",
            remediation="Restrict Access-Control-Allow-Origin to trusted origins.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
        ),
        Rule(
            rule_id="R002",
            title="CORS reflects arbitrary Origin",
            severity="CRITICAL",
            description="The server echoes back the value of the Origin request header, "
                        "granting any origin cross-site access.",
            remediation="Maintain an explicit allowlist of permitted origins.",
            references=["https://portswigger.net/web-security/cors"],
        ),
        Rule(
            rule_id="R003",
            title="CORS allows credentials with wildcard or reflected origin",
            severity="CRITICAL",
            description="Access-Control-Allow-Credentials: true is combined with a wildcard or "
                        "reflected origin, allowing any site to make credentialed cross-origin requests.",
            remediation="Never combine Allow-Credentials: true with * or reflected origins.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
        ),
        Rule(
            rule_id="R004",
            title="CORS allows null origin",
            severity="HIGH",
            description="The server accepts Origin: null, which can be exploited via sandboxed iframes.",
            remediation="Do not add null to the CORS origin allowlist.",
            references=["https://portswigger.net/web-security/cors/cors-bypass"],
        ),
        Rule(
            rule_id="R005",
            title="Overly permissive CORS allowed methods",
            severity="MEDIUM",
            description="Access-Control-Allow-Methods includes dangerous verbs such as DELETE or PUT "
                        "beyond what the application requires.",
            remediation="Restrict allowed methods to only those the endpoint actually uses.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
        ),
    ]
}


# ---------------------------------------------------------------------------
# Data classes for scan results
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    detail: str
    evidence: str
    remediation: str


@dataclass
class TargetResult:
    url: str
    final_url: str
    status_code: int
    score: int          # 0-100
    grade: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    def severity_tally(self) -> dict[str, int]:
        tally: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for f in self.findings:
            tally[f.severity] = tally.get(f.severity, 0) + 1
        return tally


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_DEDUCTION: dict[str, int] = {
    "CRITICAL": 30,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
}

_PROBE_ORIGIN = "https://evil.example.com"
_NULL_ORIGIN = "null"
_REQUEST_TIMEOUT = 15
_POLITE_DELAY = 0.5

USER_AGENT = f"PassiveHeaderAuditor/{__version__} (security-scanner; passive)"


def _make_request(
    url: str,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    insecure: bool = False,
) -> tuple[urllib.request.Request, Any]:
    """Return (request, response). Raises on network error."""
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "*/*")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)

    ctx = None
    if insecure:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    resp = urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT, context=ctx)
    return req, resp


def _redact_cookie_value(raw: str) -> str:
    """Keep cookie name, redact value."""
    parts = raw.split(";")
    if not parts:
        return raw
    name_value = parts[0].strip()
    if "=" in name_value:
        name = name_value.split("=", 1)[0]
        parts[0] = f"{name}=<redacted>"
    return "; ".join(parts)


def _check_headers(
    headers: Any,
    findings: list[Finding],
    check_body: bool = False,
    body_text: str = "",
) -> None:
    """Populate findings list from response headers."""
    hdr = {k.lower(): v for k, v in headers.items()}

    # H001 HSTS
    hsts = hdr.get("strict-transport-security", "")
    if not hsts:
        findings.append(Finding(
            rule_id="H001",
            title=RULES["H001"].title,
            severity=RULES["H001"].severity,
            detail="Header not present.",
            evidence="",
            remediation=RULES["H001"].remediation,
        ))
    else:
        # H009 short max-age
        for part in hsts.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    age = int(part.split("=", 1)[1].strip())
                    if age < 31536000:
                        findings.append(Finding(
                            rule_id="H009",
                            title=RULES["H009"].title,
                            severity=RULES["H009"].severity,
                            detail=f"max-age={age} is less than 31536000.",
                            evidence=hsts,
                            remediation=RULES["H009"].remediation,
                        ))
                except ValueError:
                    pass

    # H002 X-Content-Type-Options
    if "x-content-type-options" not in hdr:
        findings.append(Finding(
            rule_id="H002",
            title=RULES["H002"].title,
            severity=RULES["H002"].severity,
            detail="Header not present.",
            evidence="",
            remediation=RULES["H002"].remediation,
        ))

    # H003 X-Frame-Options
    if "x-frame-options" not in hdr and "content-security-policy" not in hdr:
        findings.append(Finding(
            rule_id="H003",
            title=RULES["H003"].title,
            severity=RULES["H003"].severity,
            detail="Neither X-Frame-Options nor CSP frame-ancestors found.",
            evidence="",
            remediation=RULES["H003"].remediation,
        ))

    # H004 CSP
    csp = hdr.get("content-security-policy", "")
    if not csp:
        findings.append(Finding(
            rule_id="H004",
            title=RULES["H004"].title,
            severity=RULES["H004"].severity,
            detail="Header not present.",
            evidence="",
            remediation=RULES["H004"].remediation,
        ))
    else:
        csp_lower = csp.lower()
        # H010 unsafe-inline
        if "unsafe-inline" in csp_lower and "script-src" in csp_lower:
            findings.append(Finding(
                rule_id="H010",
                title=RULES["H010"].title,
                severity=RULES["H010"].severity,
                detail="script-src contains 'unsafe-inline'.",
                evidence=csp[:200],
                remediation=RULES["H010"].remediation,
            ))
        # H011 unsafe-eval
        if "unsafe-eval" in csp_lower:
            findings.append(Finding(
                rule_id="H011",
                title=RULES["H011"].title,
                severity=RULES["H011"].severity,
                detail="CSP contains 'unsafe-eval'.",
                evidence=csp[:200],
                remediation=RULES["H011"].remediation,
            ))

    # H005 Referrer-Policy
    if "referrer-policy" not in hdr:
        findings.append(Finding(
            rule_id="H005",
            title=RULES["H005"].title,
            severity=RULES["H005"].severity,
            detail="Header not present.",
            evidence="",
            remediation=RULES["H005"].remediation,
        ))

    # H006 Permissions-Policy
    if "permissions-policy" not in hdr and "feature-policy" not in hdr:
        findings.append(Finding(
            rule_id="H006",
            title=RULES["H006"].title,
            severity=RULES["H006"].severity,
            detail="Header not present.",
            evidence="",
            remediation=RULES["H006"].remediation,
        ))

    # H007 Server version leak
    server = hdr.get("server", "")
    if server:
        import re
        if re.search(r"[\d.]", server):
            findings.append(Finding(
                rule_id="H007",
                title=RULES["H007"].title,
                severity=RULES["H007"].severity,
                detail="Server header contains version information.",
                evidence=server[:120],
                remediation=RULES["H007"].remediation,
            ))

    # H008 X-Powered-By
    xpb = hdr.get("x-powered-by", "")
    if xpb:
        findings.append(Finding(
            rule_id="H008",
            title=RULES["H008"].title,
            severity=RULES["H008"].severity,
            detail="Header reveals framework/runtime.",
            evidence=xpb[:120],
            remediation=RULES["H008"].remediation,
        ))


def _check_cookies(raw_cookies: list[str], findings: list[Finding]) -> None:
    """Check Set-Cookie headers for security attributes."""
    missing_secure: list[str] = []
    missing_httponly: list[str] = []
    bad_samesite: list[str] = []

    for raw in raw_cookies:
        parts = [p.strip().lower() for p in raw.split(";")]
        attrs = set(parts[1:])
        name = raw.split("=", 1)[0].strip()

        has_secure = "secure" in attrs
        has_httponly = "httponly" in attrs
        samesite_strict = any(p == "samesite=strict" for p in attrs)
        samesite_none = any(p == "samesite=none" for p in attrs)
        has_samesite = any(p.startswith("samesite=") for p in attrs)

        if not has_secure:
            missing_secure.append(name)
        if not has_httponly:
            missing_httponly.append(name)
        if samesite_none or not has_samesite:
            bad_samesite.append(name)

    if missing_secure:
        findings.append(Finding(
            rule_id="C001",
            title=RULES["C001"].title,
            severity=RULES["C001"].severity,
            detail=f"Cookies without Secure flag: {', '.join(missing_secure[:5])}",
            evidence="(values redacted)",
            remediation=RULES["C001"].remediation,
        ))
    if missing_httponly:
        findings.append(Finding(
            rule_id="C002",
            title=RULES["C002"].title,
            severity=RULES["C002"].severity,
            detail=f"Cookies without HttpOnly flag: {', '.join(missing_httponly[:5])}",
            evidence="(values redacted)",
            remediation=RULES["C002"].remediation,
        ))
    if bad_samesite:
        findings.append(Finding(
            rule_id="C003",
            title=RULES["C003"].title,
            severity=RULES["C003"].severity,
            detail=f"Cookies without SameSite=Strict: {', '.join(bad_samesite[:5])}",
            evidence="(values redacted)",
            remediation=RULES["C003"].remediation,
        ))


def _check_cors(url: str, insecure: bool, findings: list[Finding]) -> None:
    """Probe CORS configuration with passive OPTIONS requests."""
    probes = [
        ("arbitrary_origin", {"Origin": _PROBE_ORIGIN}),
        ("null_origin", {"Origin": _NULL_ORIGIN}),
    ]
    for probe_name, extra in probes:
        try:
            time.sleep(_POLITE_DELAY)
            _, resp = _make_request(
                url, method="OPTIONS",
                extra_headers=extra,
                insecure=insecure,
            )
            hdr = {k.lower(): v for k, v in resp.headers.items()}
            acao = hdr.get("access-control-allow-origin", "")
            acac = hdr.get("access-control-allow-credentials", "").lower()
            acam = hdr.get("access-control-allow-methods", "")
            resp.close()
        except Exception:
            continue

        if probe_name == "arbitrary_origin":
            if acao == "*":
                findings.append(Finding(
                    rule_id="R001",
                    title=RULES["R001"].title,
                    severity=RULES["R001"].severity,
                    detail="Server returns Access-Control-Allow-Origin: *",
                    evidence=f"ACAO: {acao}",
                    remediation=RULES["R001"].remediation,
                ))
            if acao == _PROBE_ORIGIN:
                findings.append(Finding(
                    rule_id="R002",
                    title=RULES["R002"].title,
                    severity=RULES["R002"].severity,
                    detail="Server reflects the request Origin header verbatim.",
                    evidence=f"ACAO: {acao}",
                    remediation=RULES["R002"].remediation,
                ))
            # R003 credentials with wildcard/reflected
            if acac == "true" and (acao == "*" or acao == _PROBE_ORIGIN):
                findings.append(Finding(
                    rule_id="R003",
                    title=RULES["R003"].title,
                    severity=RULES["R003"].severity,
                    detail="Credentials allowed with wildcard or reflected origin.",
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    remediation=RULES["R003"].remediation,
                ))
            # R005 dangerous methods
            if acam:
                dangerous = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}
                allowed_methods = {m.strip().upper() for m in acam.split(",")}
                found_dangerous = dangerous & allowed_methods
                if found_dangerous:
                    findings.append(Finding(
                        rule_id="R005",
                        title=RULES["R005"].title,
                        severity=RULES["R005"].severity,
                        detail=f"Dangerous methods allowed: {', '.join(sorted(found_dangerous))}",
                        evidence=f"ACAM: {acam}",
                        remediation=RULES["R005"].remediation,
                    ))

        if probe_name == "null_origin" and acao == "null":
            findings.append(Finding(
                rule_id="R004",
                title=RULES["R004"].title,
                severity=RULES["R004"].severity,
                detail="Server accepts Origin: null.",
                evidence=f"ACAO: {acao}",
                remediation=RULES["R004"].remediation,
            ))


def _compute_score_grade(findings: list[Finding]) -> tuple[int, str]:
    score = 100
    for f in findings:
        score -= _DEDUCTION.get(f.severity, 0)
    score = max(0, score)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def scan_target(
    url: str,
    insecure: bool = False,
    check_body: bool = False,
) -> TargetResult:
    """Scan a single URL and return a TargetResult."""
    findings: list[Finding] = []
    final_url = url
    status_code = 0

    try:
        time.sleep(_POLITE_DELAY)
        _, resp = _make_request(url, insecure=insecure)
        final_url = resp.url if hasattr(resp, "url") else url
        status_code = resp.status

        raw_headers = resp.headers
        raw_cookies = resp.headers.get_all("set-cookie") or []
        body_text = ""
        if check_body:
            try:
                body_text = resp.read(65536).decode("utf-8", errors="replace")
            except Exception:
                pass
        resp.close()

        _check_headers(raw_headers, findings, check_body, body_text)
        _check_cookies(raw_cookies, findings)
        _check_cors(url, insecure, findings)

    except urllib.error.HTTPError as e:
        status_code = e.code
        try:
            raw_headers = e.headers
            raw_cookies = e.headers.get_all("set-cookie") or []
            _check_headers(raw_headers, findings)
            _check_cookies(raw_cookies, findings)
        except Exception:
            pass
        _check_cors(url, insecure, findings)
    except urllib.error.URLError as e:
        return TargetResult(
            url=url, final_url=url, status_code=0,
            score=0, grade="F", error=str(e.reason),
        )
    except Exception as e:
        return TargetResult(
            url=url, final_url=url, status_code=0,
            score=0, grade="F", error=str(e),
        )

    # Deduplicate by rule_id (keep first occurrence)
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            unique.append(f)

    # Sort by severity
    unique.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    score, grade = _compute_score_grade(unique)
    return TargetResult(
        url=url, final_url=final_url, status_code=status_code,
        score=score, grade=grade, findings=unique,
    )


def results_to_dict(results: list[TargetResult]) -> list[dict]:
    out = []
    for r in results:
        d = asdict(r)
        d["severity_tally"] = r.severity_tally()
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# CLI output
# ---------------------------------------------------------------------------

_SEVERITY_COLOUR = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[0;31m",
    "MEDIUM": "\033[0;33m",
    "LOW": "\033[0;34m",
    "INFO": "\033[0;37m",
}
_RESET = "\033[0m"


def _colourise(text: str, severity: str, colour: bool) -> str:
    if not colour:
        return text
    return f"{_SEVERITY_COLOUR.get(severity, '')}{text}{_RESET}"


def print_results_cli(results: list[TargetResult], colour: bool = True, verbose: bool = False) -> None:
    for r in results:
        print(f"\n{'='*70}")
        print(f"  URL   : {r.url}")
        if r.final_url != r.url:
            print(f"  Final : {r.final_url}")
        print(f"  Status: {r.status_code}")
        print(f"  Score : {r.score}/100  Grade: {r.grade}")
        tally = r.severity_tally()
        tally_str = "  ".join(
            f"{sev}: {tally[sev]}"
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if tally[sev]
        )
        if tally_str:
            print(f"  Tally : {tally_str}")
        if r.error:
            print(f"  Error : {r.error}")
        if r.findings:
            print(f"\n  {'SEV':<10} {'ID':<6} {'TITLE'}")
            print(f"  {'-'*60}")
            for f in r.findings:
                label = _colourise(f.severity.ljust(10), f.severity, colour)
                print(f"  {label} {f.rule_id:<6} {f.title}")
                if verbose:
                    print(f"         Detail: {f.detail}")
                    if f.evidence:
                        print(f"         Evidence: {f.evidence[:100]}")
                    print(f"         Fix: {f.remediation}")
        else:
            print("  No findings.")


# ---------------------------------------------------------------------------
# HTML / CSS / JS for the web UI (Python string constants)
# ---------------------------------------------------------------------------

_HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Passive Header &amp; CORS Auditor</title>
<style>
:root {
  --bg: #ffffff;
  --surface: #f7f8fa;
  --border: #e5e7eb;
  --text: #1f2328;
  --muted: #57606a;
  --accent: #3b82d4;
  --secondary: #7c5cd8;
  --c-critical: #dc2626;
  --c-high: #ea580c;
  --c-medium: #d97706;
  --c-low: #2563eb;
  --c-info: #6b7280;
  --radius: 6px;
  --shadow: 0 1px 3px rgba(0,0,0,.08);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --secondary: #bc8cff;
    --c-critical: #f85149;
    --c-high: #fb923c;
    --c-medium: #f59e0b;
    --c-low: #60a5fa;
    --c-info: #9ca3af;
  }
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
  font-size: 15px;
  line-height: 1.6;
  background: var(--bg);
  color: var(--text);
  padding: 0 16px 60px;
}
header {
  border-bottom: 1px solid var(--border);
  padding: 16px 0 12px;
  margin-bottom: 24px;
}
header h1 { font-size: 1.3rem; font-weight: 700; }
header p { color: var(--muted); font-size: 0.875rem; }
.container { max-width: 860px; margin: 0 auto; }
nav { display: flex; gap: 2px; margin-bottom: 24px; border-bottom: 1px solid var(--border); }
nav button {
  background: none; border: none; padding: 8px 16px;
  cursor: pointer; font-size: 0.9rem; color: var(--muted);
  border-bottom: 2px solid transparent; margin-bottom: -1px;
}
nav button.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
nav button:hover { color: var(--text); }
.tab { display: none; }
.tab.active { display: block; }
label { display: block; font-size: 0.875rem; margin-bottom: 4px; color: var(--muted); }
textarea {
  width: 100%;
  font-family: ui-monospace, "Cascadia Code", monospace;
  font-size: 0.85rem;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  color: var(--text);
  resize: vertical;
  min-height: 100px;
}
textarea:focus { outline: 2px solid var(--accent); border-color: transparent; }
.checks { display: flex; flex-wrap: wrap; gap: 16px; margin: 12px 0; }
.check-item { display: flex; align-items: center; gap: 6px; font-size: 0.875rem; }
.check-item input[type=checkbox] { width: 16px; height: 16px; cursor: pointer; accent-color: var(--accent); }
.auth-notice {
  background: #fff8e1;
  border: 1px solid #f59e0b;
  border-radius: var(--radius);
  padding: 10px 14px;
  font-size: 0.85rem;
  margin-bottom: 14px;
  color: #92400e;
  display: flex;
  align-items: flex-start;
  gap: 8px;
}
@media (prefers-color-scheme: dark) {
  .auth-notice { background: #1c1a0a; border-color: #78350f; color: #fde68a; }
}
.actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 14px; }
button.primary {
  background: var(--accent); color: #fff;
  border: none; padding: 9px 22px; border-radius: var(--radius);
  font-size: 0.9rem; font-weight: 600; cursor: pointer;
}
button.primary:disabled { opacity: .45; cursor: not-allowed; }
button.primary:not(:disabled):hover { filter: brightness(1.1); }
button.secondary {
  background: var(--surface); color: var(--text);
  border: 1px solid var(--border); padding: 8px 16px;
  border-radius: var(--radius); font-size: 0.875rem; cursor: pointer;
}
button.secondary:hover { border-color: var(--accent); color: var(--accent); }
.spinner {
  display: inline-block; width: 16px; height: 16px;
  border: 2px solid rgba(255,255,255,.4); border-top-color: #fff;
  border-radius: 50%; animation: spin .7s linear infinite; vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }
#results { margin-top: 28px; }
.result-card {
  border: 1px solid var(--border); border-radius: var(--radius);
  background: var(--surface); margin-bottom: 20px;
  box-shadow: var(--shadow); overflow: hidden;
}
.card-header {
  display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
  padding: 14px 16px; border-bottom: 1px solid var(--border);
  background: var(--bg);
}
.card-url { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 0.85rem; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.score-badge {
  font-size: 1rem; font-weight: 700; padding: 2px 10px;
  border-radius: 20px; border: 2px solid var(--border);
  white-space: nowrap;
}
.grade-A { color: #16a34a; border-color: #16a34a; }
.grade-B { color: #2563eb; border-color: #2563eb; }
.grade-C { color: #d97706; border-color: #d97706; }
.grade-D { color: #ea580c; border-color: #ea580c; }
.grade-F { color: #dc2626; border-color: #dc2626; }
.card-meta { padding: 8px 16px; font-size: 0.8rem; color: var(--muted); display: flex; flex-wrap: wrap; gap: 14px; border-bottom: 1px solid var(--border); }
.tally-badges { display: flex; gap: 6px; flex-wrap: wrap; }
.badge {
  font-size: 0.73rem; font-weight: 700; padding: 1px 7px;
  border-radius: 10px; text-transform: uppercase;
}
.badge-CRITICAL { background: var(--c-critical); color: #fff; }
.badge-HIGH { background: var(--c-high); color: #fff; }
.badge-MEDIUM { background: var(--c-medium); color: #fff; }
.badge-LOW { background: var(--c-low); color: #fff; }
.badge-INFO { background: var(--c-info); color: #fff; }
.findings-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
.findings-table th { text-align: left; padding: 8px 14px; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); border-bottom: 1px solid var(--border); background: var(--bg); }
.findings-table tr.finding-row { cursor: pointer; }
.findings-table tr.finding-row:hover td { background: rgba(59,130,212,.06); }
.findings-table td { padding: 9px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
.findings-table tr:last-child td { border-bottom: none; }
.expand-btn { background: none; border: none; color: var(--accent); font-size: 0.8rem; cursor: pointer; padding: 0; }
tr.detail-row td { padding: 12px 16px 14px; background: var(--surface); border-bottom: 1px solid var(--border); }
tr.detail-row { display: none; }
tr.detail-row.open { display: table-row; }
.detail-grid { display: grid; grid-template-columns: 90px 1fr; gap: 6px 12px; font-size: 0.83rem; }
.detail-grid dt { color: var(--muted); font-weight: 600; }
.detail-grid dd code { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 0.8rem; background: var(--bg); padding: 2px 6px; border-radius: 3px; border: 1px solid var(--border); display: inline-block; word-break: break-all; }
.no-findings { padding: 16px; color: var(--muted); font-size: 0.875rem; text-align: center; }
.error-card { background: #fff1f2; border-color: #fca5a5; }
@media (prefers-color-scheme: dark) { .error-card { background: #1c0a0a; border-color: #7f1d1d; } }
.error-msg { padding: 14px 16px; color: #dc2626; font-size: 0.875rem; }
.rules-grid { display: grid; gap: 12px; }
.rule-card { border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; background: var(--surface); }
.rule-card h3 { font-size: 0.95rem; display: flex; align-items: center; gap: 8px; }
.rule-card p { font-size: 0.85rem; color: var(--muted); margin-top: 4px; }
.rule-card .remediation { font-size: 0.82rem; margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border); color: var(--text); }
#scan-error { display: none; background: #fff1f2; border: 1px solid #fca5a5; border-radius: var(--radius); padding: 10px 14px; font-size: 0.875rem; color: #dc2626; margin-top: 12px; }
@media (prefers-color-scheme: dark) { #scan-error { background: #1c0a0a; border-color: #7f1d1d; } }
footer { text-align: center; font-size: 0.75rem; color: var(--muted); border-top: 1px solid var(--border); padding: 14px 0 0; margin-top: 40px; }
@media (max-width: 600px) {
  .card-header { flex-direction: column; align-items: flex-start; }
  .detail-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Passive Header &amp; CORS Auditor</h1>
    <p>Passively checks HTTP security headers, cookies, and CORS configuration.</p>
  </header>
  <nav>
    <button class="active" onclick="showTab('scan', this)">Scan</button>
    <button onclick="showTab('rules', this)">Rules</button>
  </nav>

  <div id="tab-scan" class="tab active">
    <label for="targets">Target URLs <span style="color:var(--muted)">(one per line, max 20)</span></label>
    <textarea id="targets" rows="5" placeholder="https://example.com&#10;https://another.org"></textarea>

    <div class="checks">
      <label class="check-item">
        <input type="checkbox" id="insecure">
        <span>Skip TLS verification</span>
      </label>
      <label class="check-item">
        <input type="checkbox" id="check-body">
        <span>Check response body</span>
      </label>
    </div>

    <div class="auth-notice">
      <span>&#x26A0;&#xFE0F;</span>
      <span>This tool makes real HTTP requests to the targets you provide. Only scan systems you own or have written authorisation to test.</span>
    </div>

    <label class="check-item" style="margin-bottom:12px;">
      <input type="checkbox" id="authorized" onchange="updateScanBtn()">
      <span><strong>I own these systems or have written authorisation to test them.</strong></span>
    </label>

    <div class="actions">
      <button class="primary" id="scan-btn" onclick="runScan()" disabled>Scan</button>
      <button class="secondary" id="dl-json" style="display:none" onclick="downloadJSON()">Download JSON</button>
      <button class="secondary" id="dl-csv" style="display:none" onclick="downloadCSV()">Download CSV</button>
    </div>
    <div id="scan-error"></div>
    <div id="results"></div>
  </div>

  <div id="tab-rules" class="tab">
    <div id="rules-content"><p style="color:var(--muted);font-size:.875rem">Loading rules...</p></div>
  </div>
</div>

<footer>Made with IBM Bob</footer>

<script>
"use strict";
var lastResults = null;

function showTab(name, btn) {
  document.querySelectorAll('.tab').forEach(function(t){ t.classList.remove('active'); });
  document.querySelectorAll('nav button').forEach(function(b){ b.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'rules') loadRules();
}

function updateScanBtn() {
  document.getElementById('scan-btn').disabled = !document.getElementById('authorized').checked;
}

function showError(msg) {
  var el = document.getElementById('scan-error');
  el.style.display = 'block';
  el.textContent = msg;
}

function hideError() {
  document.getElementById('scan-error').style.display = 'none';
}

function runScan() {
  hideError();
  var rawTargets = document.getElementById('targets').value;
  var targets = rawTargets.split('\n').map(function(s){ return s.trim(); }).filter(Boolean);
  if (!targets.length) { showError('Enter at least one target URL.'); return; }
  if (targets.length > 20) { showError('Maximum 20 targets per scan.'); return; }
  var insecure = document.getElementById('insecure').checked;
  var checkBody = document.getElementById('check-body').checked;

  var btn = document.getElementById('scan-btn');
  btn.innerHTML = '<span class="spinner"></span> Scanning…';
  btn.disabled = true;
  document.getElementById('results').innerHTML = '';
  document.getElementById('dl-json').style.display = 'none';
  document.getElementById('dl-csv').style.display = 'none';

  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targets: targets, insecure: insecure, check_body: checkBody, authorized: true })
  })
  .then(function(r){
    if (!r.ok) return r.json().then(function(d){ throw new Error(d.error || ('HTTP ' + r.status)); });
    return r.json();
  })
  .then(function(data) {
    lastResults = data;
    renderResults(data);
    document.getElementById('dl-json').style.display = '';
    document.getElementById('dl-csv').style.display = '';
  })
  .catch(function(e){ showError('Scan failed: ' + e.message); })
  .finally(function(){
    btn.textContent = 'Scan';
    btn.disabled = false;
    updateScanBtn();
  });
}

function renderResults(data) {
  var container = document.getElementById('results');
  container.innerHTML = '';
  data.forEach(function(r) {
    var card = document.createElement('div');
    card.className = 'result-card' + (r.error ? ' error-card' : '');

    var header = document.createElement('div');
    header.className = 'card-header';

    var urlSpan = document.createElement('span');
    urlSpan.className = 'card-url';
    urlSpan.textContent = r.url;
    header.appendChild(urlSpan);

    var scoreBadge = document.createElement('span');
    scoreBadge.className = 'score-badge grade-' + r.grade;
    scoreBadge.textContent = r.score + '/100 ' + r.grade;
    header.appendChild(scoreBadge);
    card.appendChild(header);

    var meta = document.createElement('div');
    meta.className = 'card-meta';
    var statusSpan = document.createElement('span');
    statusSpan.textContent = 'Status: ' + r.status_code;
    meta.appendChild(statusSpan);

    var tally = r.severity_tally;
    var tallyDiv = document.createElement('div');
    tallyDiv.className = 'tally-badges';
    ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(function(sev) {
      if (tally[sev]) {
        var b = document.createElement('span');
        b.className = 'badge badge-' + sev;
        b.textContent = sev + ': ' + tally[sev];
        tallyDiv.appendChild(b);
      }
    });
    meta.appendChild(tallyDiv);
    card.appendChild(meta);

    if (r.error) {
      var errDiv = document.createElement('div');
      errDiv.className = 'error-msg';
      errDiv.textContent = 'Error: ' + r.error;
      card.appendChild(errDiv);
    } else if (!r.findings || !r.findings.length) {
      var nf = document.createElement('div');
      nf.className = 'no-findings';
      nf.textContent = 'No findings — all checks passed.';
      card.appendChild(nf);
    } else {
      var table = document.createElement('table');
      table.className = 'findings-table';
      var thead = document.createElement('thead');
      var hr = document.createElement('tr');
      ['Severity','Rule','Title',''].forEach(function(h){
        var th = document.createElement('th');
        th.textContent = h;
        hr.appendChild(th);
      });
      thead.appendChild(hr); table.appendChild(thead);
      var tbody = document.createElement('tbody');
      r.findings.forEach(function(f, idx) {
        var rowId = 'det-' + r.url.replace(/\W/g,'') + idx;
        var row = document.createElement('tr');
        row.className = 'finding-row';
        row.onclick = function(){ toggleDetail(rowId); };

        var td1 = document.createElement('td');
        var badge = document.createElement('span');
        badge.className = 'badge badge-' + f.severity;
        badge.textContent = f.severity;
        td1.appendChild(badge); row.appendChild(td1);

        var td2 = document.createElement('td');
        td2.textContent = f.rule_id; row.appendChild(td2);

        var td3 = document.createElement('td');
        td3.textContent = f.title; row.appendChild(td3);

        var td4 = document.createElement('td');
        var expBtn = document.createElement('button');
        expBtn.className = 'expand-btn';
        expBtn.textContent = '▼';
        expBtn.setAttribute('aria-label', 'Expand');
        td4.appendChild(expBtn); row.appendChild(td4);

        tbody.appendChild(row);

        var detRow = document.createElement('tr');
        detRow.className = 'detail-row';
        detRow.id = rowId;
        var detTd = document.createElement('td');
        detTd.colSpan = 4;
        var dl = document.createElement('dl');
        dl.className = 'detail-grid';
        function addDetail(label, value) {
          var dt = document.createElement('dt'); dt.textContent = label;
          var dd = document.createElement('dd');
          if (value) {
            var code = document.createElement('code');
            code.textContent = value;
            dd.appendChild(code);
          } else {
            dd.textContent = '—';
          }
          dl.appendChild(dt); dl.appendChild(dd);
        }
        addDetail('Detail', f.detail);
        if (f.evidence) addDetail('Evidence', f.evidence);
        addDetail('Fix', f.remediation);
        detTd.appendChild(dl); detRow.appendChild(detTd);
        tbody.appendChild(detRow);
      });
      table.appendChild(tbody);
      card.appendChild(table);
    }
    container.appendChild(card);
  });
}

function toggleDetail(rowId) {
  var row = document.getElementById(rowId);
  if (!row) return;
  var isOpen = row.classList.contains('open');
  row.classList.toggle('open', !isOpen);
  var prevRow = row.previousElementSibling;
  if (prevRow) {
    var btn = prevRow.querySelector('.expand-btn');
    if (btn) btn.textContent = isOpen ? '▼' : '▲';
  }
}

function downloadJSON() {
  if (!lastResults) return;
  var blob = new Blob([JSON.stringify(lastResults, null, 2)], {type:'application/json'});
  triggerDownload(blob, 'scan-results.json');
}

function downloadCSV() {
  if (!lastResults) return;
  var rows = [['URL','Status','Score','Grade','RuleID','Severity','Title','Detail','Remediation']];
  lastResults.forEach(function(r) {
    if (!r.findings || !r.findings.length) {
      rows.push([r.url, r.status_code, r.score, r.grade, '', '', '', r.error || '', '']);
    } else {
      r.findings.forEach(function(f) {
        rows.push([r.url, r.status_code, r.score, r.grade, f.rule_id, f.severity, f.title, f.detail, f.remediation]);
      });
    }
  });
  var csv = rows.map(function(row){
    return row.map(function(cell){
      var s = String(cell).replace(/"/g,'""');
      return '"' + s + '"';
    }).join(',');
  }).join('\r\n');
  var blob = new Blob([csv], {type:'text/csv'});
  triggerDownload(blob, 'scan-results.csv');
}

function triggerDownload(blob, filename) {
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function loadRules() {
  var content = document.getElementById('rules-content');
  fetch('/api/rules')
    .then(function(r){ return r.json(); })
    .then(function(rules) {
      content.innerHTML = '';
      var grid = document.createElement('div');
      grid.className = 'rules-grid';
      rules.forEach(function(rule) {
        var card = document.createElement('div');
        card.className = 'rule-card';
        var h3 = document.createElement('h3');
        var badge = document.createElement('span');
        badge.className = 'badge badge-' + rule.severity;
        badge.textContent = rule.severity;
        var titleNode = document.createTextNode('\u00a0' + rule.rule_id + ' — ' + rule.title);
        h3.appendChild(badge);
        h3.appendChild(titleNode);
        card.appendChild(h3);
        var desc = document.createElement('p');
        desc.textContent = rule.description;
        card.appendChild(desc);
        var rem = document.createElement('div');
        rem.className = 'remediation';
        rem.textContent = rule.remediation;
        card.appendChild(rem);
        grid.appendChild(card);
      });
      content.appendChild(grid);
    })
    .catch(function(e){
      content.textContent = 'Failed to load rules: ' + e.message;
    });
}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Web server
# ---------------------------------------------------------------------------

_MAX_BODY = 65536
_MAX_TARGETS = 20

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    ),
    "Cache-Control": "no-store",
}


def _is_loopback(host: str) -> bool:
    try:
        addr = socket.getaddrinfo(host, None)[0][4][0]
        return addr in ("127.0.0.1", "::1") or addr.startswith("127.")
    except Exception:
        return False


class _AuditorHandler(BaseHTTPRequestHandler):
    server_host: str = "127.0.0.1"
    server_port: int = 8000

    def log_message(self, fmt: str, *args: Any) -> None:  # type: ignore[override]
        pass  # silence access log

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(encoded)

    def _reject(self, msg: str, status: int = 403) -> None:
        self._send_json({"error": msg}, status)

    def _validate_host(self) -> bool:
        host_hdr = self.headers.get("Host", "").split(":")[0].strip()
        allowed = {"localhost", "127.0.0.1", self.server_host}
        if host_hdr not in allowed:
            self._reject(f"Invalid Host header: {host_hdr}")
            return False
        return True

    def _validate_origin(self) -> bool:
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        parsed = urllib.parse.urlparse(origin)
        host = parsed.hostname or ""
        allowed = {"localhost", "127.0.0.1", self.server_host}
        if host not in allowed:
            self._reject(f"Origin not allowed: {origin}")
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._validate_host():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self._send_html(_HTML_PAGE)
        elif path == "/api/health":
            self._send_json({"status": "ok", "version": __version__})
        elif path == "/api/rules":
            rules_list = [
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "severity": r.severity,
                    "description": r.description,
                    "remediation": r.remediation,
                    "references": r.references,
                }
                for r in RULES.values()
            ]
            self._send_json(rules_list)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._validate_host():
            return
        if not self._validate_origin():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path != "/api/scan":
            self._send_json({"error": "Not found"}, 404)
            return

        ct = self.headers.get("Content-Type", "")
        if "application/json" not in ct:
            self._reject("Content-Type must be application/json", 415)
            return

        length = int(self.headers.get("Content-Length", 0))
        if length > _MAX_BODY:
            self._reject("Request body too large", 413)
            return

        try:
            raw = self.rfile.read(min(length, _MAX_BODY))
            payload = json.loads(raw)
        except Exception:
            self._reject("Invalid JSON", 400)
            return

        if not payload.get("authorized"):
            self._reject("authorized must be true", 400)
            return

        targets = payload.get("targets", [])
        if not isinstance(targets, list) or not targets:
            self._reject("targets must be a non-empty array", 400)
            return
        if len(targets) > _MAX_TARGETS:
            self._reject(f"Maximum {_MAX_TARGETS} targets per request", 400)
            return

        insecure = bool(payload.get("insecure", False))
        check_body = bool(payload.get("check_body", False))

        results: list[TargetResult] = []
        errors: list[str] = []
        lock = threading.Lock()

        def worker(url: str) -> None:
            try:
                r = scan_target(url, insecure=insecure, check_body=check_body)
            except Exception as exc:
                r = TargetResult(url=url, final_url=url, status_code=0,
                                 score=0, grade="F", error=str(exc))
            with lock:
                results.append(r)

        threads = [threading.Thread(target=worker, args=(str(t),), daemon=True) for t in targets]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        # Preserve original order
        order = {str(t): i for i, t in enumerate(targets)}
        results.sort(key=lambda r: order.get(r.url, 999))

        self._send_json(results_to_dict(results))


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def run_web(host: str, port: int, open_browser: bool) -> None:
    """Start the web server."""
    if not _is_loopback(host):
        print(
            f"\n{'!'*70}\n"
            f"  WARNING: Binding to non-loopback address {host}.\n"
            f"  The scanner will make real outbound HTTP requests on behalf of anyone\n"
            f"  who can reach this port. Only do this on a trusted private network.\n"
            f"{'!'*70}\n",
            file=sys.stderr,
        )

    _AuditorHandler.server_host = host
    _AuditorHandler.server_port = port

    server = _ThreadingHTTPServer((host, port), _AuditorHandler)
    url = f"http://{host}:{port}"
    print(f"Passive Header & CORS Auditor running at {url}")
    print("Press Ctrl-C to stop.")

    if open_browser:
        threading.Thread(
            target=lambda: (time.sleep(0.5), webbrowser.open(url)),
            daemon=True,
        ).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down…")
        server.shutdown()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passive-auditor",
        description="Passive HTTP Security Header & CORS Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python main.py https://example.com
              python main.py --insecure https://example.com https://another.org
              python main.py --json https://example.com
              python main.py --web
              python main.py --web --port 9000 --no-browser
        """),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--rules", action="store_true", help="List all rules and exit.")

    # Scan targets
    parser.add_argument("targets", nargs="*", metavar="URL", help="Target URLs to scan.")
    parser.add_argument("--insecure", "-k", action="store_true",
                        help="Skip TLS certificate verification.")
    parser.add_argument("--check-body", action="store_true",
                        help="Also read response body for analysis.")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Output results as JSON.")
    parser.add_argument("--no-colour", "--no-color", action="store_true",
                        help="Disable ANSI colour output.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show finding details in CLI output.")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit with non-zero code if any findings exist.")

    # Web mode
    parser.add_argument("--web", action="store_true", help="Start the web UI.")
    parser.add_argument("--port", type=int, default=8000, help="Web server port (default: 8000).")
    parser.add_argument("--host", default="127.0.0.1", help="Web server host (default: 127.0.0.1).")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open the browser automatically.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # --rules
    if args.rules:
        for r in RULES.values():
            print(f"[{r.severity:<8}] {r.rule_id}  {r.title}")
        sys.exit(0)

    # --web
    if args.web:
        run_web(args.host, args.port, not args.no_browser)
        sys.exit(0)

    # CLI scan
    if not args.targets:
        parser.print_help()
        sys.exit(1)

    results: list[TargetResult] = []
    for url in args.targets:
        print(f"Scanning {url} …", file=sys.stderr)
        r = scan_target(url, insecure=args.insecure, check_body=args.check_body)
        results.append(r)

    if args.json_output:
        print(json.dumps(results_to_dict(results), indent=2, ensure_ascii=False))
    else:
        colour = not args.no_colour and sys.stdout.isatty()
        print_results_cli(results, colour=colour, verbose=args.verbose)

    if args.exit_code:
        has_findings = any(r.findings for r in results)
        sys.exit(1 if has_findings else 0)


if __name__ == "__main__":
    main()

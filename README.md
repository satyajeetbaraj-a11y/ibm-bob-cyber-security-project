# Passive Header & CORS Auditor

A passive HTTP security scanner that checks response headers, cookie attributes, and CORS configuration. Runs as a CLI tool or a local web application. Single file, Python standard library only — no dependencies to install.

---

## Requirements

- Python 3.10+
- No third-party packages required

---

## Quick Start

### Web UI (recommended)

```bash
python main.py --web
```

Opens `http://127.0.0.1:8000` in your browser automatically.

### CLI

```bash
python main.py https://example.com
```

---

## Usage

### Web mode

| Command | Description |
|---|---|
| `python main.py --web` | Start server, open browser |
| `python main.py --web --port 9000` | Use a custom port |
| `python main.py --web --no-browser` | Start server without opening browser |
| `python main.py --web --host 0.0.0.0` | Bind to all interfaces (⚠️ trusted networks only) |

Stop the server with **Ctrl-C**.

### CLI mode

```bash
# Scan one or more targets
python main.py https://example.com https://another.org

# Skip TLS certificate verification
python main.py --insecure https://example.com

# Output results as JSON
python main.py --json https://example.com

# Show finding details (verbose)
python main.py --verbose https://example.com

# Exit with code 1 if any findings exist (useful in CI)
python main.py --exit-code https://example.com

# List all rules
python main.py --rules

# Show version
python main.py --version
```

### All flags

| Flag | Default | Description |
|---|---|---|
| `--web` | — | Start the web UI |
| `--port` | `8000` | Web server port |
| `--host` | `127.0.0.1` | Web server host |
| `--no-browser` | — | Don't auto-open browser |
| `--insecure` / `-k` | — | Skip TLS verification |
| `--check-body` | — | Also read response body |
| `--json` | — | Output as JSON |
| `--verbose` / `-v` | — | Show detail per finding |
| `--no-colour` | — | Disable ANSI colours |
| `--exit-code` | — | Non-zero exit if findings exist |
| `--rules` | — | List all rules and exit |
| `--version` | — | Show version and exit |

---

## Web API

The web server exposes four routes:

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | The web UI |
| `GET` | `/api/health` | Health check — `{"status":"ok","version":"..."}` |
| `GET` | `/api/rules` | Full rule registry as JSON |
| `POST` | `/api/scan` | Run a scan |

### POST /api/scan

**Request body:**

```json
{
  "targets": ["https://example.com"],
  "insecure": false,
  "check_body": false,
  "authorized": true
}
```

- `authorized` must be `true` — returns `400` otherwise.
- Maximum 20 targets per request.

**Response:** array of result objects, one per target.

---

## Rules

19 rules across three categories:

### Headers (H)

| ID | Severity | Rule |
|---|---|---|
| H001 | HIGH | Missing Strict-Transport-Security |
| H002 | MEDIUM | Missing X-Content-Type-Options |
| H003 | MEDIUM | Missing X-Frame-Options |
| H004 | HIGH | Missing Content-Security-Policy |
| H005 | LOW | Missing Referrer-Policy |
| H006 | LOW | Missing Permissions-Policy |
| H007 | LOW | Server header exposes version |
| H008 | LOW | X-Powered-By header present |
| H009 | MEDIUM | HSTS max-age too short |
| H010 | HIGH | CSP allows unsafe-inline scripts |
| H011 | HIGH | CSP allows unsafe-eval |

### Cookies (C)

| ID | Severity | Rule |
|---|---|---|
| C001 | HIGH | Cookie missing Secure flag |
| C002 | MEDIUM | Cookie missing HttpOnly flag |
| C003 | MEDIUM | Cookie SameSite not set or Lax/None |

### CORS (R)

| ID | Severity | Rule |
|---|---|---|
| R001 | HIGH | Wildcard Access-Control-Allow-Origin |
| R002 | CRITICAL | Server reflects arbitrary Origin |
| R003 | CRITICAL | Credentials with wildcard or reflected origin |
| R004 | HIGH | Null origin accepted |
| R005 | MEDIUM | Overly permissive allowed methods |

### Scoring

Each finding deducts points from a starting score of 100:

| Severity | Deduction |
|---|---|
| CRITICAL | −30 |
| HIGH | −15 |
| MEDIUM | −8 |
| LOW | −3 |
| INFO | 0 |

Grades: **A** (90–100) · **B** (75–89) · **C** (60–74) · **D** (40–59) · **F** (0–39)

---

## Security Notes

- Binds to `127.0.0.1` by default — accessible only from your machine.
- A warning is printed if you bind to a non-loopback address.
- The scanner is **passive**: it issues GET and OPTIONS requests only, with no attack payloads.
- Cookie values are always redacted in output.
- The web UI enforces an authorization checkbox before any scan can be submitted.

---

## Legal

Only scan systems you own or have explicit written authorisation to test. Unauthorised scanning may violate laws and terms of service.

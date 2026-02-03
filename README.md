# 🐭 Sorcino

> Stringimi forte che nessuna notte è infinita.  (cit. Renato Zero :PpPpp)

Scanner to identify misconfigured [OpenClaw](https://github.com/openclaw/openclaw) instances and other LLM proxies exposed on the Internet.

## Features

- Scans IP ranges, CIDR blocks, and ASNs for exposed LLM proxies
- Identifies service type (OpenClaw, LiteLLM, Ollama, MCP Server)
- Detects security misconfigurations:
  - Auth bypass (unauthenticated WebSocket/HTTP endpoints)
  - API key exposure (Anthropic/OpenAI keys leaked in responses)
  - Information disclosure (debug mode, exposed configs, stack traces)
  - mDNS information leak
- SPA false-positive filtering (ignores HTML catch-all responses on sensitive file paths)
- Evidence collection (`--dump-evidence`) to save raw files and WebSocket responses
- Reverse DNS (PTR) lookup for scanned targets (configurable via `--rdns/--no-rdns`)
- Scan modes: `fast`, `thorough`, `stealth` with preset timeout/concurrency/delay
- Generates reports in JSON, Markdown, and plain text
- Auto-generated report filenames with timestamps
- Quiet mode (`--quiet`) for script-friendly output
- Verbose mode (`--verbose`) for detailed probe debugging
- Severity filtering (`--min-severity`) to show only relevant findings

## Installation

```bash
git clone https://github.com/renat0z3r0/sorcino.git
cd sorcino
pip install -e .
```

## Usage

```bash
# Single IP scan
sorcino scan 192.168.1.100

# CIDR scan
sorcino scan 192.168.1.0/24

# IP range scan
sorcino scan 192.168.1.1-254
sorcino scan 10.0.0.1-10.0.0.254

# Scan from file
sorcino scan @targets.txt

# ASN scan
sorcino asn AS12345
sorcino asn AS12345 --list-only

# Shodan import
sorcino shodan-import "port:18789" --api-key $SHODAN_KEY
sorcino shodan-import "port:18789 country:IT" --scan

# mDNS discovery (local network)
sorcino mdns-scan

# Common options
sorcino scan 10.0.0.0/16 --ports 18789,8080 --mode fast --concurrency 50
sorcino scan targets.txt --format markdown --output report.md

# Quiet mode (only CRITICAL/HIGH findings, no progress bar)
sorcino scan 192.168.1.0/24 --quiet

# Verbose mode (detailed probe output)
sorcino scan 192.168.1.100 --verbose

# Filter by minimum severity
sorcino scan 192.168.1.0/24 --min-severity high
```

## Scan Modes

Three scan modes with different speed/stealth tradeoffs:

| Mode | Timeout | Concurrency | Delay | rDNS |
|------|---------|-------------|-------|------|
| `fast` | 3s | 50 | 0ms | off |
| `thorough` | 10s | 20 | 0ms | on |
| `stealth` | 15s | 5 | 500ms | on |

```bash
# Fast mode - quick scan, no rDNS
sorcino scan 10.0.0.0/16 --mode fast

# Thorough mode (default) - balanced
sorcino scan 192.168.1.0/24 --mode thorough

# Stealth mode - slow, with delay between batches
sorcino scan 192.168.1.0/24 --mode stealth

# Override mode defaults with explicit options
sorcino scan 10.0.0.0/16 --mode fast --timeout 5 --concurrency 100

# Control rDNS independently
sorcino scan 192.168.1.0/24 --mode fast --rdns      # fast + rDNS
sorcino scan 192.168.1.0/24 --mode thorough --no-rdns  # thorough without rDNS
```

## Output

Report filenames are auto-generated with timestamps when `-o` is omitted:

```
sorcino_scan_20260203_143052.json
sorcino_scan_20260203_143052.txt
sorcino_scan_20260203_143052.md
```

```bash
# JSON (default, auto-named)
sorcino scan 192.168.1.0/24

# JSON with custom name
sorcino scan 192.168.1.0/24 -o results.json

# Markdown
sorcino scan 192.168.1.0/24 -f markdown -o report.md

# Plain text
sorcino scan 192.168.1.0/24 -f txt
```

## Evidence Collection

Use `--dump-evidence` to save raw evidence for forensic review:

```bash
sorcino scan 192.168.1.100 --dump-evidence
```

Creates a structured directory per target:

```
evidence/
└── 20260203_143052_192.168.1.100/
    ├── .env                       # Exposed sensitive files (real content only)
    ├── config.json
    ├── websocket_responses.txt    # Raw WS request/response pairs
    └── manifest.json              # Index of all collected evidence
```

Only real files are saved - SPA catch-all responses (HTML pages served on any path) are filtered out.

## Detected Services

| Service | Default Port | Notes |
|---------|-------------|-------|
| OpenClaw | 18789 | Gateway WS+HTTP |
| OpenClaw CDP | 18791 | Browser control |
| OpenClaw Canvas | 18793 | File server |
| LiteLLM | 4000 | Multi-provider proxy |
| Ollama | 11434 | Local LLM |
| MCP Server | various | Model Context Protocol |

## Vulnerability Checks

- **Auth bypass**: WebSocket and HTTP endpoints accessible without tokens
- **API key exposure**: `sk-ant-*`, `sk-*` patterns in responses
- **Info disclosure**: Debug mode, version leaks, exposed configs (with SPA false-positive filtering)
- **mDNS leak**: `cliPath` exposes username, `sshPort` exposes SSH
- **DM policy**: Open policy without allowlist

## Requirements

- Python 3.9+
- Dependencies: aiohttp, typer, rich, websockets, pyyaml, zeroconf, shodan

## Disclaimer or discLAMERZ :)

```
This tool is intended exclusively for:
- Authorized (EHHHH!!) penetration testing
- Assessment of owned infrastructure or with written (of course, plz :P) authorization
- Responsible (ehm :P) security research
- BLA BLA BLA

Unauthorized use to scan systems without permission is illegal.
Renato Zero is not responsible for misuse of this tool, okkkkk?!? D'ACCCOOOORDDOOOO? (cit. Wanna Marchi)
```

## License

MIT License - Copyright (c) 2026 Renato Zero

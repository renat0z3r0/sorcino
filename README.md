# 🐭 Sorcino

> Stringimi forte che nessuna notte è infinita.  (cit. Renato Zero :PpPpp)

Scanner to identify misconfigured [OpenClaw](https://github.com/openclaw/openclaw) instances and other LLM proxies exposed on the Internet.

## Features

- Scans IP ranges, CIDR blocks, and ASNs for exposed LLM proxies
- Identifies 17 LLM server/agent types (OpenClaw, Hermes Agent, vLLM, Ollama,
  Open WebUI, LiteLLM, TGI, llama.cpp, LocalAI, MCP, and more — see below)
- Concurrent worker-pool scanning (no head-of-line blocking) with parallel
  per-host checks
- Detects security misconfigurations:
  - Auth bypass (unauthenticated WebSocket/HTTP endpoints, fail-closed aware)
  - API key exposure (Anthropic/OpenAI keys leaked in responses)
  - Information disclosure (debug mode, exposed configs, stack traces)
  - mDNS information leak
- Checks run over the scheme that answered, so TLS-fronted (`https`/`wss`) proxies are covered
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

# Also scan less-common LLM-server ports (LM Studio, Jan, Xinference, ...)
sorcino scan 192.168.1.0/24 --llm-ports

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
    ├── 192.168.1.100_8080_.env         # Exposed sensitive files (prefixed host_port)
    ├── 192.168.1.100_8080_config.json
    ├── websocket_responses.txt         # Raw WS request/response pairs
    └── manifest.json                   # Index of all collected evidence
```

Only real files are saved - SPA catch-all responses (HTML pages served on any path) are filtered out.

## Detected Services

| Service | Default Port | Notes |
|---------|-------------|-------|
| OpenClaw | 18789 | Gateway WS+HTTP (CDP 18791, Canvas via mDNS `canvasPort`) |
| Hermes Agent | 8642 / 9119 | NousResearch agent — unauth dashboard can leak `.env` |
| vLLM | 8000 | Fingerprinted via `vllm:` `/metrics` |
| Ollama | 11434 | Local LLM (`/api/tags`) |
| Open WebUI | 8080 / 3000 | Ollama/OpenAI front-end (`/api/config` often exposed) |
| LiteLLM | 4000 | Multi-provider proxy |
| MCP Server | various | Model Context Protocol |
| TGI / LocalAI / llama.cpp / Tabby | 3000 / 8080 | Inference & code-completion servers |
| Triton / LangServe | 8000 | NVIDIA Triton / LangChain deploy |
| Dify | 80 / 443 | LLM app platform |
| Flowise | 3000 | Agent builder (frequently exposed) |
| LM Studio / Jan / GPT4All / oobabooga / Xinference / AnythingLLM | 1234 / 1337 / 4891 / 5000 / 9997 / 3001 | Desktop & self-hosted servers (use `--llm-ports`) |

Use `--llm-ports` to also scan the less-common LLM-server ports above
(`1234,1337,3001,4891,5000,8002,9000,9997`); the default scan stays lean.

> Signatures live in `fingerprint/signatures/*.yaml`; each declares its own
> probe paths, fetched only on the port(s) it targets, so adding a service is a
> YAML drop-in (no code change) and the per-port probe set stays small.

## Vulnerability Checks

- **Auth bypass** (fail-closed aware): modern OpenClaw refuses unauthenticated
  WebSocket connections by default. Sorcino distinguishes a gateway that is
  *exposed but enforcing auth* (close code `1008` → **LOW**) from one that
  actually answers RPC without a token (→ **CRITICAL**). Probes both `ws://`
  and `wss://`. HTTP endpoints (`/tools/invoke`, `/api/v1/admin/rpc`, `/v1/*`,
  `/api/channels`) returning `operator.*` scopes without a bearer → **CRITICAL**.
- **Trusted-proxy spoofing**: optional, data-driven check for identity-header
  spoofing in `trusted-proxy` auth mode (disabled unless header names are
  configured in `config/openclaw_surface.yaml`).
- **API key exposure**: `sk-ant-*`, `sk-*` patterns in responses
- **Info disclosure**: Debug mode, version leaks, exposed configs (with SPA false-positive filtering)
- **mDNS leak**: `cliPath` (username) / `sshPort` only leak in `full` discovery
  mode; remediate via `discovery.mdns.mode: minimal|off`. Also surfaces
  `gatewayTls` (TLS gateway → `wss://`) and the dynamic `canvasPort`.

> **Note on alignment.** Everything Sorcino knows about OpenClaw's surface
> (endpoints, auth modes/keys, mDNS TXT keys, ports) lives in the versioned
> `config/openclaw_surface.yaml`. Tracking a new OpenClaw release means editing
> that file, not the Python.

## Requirements

- Python 3.9+
- Dependencies: aiohttp, aiodns, typer, rich, websockets, pyyaml, zeroconf
- Dev/test: `pip install -e .[dev]` then `pytest`

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

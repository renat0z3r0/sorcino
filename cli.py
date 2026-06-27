#!/usr/bin/env python3
"""
Sorcino - LLM Proxy Misconfiguration Scanner

Copyright (c) 2026 Renato Zero
Licensed under the MIT License
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from discovery.port_scanner import scan_host, DEFAULT_PORTS, LLM_EXTRA_PORTS
from discovery.service_probe import probe_http, DEFAULT_PATHS
from discovery.rdns import reverse_dns_bulk
from fingerprint.matcher import SignatureMatcher
from checks.models import Severity, VulnFinding, SEVERITY_ORDER
from checks.auth_bypass import check_auth_bypass
from checks.info_disclosure import check_info_disclosure
from checks.api_key_exposure import check_api_key_exposure
from checks.websocket_check import check_websocket_auth
from checks.hermes import check_hermes
from checks.mdns_discovery import check_mdns_discovery
from checks.evidence import EvidenceCollector
from output.json_report import generate_json_report
from output.markdown_report import generate_markdown_report
from output.txt_report import generate_txt_report
from utils.asn_resolver import resolve_asn_prefixes, get_asn_info
from utils.shodan_client import fetch_shodan_targets

FORMAT_EXTENSIONS = {"json": ".json", "markdown": ".md", "txt": ".txt"}

# Mode presets: CLI options override these when explicitly specified
MODE_PRESETS = {
    "fast": {"timeout": 3.0, "concurrency": 50, "delay_ms": 0},
    "thorough": {"timeout": 10.0, "concurrency": 20, "delay_ms": 0},
    "stealth": {"timeout": 15.0, "concurrency": 5, "delay_ms": 500},
}

_SEVERITY_NAMES = {s.value: s for s in Severity}


def _auto_output_name(fmt: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    ext = FORMAT_EXTENSIONS.get(fmt, ".json")
    return f"sorcino_scan_{ts}{ext}"


def _parse_severity(value: str) -> Severity:
    s = _SEVERITY_NAMES.get(value.lower())
    if s is None:
        raise typer.BadParameter(f"Invalid severity: {value}. Use: info, low, medium, high, critical")
    return s


def _filter_findings(findings: list[VulnFinding], min_severity: Severity) -> list[VulnFinding]:
    threshold = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold]


app = typer.Typer(
    name="sorcino",
    help="Sorcino - LLM Proxy Misconfiguration Scanner",
    no_args_is_help=True,
)
console = Console()


def parse_targets(target: str) -> list[str]:
    targets: list[str] = []

    target = target.strip()
    if not target:
        return targets

    if target.startswith("@") or (not target[0].isdigit() and Path(target).exists()):
        file_path = target[1:] if target.startswith("@") else target
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.extend(parse_targets(line))
        return targets

    if "-" in target and not target.startswith("-"):
        range_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", target)
        if range_match:
            start_ip = ipaddress.IPv4Address(range_match.group(1))
            end_ip = ipaddress.IPv4Address(range_match.group(2))
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                targets.append(str(ipaddress.IPv4Address(ip_int)))
            return targets

        compact_match = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$", target)
        if compact_match:
            prefix = compact_match.group(1)
            start = int(compact_match.group(2))
            end = int(compact_match.group(3))
            for i in range(start, end + 1):
                targets.append(f"{prefix}.{i}")
            return targets

    if "/" in target:
        try:
            network = ipaddress.IPv4Network(target, strict=False)
            for ip in network.hosts():
                targets.append(str(ip))
            return targets
        except ValueError:
            pass

    # shodan-import writes "ip:port" lines (README two-step flow); strip the
    # port so the IP actually scans instead of being passed verbatim to
    # open_connection (which fails silently -> "0 open ports"). The port suffix
    # is dropped, so the scan falls back to DEFAULT_PORTS (covers the common LLM
    # ports); thread per-target ports only if Shodan ports stray outside that set.
    ip_port = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$", target)
    if ip_port:
        targets.append(ip_port.group(1))
        return targets

    targets.append(target)
    return targets


def parse_ports(ports_str: str) -> list[int]:
    ports: list[int] = []
    invalid: list[str] = []
    for tok in ports_str.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok.isdigit() and 1 <= int(tok) <= 65535:
            ports.append(int(tok))
        else:
            invalid.append(tok)
    if invalid:
        raise typer.BadParameter(f"Invalid port(s): {', '.join(invalid)} (must be 1-65535)")
    return ports


# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------

async def run_scan(
    targets: list[str],
    ports: list[int] | None,
    output: str,
    fmt: str,
    timeout: float,
    concurrency: int,
    run_mdns: bool,
    dump_evidence: bool = False,
    quiet: bool = False,
    verbose: bool = False,
    min_severity: Severity = Severity.INFO,
    rdns: bool = True,
    delay_ms: int = 0,
) -> None:
    if ports is None:
        ports = DEFAULT_PORTS

    matcher = SignatureMatcher()
    all_findings: list[VulnFinding] = []
    all_services: list[dict] = []
    all_open_ports: list[dict] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_single_target(ip: str) -> tuple[list[dict], list[VulnFinding], list[dict]]:
        services: list[dict] = []
        findings: list[VulnFinding] = []
        host_ports: list[dict] = []
        ev: EvidenceCollector | None = None
        if dump_evidence:
            ev = EvidenceCollector("evidence", ip)

        async with semaphore:
            open_ports = await scan_host(ip, ports, concurrency=10, timeout=timeout)

            for p in open_ports:
                host_ports.append({"host": ip, "port": p.port, "banner": p.banner, "latency_ms": p.latency_ms})

            if verbose and not open_ports:
                console.print(f"  [dim]{ip} - no open ports[/dim]")

            if not open_ports:
                return services, findings, host_ports

            if verbose:
                port_list = ", ".join(str(p.port) for p in open_ports)
                console.print(f"  [dim]{ip} - open: {port_list}[/dim]")

            # Each host gets its own session, so the GLOBAL socket ceiling is
            # (worker pool = concurrency) x this limit. Scale it down with
            # concurrency to stay well under the OS fd limit (macOS default 256).
            conn_limit = max(4, 150 // max(1, concurrency))
            connector = aiohttp.TCPConnector(ssl=False, limit=conn_limit)
            client_timeout = aiohttp.ClientTimeout(total=timeout)

            async with aiohttp.ClientSession(
                timeout=client_timeout, connector=connector
            ) as session:

                async def scan_one_port(port_result) -> tuple[list[dict], list[VulnFinding]]:
                    port = port_result.port
                    psvc: list[dict] = []
                    pfind: list[VulnFinding] = []
                    # DEFAULT_PATHS plus the signature paths relevant to this
                    # port (so new signatures fire without probing every path
                    # on every port).
                    paths = list(dict.fromkeys(DEFAULT_PATHS + matcher.extra_paths_for_port(port)))
                    probe_results = await probe_http(ip, port, paths=paths, timeout=timeout, session=session)

                    if verbose:
                        for probe in probe_results:
                            console.print(
                                f"    [dim]PROBE {probe.url} -> {probe.status_code} "
                                f"({probe.response_time_ms:.0f}ms) "
                                f"ct={probe.content_type or '-'} "
                                f"body={probe.body_preview[:60]!r}[/dim]"
                            )

                    for probe in probe_results:
                        url_path = urllib.parse.urlsplit(probe.url).path or "/"
                        for m in matcher.match(port=port, headers=probe.headers,
                                               body=probe.body_preview, url_path=url_path):
                            psvc.append({
                                "host": ip, "port": port, "name": m.service_name,
                                "confidence": m.confidence, "signals": list(m.matched_signals),
                            })

                    # Check over the scheme that actually answered, so TLS-fronted
                    # proxies get auth/key/info-checked, not just fingerprinted.
                    scheme = urllib.parse.urlsplit(probe_results[0].url).scheme if probe_results else "http"
                    base_url = f"{scheme or 'http'}://{ip}:{port}"

                    # The three checks are independent -> run them concurrently.
                    results = await asyncio.gather(
                        check_auth_bypass(base_url, session, evidence=ev),
                        check_info_disclosure(base_url, session, probe_results, evidence=ev),
                        check_api_key_exposure(base_url, session),
                        return_exceptions=True,
                    )
                    for name, r in zip(("auth_bypass", "info_disclosure", "api_key_exposure"), results):
                        if isinstance(r, list):
                            pfind.extend(r)
                        elif verbose:
                            console.print(f"  [yellow]{name} failed on {base_url}: {r!r}[/yellow]")

                    pfind.extend(check_hermes(probe_results))
                    return psvc, pfind

                # Ports are independent -> scan them concurrently.
                port_outputs = await asyncio.gather(
                    *[scan_one_port(pr) for pr in open_ports], return_exceptions=True
                )
                for out in port_outputs:
                    if isinstance(out, tuple):
                        psvc, pfind = out
                        services.extend(psvc)
                        findings.extend(pfind)
                    elif verbose and isinstance(out, Exception):
                        console.print(f"  [yellow]port scan failed on {ip}: {out!r}[/yellow]")

                try:
                    open_port_numbers = [p.port for p in open_ports]
                    ws_findings = await check_websocket_auth(f"http://{ip}", ports=open_port_numbers, evidence=ev)
                    findings.extend(ws_findings)
                except Exception as e:
                    if verbose:
                        console.print(f"  [yellow]websocket check failed on {ip}: {e!r}[/yellow]")

        if ev is not None:
            ev.write_manifest()

        return services, findings, host_ports

    # --- run: worker pool instead of fixed-size batches, so a slow host no
    # longer stalls a whole batch — a freed slot is reused immediately. ---
    delay_sec = delay_ms / 1000.0 if delay_ms > 0 else 0

    def collect(result: tuple) -> None:
        services, findings, host_ports = result
        all_services.extend(services)
        all_findings.extend(findings)
        all_open_ports.extend(host_ports)

    async def drain(advance=None) -> None:
        queue: asyncio.Queue[str] = asyncio.Queue()
        for t in targets:
            queue.put_nowait(t)

        async def worker() -> None:
            while True:
                try:
                    ip = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    collect(await scan_single_target(ip))
                except Exception as e:
                    if verbose:
                        console.print(f"[yellow]host {ip} failed: {e!r}[/yellow]")
                if advance:
                    advance()
                if delay_sec:
                    await asyncio.sleep(delay_sec)  # stealth pacing, per worker

        # The worker count is the concurrency gate; scan_single_target's own
        # semaphore is now redundant but harmless, so left in place.
        n = min(concurrency, len(targets)) or 1
        await asyncio.gather(*[worker() for _ in range(n)])

    if quiet:
        await drain()
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning targets...", total=len(targets))
            await drain(advance=lambda: progress.update(task, advance=1))

    if run_mdns:
        if not quiet:
            console.print("[bold]Running mDNS discovery...[/bold]")
        try:
            mdns_findings = await check_mdns_discovery(timeout=5.0)
            all_findings.extend(mdns_findings)
        except Exception as e:
            if not quiet:
                console.print(f"[yellow]mDNS scan failed: {e}[/yellow]")

    # --- reverse DNS ---
    unique_ips = list({p["host"] for p in all_open_ports})
    rdns_map: dict[str, str | None] = {}
    if rdns and unique_ips:
        if not quiet:
            console.print(f"Resolving rDNS for {len(unique_ips)} host(s)...")
        rdns_map = await reverse_dns_bulk(unique_ips, concurrency=concurrency)

    for p in all_open_ports:
        p["hostname"] = rdns_map.get(p["host"])

    # --- dedup services ---
    seen_services: set[tuple] = set()
    unique_services = []
    for s in all_services:
        s["hostname"] = rdns_map.get(s["host"])
        key = (s["host"], s["port"], s["name"])
        if key not in seen_services:
            seen_services.add(key)
            unique_services.append(s)

    # --- severity filter ---
    filtered_findings = _filter_findings(all_findings, min_severity)

    # --- results ---
    scan_results = {
        "targets_scanned": len(targets),
        "open_ports": all_open_ports,
        "services_found": len(unique_services),
        "services": unique_services,
    }

    if quiet:
        _print_quiet(filtered_findings)
    else:
        _print_results(all_open_ports, unique_services, filtered_findings, verbose)

    # Reports always use filtered findings
    if fmt == "markdown":
        generate_markdown_report(scan_results, filtered_findings, output)
    elif fmt == "txt":
        generate_txt_report(scan_results, filtered_findings, output)
    else:
        generate_json_report(scan_results, filtered_findings, output)

    if not quiet:
        console.print(f"\n[bold green]Report saved to {output}[/bold green]")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_quiet(findings: list[VulnFinding]) -> None:
    """Minimal output: one line per finding, CRITICAL and HIGH only."""
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
        if SEVERITY_ORDER.get(f.severity, 0) < SEVERITY_ORDER[Severity.HIGH]:
            continue
        print(f"{f.severity.value.upper()} | {f.title}")


def _print_results(
    open_ports: list[dict],
    services: list[dict],
    findings: list[VulnFinding],
    verbose: bool = False,
) -> None:
    if open_ports:
        table = Table(title="Open Ports")
        table.add_column("Host")
        table.add_column("Hostname")
        table.add_column("Port")
        table.add_column("Banner")
        table.add_column("Latency")

        for p in open_ports:
            banner = (p["banner"] or "")[:60]
            latency = f"{p['latency_ms']:.0f}ms" if p["latency_ms"] else "-"
            hostname = p.get("hostname") or ""
            table.add_row(p["host"], hostname, str(p["port"]), banner, latency)

        console.print(table)

    if services:
        table = Table(title="Identified Services")
        table.add_column("Host")
        table.add_column("Hostname")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Confidence")

        for s in services:
            hostname = s.get("hostname") or ""
            table.add_row(s["host"], hostname, str(s["port"]), s["name"], f"{s['confidence']}%")

        console.print(table)

    if findings:
        table = Table(title="Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Check")
        if verbose:
            table.add_column("Evidence")

        severity_colors = {
            "critical": "red",
            "high": "bright_red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )

        for f in sorted_findings:
            color = severity_colors.get(f.severity.value, "white")
            row = [
                f"[{color}]{f.severity.value.upper()}[/{color}]",
                f.title,
                f.check_name,
            ]
            if verbose:
                row.append(f.evidence[:120])
            table.add_row(*row)

        console.print(table)

    console.print(f"\nTotal: {len(open_ports)} open port(s), {len(services)} service(s), {len(findings)} finding(s)")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target: IP, CIDR, range, domain, or @file"),
    ports: str = typer.Option(None, "--ports", "-p", help="Custom ports (comma-separated)"),
    llm_ports: bool = typer.Option(False, "--llm-ports", help="Also scan less-common LLM-server ports (LM Studio, Jan, Xinference, ...)"),
    mode: str = typer.Option("thorough", "--mode", "-m", help="Scan mode: fast, thorough, stealth"),
    output: str = typer.Option(None, "--output", "-o", help="Output file (auto-generated if omitted)"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json, markdown, txt"),
    timeout: float = typer.Option(None, "--timeout", "-t", help="Request timeout in seconds (default: from mode)"),
    concurrency: int = typer.Option(None, "--concurrency", "-c", help="Max concurrent connections (default: from mode)"),
    mdns: bool = typer.Option(False, "--mdns", help="Enable mDNS discovery"),
    dump_evidence: bool = typer.Option(False, "--dump-evidence", help="Save raw evidence files"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output (CRITICAL/HIGH only)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug details"),
    min_severity: str = typer.Option("info", "--min-severity", help="Minimum severity: info, low, medium, high, critical"),
    rdns: bool = typer.Option(None, "--rdns/--no-rdns", help="Enable/disable reverse DNS lookup (default: off in fast mode, on otherwise)"),
):
    """Scan targets for misconfigured LLM proxy instances."""
    if output is None:
        output = _auto_output_name(fmt)

    # Apply mode presets, CLI options override
    preset = MODE_PRESETS.get(mode, MODE_PRESETS["thorough"])
    eff_timeout = timeout if timeout is not None else preset["timeout"]
    eff_concurrency = concurrency if concurrency is not None else preset["concurrency"]
    eff_delay_ms = preset["delay_ms"]

    sev = _parse_severity(min_severity)

    if not quiet:
        console.print("[bold blue]Sorcino[/bold blue] - LLM Proxy Scanner")
        console.print(f"Target: {target} | Mode: {mode}")
        if mode == "stealth":
            console.print(f"[dim]Stealth: {eff_delay_ms}ms delay between batches[/dim]")
        if dump_evidence:
            console.print("[bold yellow]Evidence collection enabled[/bold yellow]")
        if sev != Severity.INFO:
            console.print(f"Min severity filter: {sev.value.upper()}")

    targets = parse_targets(target)
    if not quiet:
        console.print(f"Resolved {len(targets)} target(s)")

    if len(targets) > 1000:
        if not typer.confirm(f"This will scan {len(targets)} IPs. Continue?"):
            raise typer.Exit(0)

    port_list = (parse_ports(ports) or None) if ports else None

    if llm_ports:
        base = port_list if port_list else list(DEFAULT_PORTS)
        port_list = list(dict.fromkeys(base + LLM_EXTRA_PORTS))

    # Determine rdns default based on mode if not explicitly set
    if rdns is None:
        rdns = mode != "fast"

    asyncio.run(run_scan(
        targets=targets,
        ports=port_list,
        output=output,
        fmt=fmt,
        timeout=eff_timeout,
        concurrency=eff_concurrency,
        run_mdns=mdns,
        dump_evidence=dump_evidence,
        quiet=quiet,
        verbose=verbose,
        min_severity=sev,
        rdns=rdns,
        delay_ms=eff_delay_ms,
    ))


@app.command()
def asn(
    asn_number: str = typer.Argument(..., help="ASN number (e.g., AS12345 or 12345)"),
    ports: str = typer.Option(None, "--ports", "-p", help="Custom ports (comma-separated)"),
    mode: str = typer.Option("fast", "--mode", "-m", help="Scan mode: fast, thorough, stealth"),
    output: str = typer.Option(None, "--output", "-o", help="Output file (auto-generated if omitted)"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json, markdown, txt"),
    timeout: float = typer.Option(None, "--timeout", "-t", help="Request timeout (default: from mode)"),
    concurrency: int = typer.Option(None, "--concurrency", "-c", help="Max concurrent connections (default: from mode)"),
    list_only: bool = typer.Option(False, "--list-only", "-l", help="Only list IP ranges"),
    dump_evidence: bool = typer.Option(False, "--dump-evidence", help="Save raw evidence files"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug details"),
    min_severity: str = typer.Option("info", "--min-severity", help="Minimum severity filter"),
    rdns: bool = typer.Option(None, "--rdns/--no-rdns", help="Enable/disable reverse DNS lookup"),
):
    """Scan all IP ranges belonging to an ASN."""
    if output is None:
        output = _auto_output_name(fmt)

    # Apply mode presets, CLI options override
    preset = MODE_PRESETS.get(mode, MODE_PRESETS["fast"])
    eff_timeout = timeout if timeout is not None else preset["timeout"]
    eff_concurrency = concurrency if concurrency is not None else preset["concurrency"]
    eff_delay_ms = preset["delay_ms"]

    sev = _parse_severity(min_severity)

    console.print(f"[bold blue]ASN Scan: {asn_number}[/bold blue]")

    asn_clean = asn_number.upper().replace("AS", "")

    prefixes = asyncio.run(resolve_asn_prefixes(asn_clean))

    if not prefixes:
        console.print("[red]No prefixes found for this ASN[/red]")
        raise typer.Exit(1)

    info = asyncio.run(get_asn_info(asn_clean))
    if info:
        console.print(f"Organization: {info.get('name', 'N/A')} ({info.get('country', 'N/A')})")

    console.print(f"Found {len(prefixes)} prefix(es)")
    for prefix in prefixes:
        console.print(f"  - {prefix}")

    if list_only:
        return

    targets: list[str] = []
    for prefix in prefixes:
        targets.extend(parse_targets(prefix))

    console.print(f"Total IPs to scan: {len(targets)}")

    if len(targets) > 1000:
        if not typer.confirm(f"This will scan {len(targets)} IPs. Continue?"):
            raise typer.Exit(0)

    # Determine rdns default based on mode if not explicitly set
    if rdns is None:
        rdns = mode != "fast"

    asyncio.run(run_scan(
        targets=targets,
        ports=(parse_ports(ports) or None) if ports else None,
        output=output,
        fmt=fmt,
        timeout=eff_timeout,
        concurrency=eff_concurrency,
        run_mdns=False,
        dump_evidence=dump_evidence,
        quiet=quiet,
        verbose=verbose,
        min_severity=sev,
        rdns=rdns,
        delay_ms=eff_delay_ms,
    ))


@app.command(name="shodan-import")
def shodan_import(
    query: str = typer.Argument(..., help="Shodan query"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="SHODAN_API_KEY", help="Shodan API key"),
    output: str = typer.Option("shodan_targets.txt", "--output", "-o", help="Output file"),
    scan_now: bool = typer.Option(False, "--scan", "-s", help="Immediately scan imported targets"),
    limit: int = typer.Option(1000, "--limit", "-l", help="Max results"),
):
    """Import targets from Shodan search results."""
    if not api_key:
        console.print("[red]Shodan API key required. Set SHODAN_API_KEY or use --api-key[/red]")
        raise typer.Exit(1)

    console.print("[bold blue]Shodan Import[/bold blue]")
    console.print(f"Query: {query}")

    targets = asyncio.run(fetch_shodan_targets(api_key, query, limit))

    if not targets:
        console.print("[yellow]No results found[/yellow]")
        raise typer.Exit(0)

    console.print(f"Found {len(targets)} target(s)")

    with open(output, "w") as f:
        for t in targets:
            f.write(f"{t['ip']}:{t['port']}\n")

    console.print(f"Saved to {output}")

    table = Table(title="Preview (first 10)")
    table.add_column("IP")
    table.add_column("Port")
    table.add_column("Org")
    table.add_column("Country")

    for t in targets[:10]:
        table.add_row(t["ip"], str(t["port"]), (t.get("org") or "N/A")[:30], t.get("country") or "N/A")

    console.print(table)

    if scan_now:
        scan_ips = [t["ip"] for t in targets]
        if len(scan_ips) > 1000 and not typer.confirm(f"This will scan {len(scan_ips)} IPs. Continue?"):
            raise typer.Exit(0)
        console.print("\n[bold]Starting scan...[/bold]")
        asyncio.run(run_scan(
            targets=scan_ips,
            ports=list({t["port"] for t in targets}),
            output="shodan_scan_report.json",
            fmt="json",
            timeout=10.0,
            concurrency=20,
            run_mdns=False,
            rdns=True,
            delay_ms=0,
        ))


@app.command(name="mdns-scan")
def mdns_scan_cmd(
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Discovery timeout"),
):
    """Scan local network for OpenClaw instances via mDNS."""
    console.print("[bold blue]mDNS Discovery Scan[/bold blue]")

    findings = asyncio.run(check_mdns_discovery(timeout))

    if not findings:
        console.print("[yellow]No OpenClaw instances found via mDNS[/yellow]")
        return

    for f in findings:
        color = "red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
        console.print(f"[{color}][{f.severity.value.upper()}][/{color}] {f.title}")
        console.print(f"  {f.evidence}")


if __name__ == "__main__":
    app()

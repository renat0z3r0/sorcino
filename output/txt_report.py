from __future__ import annotations

from datetime import datetime, timezone

from checks.models import VulnFinding, SEVERITY_ORDER


def _count_by_severity(findings: list[VulnFinding], level: str) -> int:
    return sum(1 for f in findings if f.severity.value == level)


def generate_txt_report(
    scan_results: dict,
    findings: list[VulnFinding],
    output_path: str,
) -> str:
    lines = []
    lines.append("SORCINO SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Targets scanned: {scan_results.get('targets_scanned', 0)}")
    lines.append(f"Services identified: {scan_results.get('services_found', 0)}")
    lines.append("")

    lines.append("SUMMARY")
    lines.append("-" * 60)
    lines.append(f"  Critical: {_count_by_severity(findings, 'critical')}")
    lines.append(f"  High:     {_count_by_severity(findings, 'high')}")
    lines.append(f"  Medium:   {_count_by_severity(findings, 'medium')}")
    lines.append(f"  Low:      {_count_by_severity(findings, 'low')}")
    lines.append(f"  Info:     {_count_by_severity(findings, 'info')}")
    lines.append("")

    open_ports = scan_results.get("open_ports", [])
    if open_ports:
        lines.append("OPEN PORTS")
        lines.append("-" * 60)
        for p in open_ports:
            hostname = p.get("hostname") or ""
            latency = f"{p['latency_ms']:.0f}ms" if p.get("latency_ms") else "-"
            banner = p.get("banner") or ""
            host_part = f"{p['host']} ({hostname})" if hostname else p["host"]
            line = f"  {host_part}:{p['port']}  latency={latency}"
            if banner:
                line += f"  banner={banner[:60]}"
            lines.append(line)
        lines.append("")

    services = scan_results.get("services", [])
    if services:
        lines.append("IDENTIFIED SERVICES")
        lines.append("-" * 60)
        for s in services:
            hostname = s.get("hostname") or ""
            host_part = f"{s['host']} ({hostname})" if hostname else s["host"]
            lines.append(f"  {host_part}:{s['port']}  {s['name']}  confidence={s['confidence']}%")
        lines.append("")

    if findings:
        lines.append("FINDINGS")
        lines.append("-" * 60)

        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )

        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"[{i}] [{f.severity.value.upper()}] {f.title}")
            lines.append(f"    Check: {f.check_name}")
            lines.append(f"    Description: {f.description}")
            lines.append(f"    Evidence: {f.evidence}")
            lines.append(f"    Remediation: {f.remediation}")
            if f.cvss_estimate:
                lines.append(f"    CVSS estimate: {f.cvss_estimate}")
            lines.append("")

    lines.append("=" * 60)
    lines.append("END OF REPORT")

    content = "\n".join(lines) + "\n"
    with open(output_path, "w") as fh:
        fh.write(content)

    return content

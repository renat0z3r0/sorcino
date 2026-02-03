from __future__ import annotations
from datetime import datetime, timezone

from checks.models import VulnFinding, SEVERITY_ORDER


def _count_by_severity(findings: list[VulnFinding], level: str) -> int:
    return sum(1 for f in findings if f.severity.value == level)


def generate_markdown_report(
    scan_results: dict,
    findings: list[VulnFinding],
    output_path: str,
) -> str:
    report = f"""# Sorcino Scan Report

**Generated**: {datetime.now(timezone.utc).isoformat()}
**Targets Scanned**: {scan_results.get('targets_scanned', 0)}
**Services Identified**: {scan_results.get('services_found', 0)}

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {_count_by_severity(findings, 'critical')} |
| High | {_count_by_severity(findings, 'high')} |
| Medium | {_count_by_severity(findings, 'medium')} |
| Low | {_count_by_severity(findings, 'low')} |
| Info | {_count_by_severity(findings, 'info')} |

## Open Ports

| Host | Hostname | Port | Latency | Banner |
|------|----------|------|---------|--------|
"""

    for p in scan_results.get("open_ports", []):
        hostname = p.get("hostname") or "-"
        latency = f"{p['latency_ms']:.0f}ms" if p.get("latency_ms") else "-"
        banner = p.get("banner") or "-"
        report += f"| {p['host']} | {hostname} | {p['port']} | {latency} | {banner} |\n"

    report += f"""
## Identified Services

| Host | Hostname | Port | Service | Confidence |
|------|----------|------|---------|------------|
"""

    for service in scan_results.get("services", []):
        hostname = service.get("hostname") or "-"
        report += f"| {service['host']} | {hostname} | {service['port']} | {service['name']} | {service['confidence']}% |\n"

    report += "\n## Findings\n\n"

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )

    for finding in sorted_findings:
        report += f"""### [{finding.severity.value.upper()}] {finding.title}

**Check**: {finding.check_name}
**Description**: {finding.description}

**Evidence**:
```
{finding.evidence}
```

**Remediation**: {finding.remediation}

---

"""

    with open(output_path, "w") as f:
        f.write(report)

    return report

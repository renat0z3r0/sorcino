from __future__ import annotations

import json
from datetime import datetime, timezone

from checks.models import VulnFinding


def generate_json_report(
    scan_results: dict,
    findings: list[VulnFinding],
    output_path: str,
) -> str:
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "targets_scanned": scan_results.get("targets_scanned", 0),
        "open_ports": [
            {
                "host": p["host"],
                "hostname": p.get("hostname"),
                "port": p["port"],
                "banner": p.get("banner"),
                "latency_ms": p.get("latency_ms"),
            }
            for p in scan_results.get("open_ports", [])
        ],
        "services_found": scan_results.get("services_found", 0),
        "services": [
            {
                "host": s["host"],
                "hostname": s.get("hostname"),
                "port": s["port"],
                "name": s["name"],
                "confidence": s["confidence"],
                "signals": s.get("signals", []),
            }
            for s in scan_results.get("services", [])
        ],
        "findings": [
            {
                "check_name": f.check_name,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "cvss_estimate": f.cvss_estimate,
            }
            for f in findings
        ],
        "summary": {
            "critical": sum(1 for f in findings if f.severity.value == "critical"),
            "high": sum(1 for f in findings if f.severity.value == "high"),
            "medium": sum(1 for f in findings if f.severity.value == "medium"),
            "low": sum(1 for f in findings if f.severity.value == "low"),
            "info": sum(1 for f in findings if f.severity.value == "info"),
        },
    }

    content = json.dumps(report, indent=2, ensure_ascii=False)
    with open(output_path, "w") as f:
        f.write(content)

    return content

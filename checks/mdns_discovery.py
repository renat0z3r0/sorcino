from __future__ import annotations
import asyncio
import socket

from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

from checks.models import Severity, VulnFinding
from checks.openclaw_profile import OpenClawProfile, load_profile


class OpenClawServiceListener(ServiceListener):
    def __init__(self):
        self.discovered: list[dict] = []

    def add_service(self, zc: Zeroconf, type_: str, name: str):
        info = zc.get_service_info(type_, name)
        if not info:
            return

        txt_records: dict[str, str] = {}
        if info.properties:
            for key, value in info.properties.items():
                k = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else key
                v = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else value
                txt_records[k] = v

        host = socket.inet_ntoa(info.addresses[0]) if info.addresses else None
        self.discovered.append({
            "name": name,
            "host": host,
            "port": info.port,
            "txt": txt_records,
        })

    def remove_service(self, zc, type_, name):
        pass

    def update_service(self, zc, type_, name):
        pass


# TXT keys whose mere presence is a sensitive leak worth its own finding,
# beyond the generic discovery INFO record.
_LEAK_DESCRIPTIONS = {
    "cliPath": "exposes the full filesystem path to the CLI (reveals the username)",
    "sshPort": "advertises SSH availability on the gateway host",
    "tailnetDns": "exposes the Tailscale MagicDNS hostname",
}


def findings_from_records(
    discovered: list[dict],
    profile: OpenClawProfile,
) -> list[VulnFinding]:
    """Pure mapping from discovered mDNS services to findings (no I/O)."""
    findings: list[VulnFinding] = []
    mdns = profile.mdns
    fix = (
        f"Set {mdns.remediation_key} to 'minimal' or 'off' in openclaw.json "
        f"(or set {mdns.disable_env}=1)."
    )

    for service in discovered:
        txt = service.get("txt", {})

        for key, why in _LEAK_DESCRIPTIONS.items():
            if key not in txt:
                continue
            tk = mdns.txt_key(key)
            severity = tk.severity if tk else Severity.LOW
            findings.append(VulnFinding(
                check_name="mdns_info_disclosure",
                severity=severity,
                title=f"mDNS TXT '{key}' {why}",
                description=(
                    f"The mDNS TXT record '{key}' {why}. This is only published in "
                    f"'full' discovery mode (default is '{mdns.default_mode}')."
                ),
                evidence=f"{key}={txt[key]}",
                remediation=fix,
            ))

        # TLS advertisement is informational but materially changes how the
        # gateway should be probed (wss:// instead of ws://).
        if txt.get("gatewayTls") in ("1", "true", "True"):
            findings.append(VulnFinding(
                check_name="mdns_discovery",
                severity=Severity.INFO,
                title="mDNS advertises a TLS gateway (wss://)",
                description="The gateway advertises gatewayTls=1; its WebSocket uses TLS.",
                evidence=(
                    f"gatewayTls={txt.get('gatewayTls')}, "
                    f"gatewayTlsSha256={txt.get('gatewayTlsSha256', '-')}"
                ),
                remediation="No action required; informational for accurate probing.",
            ))

        if "canvasPort" in txt:
            findings.append(VulnFinding(
                check_name="mdns_discovery",
                severity=Severity.INFO,
                title="mDNS advertises canvas/file-server port",
                description=f"The gateway advertises a canvas host port: {txt['canvasPort']}.",
                evidence=f"canvasPort={txt['canvasPort']}",
                remediation="Ensure the canvas/file server is not exposed beyond trusted networks.",
            ))

        findings.append(VulnFinding(
            check_name="mdns_discovery",
            severity=Severity.INFO,
            title="OpenClaw Gateway discovered via mDNS",
            description=f"Found OpenClaw Gateway at {service.get('host')}:{service.get('port')}",
            evidence=f"Service: {service.get('name')}, TXT records: {txt}",
            remediation=f"Set {mdns.disable_env}=1 to disable mDNS advertising if not needed.",
        ))

    return findings


async def check_mdns_discovery(
    timeout: float = 5.0,
    profile: OpenClawProfile | None = None,
) -> list[VulnFinding]:
    profile = profile or load_profile()

    zeroconf = Zeroconf()
    listener = OpenClawServiceListener()
    try:
        ServiceBrowser(zeroconf, profile.mdns.service_type, listener)
        await asyncio.sleep(timeout)
        return findings_from_records(listener.discovered, profile)
    finally:
        zeroconf.close()

from __future__ import annotations
import asyncio
import socket

from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

from checks.models import Severity, VulnFinding


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


async def check_mdns_discovery(timeout: float = 5.0) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    zeroconf = Zeroconf()
    listener = OpenClawServiceListener()

    ServiceBrowser(zeroconf, "_openclaw-gw._tcp.local.", listener)

    await asyncio.sleep(timeout)

    for service in listener.discovered:
        txt = service["txt"]

        if "cliPath" in txt:
            findings.append(VulnFinding(
                check_name="mdns_info_disclosure",
                severity=Severity.MEDIUM,
                title="mDNS exposes CLI path (reveals username)",
                description=f"The mDNS TXT record 'cliPath' exposes the full filesystem path: {txt['cliPath']}",
                evidence=f"cliPath={txt['cliPath']}",
                remediation="Set gateway.discovery.mode to 'minimal' in openclaw.json",
            ))

        if "sshPort" in txt:
            findings.append(VulnFinding(
                check_name="mdns_info_disclosure",
                severity=Severity.LOW,
                title="mDNS advertises SSH availability",
                description=f"The mDNS TXT record advertises SSH on port {txt['sshPort']}",
                evidence=f"sshPort={txt['sshPort']}",
                remediation="Set gateway.discovery.mode to 'minimal' to hide SSH port",
            ))

        if "tailnetDns" in txt:
            findings.append(VulnFinding(
                check_name="mdns_info_disclosure",
                severity=Severity.LOW,
                title="mDNS exposes Tailscale hostname",
                description=f"The mDNS TXT record exposes Tailscale MagicDNS hostname: {txt['tailnetDns']}",
                evidence=f"tailnetDns={txt['tailnetDns']}",
                remediation="Consider if Tailscale hostname exposure is acceptable",
            ))

        findings.append(VulnFinding(
            check_name="mdns_discovery",
            severity=Severity.INFO,
            title="OpenClaw Gateway discovered via mDNS",
            description=f"Found OpenClaw Gateway at {service['host']}:{service['port']}",
            evidence=f"Service: {service['name']}, TXT records: {txt}",
            remediation="Set OPENCLAW_DISABLE_BONJOUR=1 to disable mDNS if not needed",
        ))

    zeroconf.close()
    return findings

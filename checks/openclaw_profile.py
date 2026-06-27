"""Loader for the centralised OpenClaw attack-surface profile.

Reads ``config/openclaw_surface.yaml`` once and exposes it as a frozen,
immutable dataclass tree so every check shares a single source of truth.
Aligning Sorcino to a new OpenClaw release means editing the YAML, not the
Python.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from checks.models import Severity

_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "openclaw_surface.yaml"

# Safe fallbacks if the profile YAML is missing/corrupt, so graceful
# degradation still recognises fail-closed WS (else a 1008 close would be
# misread as a MEDIUM "auth unclear" false positive).
_FALLBACK_SERVICE_TYPE = "_openclaw-gw._tcp.local."
_FALLBACK_RPC = '{"jsonrpc":"2.0","method":"status","id":1}'
_FALLBACK_WS_CLOSE_CODES = {1008: "fail_closed"}
_FALLBACK_FAIL_CLOSED_REASONS = ("gateway token", "unauthorized")


def _to_severity(value: str | None, default: Severity = Severity.MEDIUM) -> Severity:
    if not value:
        return default
    try:
        return Severity(str(value).lower())
    except ValueError:
        return default


@dataclass(frozen=True)
class HTTPEndpoint:
    path: str
    method: str
    name: str
    severity: Severity
    requires_auth: bool


@dataclass(frozen=True)
class TxtKey:
    key: str
    severity: Severity
    note: str


@dataclass(frozen=True)
class MdnsProfile:
    service_type: str
    remediation_key: str
    default_mode: str
    disable_env: str
    txt_keys: tuple[TxtKey, ...]

    def txt_key(self, name: str) -> TxtKey | None:
        for tk in self.txt_keys:
            if tk.key == name:
                return tk
        return None


@dataclass(frozen=True)
class OpenClawProfile:
    schema_version: int
    openclaw_version: str
    auth_modes: tuple[str, ...]
    auth_config_keys: dict[str, str]
    trusted_proxy_headers: tuple[str, ...]
    ws_close_codes: dict[int, str]
    ws_fail_closed_reasons: tuple[str, ...]
    ws_rpc_probe: str
    operator_scopes: tuple[str, ...]
    http_endpoints: tuple[HTTPEndpoint, ...]
    sensitive_indicators: tuple[str, ...]
    mdns: MdnsProfile
    verified_ports: tuple[int, ...]

    def is_fail_closed_reason(self, reason: str | None) -> bool:
        if not reason:
            return False
        low = reason.lower()
        return any(r in low for r in self.ws_fail_closed_reasons)

    def has_operator_scope(self, body: str) -> bool:
        return any(scope in body for scope in self.operator_scopes)


def _parse(data: dict) -> OpenClawProfile:
    auth = data.get("auth", {}) or {}
    ws = data.get("ws", {}) or {}
    mdns_raw = data.get("mdns", {}) or {}

    endpoints = tuple(
        HTTPEndpoint(
            path=e["path"],
            method=str(e.get("method", "GET")).upper(),
            name=e.get("name", e["path"]),
            severity=_to_severity(e.get("severity")),
            requires_auth=bool(e.get("requires_auth", True)),
        )
        for e in (data.get("http_endpoints") or [])
    )

    txt_keys = tuple(
        TxtKey(
            key=name,
            severity=_to_severity((spec or {}).get("severity"), Severity.INFO),
            note=(spec or {}).get("note", ""),
        )
        for name, spec in (mdns_raw.get("txt_keys") or {}).items()
    )

    # YAML maps integer keys natively; coerce defensively.
    close_codes = {int(k): str(v) for k, v in (ws.get("close_codes") or {}).items()}

    verified_ports = tuple(
        p["port"] for p in (data.get("ports") or []) if p.get("verified")
    )

    return OpenClawProfile(
        schema_version=int(data.get("schema_version", 1)),
        openclaw_version=str(data.get("openclaw_version", "unknown")),
        auth_modes=tuple(auth.get("modes") or []),
        auth_config_keys=dict(auth.get("config_keys") or {}),
        trusted_proxy_headers=tuple((auth.get("trusted_proxy") or {}).get("identity_headers") or []),
        ws_close_codes=close_codes or dict(_FALLBACK_WS_CLOSE_CODES),
        ws_fail_closed_reasons=tuple(r.lower() for r in (ws.get("fail_closed_reasons") or [])) or _FALLBACK_FAIL_CLOSED_REASONS,
        ws_rpc_probe=ws.get("rpc_probe") or _FALLBACK_RPC,
        operator_scopes=tuple(data.get("operator_scopes") or []),
        http_endpoints=endpoints,
        sensitive_indicators=tuple(data.get("sensitive_indicators") or []),
        mdns=MdnsProfile(
            service_type=mdns_raw.get("service_type") or _FALLBACK_SERVICE_TYPE,
            remediation_key=mdns_raw.get("remediation_key") or "discovery.mdns.mode",
            default_mode=mdns_raw.get("default_mode") or "minimal",
            disable_env=mdns_raw.get("disable_env") or "OPENCLAW_DISABLE_BONJOUR",
            txt_keys=txt_keys,
        ),
        verified_ports=verified_ports,
    )


@lru_cache(maxsize=None)
def load_profile(path: str | None = None) -> OpenClawProfile:
    """Load and cache the OpenClaw surface profile.

    Falls back to a minimal, safe profile if the YAML is missing or invalid so
    that a packaging slip degrades gracefully instead of crashing every scan.
    """
    target = Path(path) if path else _DEFAULT_PATH
    try:
        with open(target) as f:
            data = yaml.safe_load(f) or {}
        return _parse(data)
    except (OSError, yaml.YAMLError, KeyError):
        return _parse({})

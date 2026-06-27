from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass(frozen=True)
class FingerprintMatch:
    service_name: str
    confidence: int
    matched_signals: tuple[str, ...]
    details: dict


class SignatureMatcher:
    def __init__(self, signatures_dir: Optional[str] = None):
        if signatures_dir is None:
            signatures_dir = str(Path(__file__).parent / "signatures")
        self.signatures = self._load_signatures(signatures_dir)
        self._path_rules = self._collect_path_rules()

    def _collect_path_rules(self) -> list[tuple[frozenset[int] | None, list[str]]]:
        """(ports, GET-paths) per signature. A signature's extra paths are only
        probed on the port(s) it declares (or on every port if it declares
        none), so adding many signatures doesn't bloat per-port probing."""
        rules: list[tuple[frozenset[int] | None, list[str]]] = []
        for sig in self.signatures:
            ports = frozenset(p["port"] for p in sig.get("ports", [])) or None
            paths = [
                ep["path"] for ep in sig.get("endpoints", [])
                if str(ep.get("method", "GET")).upper() == "GET" and ep.get("path")
            ]
            if paths:
                rules.append((ports, paths))
        return rules

    def extra_paths_for_port(self, port: int) -> list[str]:
        """Signature-declared GET paths relevant to `port` (beyond DEFAULT_PATHS)."""
        out: list[str] = []
        for ports, paths in self._path_rules:
            if ports is None or port in ports:
                out.extend(paths)
        return list(dict.fromkeys(out))

    def _load_signatures(self, dir_path: str) -> list[dict]:
        signatures = []
        sig_path = Path(dir_path)
        if not sig_path.exists():
            return signatures
        for yaml_file in sig_path.glob("*.yaml"):
            with open(yaml_file) as f:
                sig = yaml.safe_load(f)
                if sig:
                    signatures.append(sig)
        return signatures

    def match(
        self,
        port: int,
        headers: dict[str, str],
        body: str,
        url_path: str,
    ) -> list[FingerprintMatch]:
        matches = []

        for sig in self.signatures:
            confidence = sig.get("confidence_base", 0)
            matched_signals = []

            for port_rule in sig.get("ports", []):
                if port == port_rule["port"]:
                    confidence += port_rule["weight"]
                    matched_signals.append(f"port:{port}")

            for header_rule in sig.get("headers", []):
                header_name = header_rule["name"].lower()
                for h_name in headers:
                    if h_name.lower() == header_name:
                        confidence += header_rule["weight"]
                        matched_signals.append(f"header:{header_name}")
                        break

            for pattern_rule in sig.get("body_patterns", []):
                flags = re.IGNORECASE if pattern_rule.get("case_insensitive") else 0
                if re.search(pattern_rule["pattern"], body, flags):
                    confidence += pattern_rule["weight"]
                    matched_signals.append(f"body_pattern:{pattern_rule['pattern'][:30]}")

            for endpoint in sig.get("endpoints", []):
                if url_path == endpoint["path"]:
                    confidence += endpoint.get("weight", 0)
                    matched_signals.append(f"endpoint:{endpoint['path']}")

                    # Per-endpoint header checks (previously declared in the
                    # signatures but silently ignored by the matcher).
                    for hc in endpoint.get("headers_check", []):
                        want_name = hc["header"].lower()
                        want_val = str(hc.get("value", "")).lower()
                        for h_name, h_val in headers.items():
                            if h_name.lower() == want_name and (
                                not want_val or want_val in str(h_val).lower()
                            ):
                                confidence += hc.get("weight", 0)
                                matched_signals.append(f"header_check:{want_name}")
                                break

                    for resp_pattern in endpoint.get("response_patterns", []):
                        flags = re.IGNORECASE if resp_pattern.get("case_insensitive") else 0
                        if re.search(resp_pattern["pattern"], body, flags):
                            confidence += resp_pattern["weight"]
                            matched_signals.append(f"response:{resp_pattern['pattern'][:30]}")

            confidence = min(confidence, 100)
            threshold = sig.get("threshold", 50)
            if confidence >= threshold:
                matches.append(FingerprintMatch(
                    service_name=sig["name"],
                    confidence=confidence,
                    matched_signals=tuple(matched_signals),
                    details={"description": sig.get("description", "")},
                ))

        return sorted(matches, key=lambda x: x.confidence, reverse=True)

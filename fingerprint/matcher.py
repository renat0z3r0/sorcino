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

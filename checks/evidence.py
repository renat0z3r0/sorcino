from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class EvidenceCollector:
    """Collects and saves raw evidence to disk when --dump-evidence is active."""

    def __init__(self, base_dir: str, target_label: str):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_label = target_label.replace("/", "_").replace(":", "_")
        self.dir = Path(base_dir) / f"{ts}_{safe_label}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._items: list[dict] = []

    def save_file(self, path: str, content: str, source_url: str) -> None:
        # Prefix with host:port so the same path served on two ports of one
        # host doesn't collide (last-writer-wins + an inconsistent manifest).
        netloc = urlsplit(source_url).netloc.replace(":", "_")
        base = path.lstrip("/").replace("/", "_") or "root"
        safe_name = f"{netloc}_{base}" if netloc else base
        dest = self.dir / safe_name
        dest.write_text(content, encoding="utf-8")
        self._items.append({
            "type": "sensitive_file",
            "path": path,
            "source_url": source_url,
            "saved_as": str(dest.name),
            "size_bytes": len(content.encode("utf-8")),
        })

    def save_ws_response(self, ws_url: str, sent: str, received: str) -> None:
        dest = self.dir / "websocket_responses.txt"
        with open(dest, "a", encoding="utf-8") as f:
            f.write(f"--- {ws_url} ---\n")
            f.write(f"SENT: {sent}\n")
            f.write(f"RECV: {received}\n\n")
        already = any(i.get("saved_as") == "websocket_responses.txt" for i in self._items)
        if not already:
            self._items.append({
                "type": "websocket_response",
                "saved_as": "websocket_responses.txt",
            })

    def write_manifest(self) -> None:
        if not self._items:
            return
        manifest = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "evidence_dir": str(self.dir),
            "items": self._items,
        }
        dest = self.dir / "manifest.json"
        dest.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

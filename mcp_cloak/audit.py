"""Append-only JSONL audit log.

Each masking event is recorded as one JSON line. The log never contains the raw
secret — only its class, the placeholder token, and its length. This makes the
audit trail safe to share while still being useful for forensics.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    """Thread-safe append-only JSONL audit log."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        direction: str,
        cls: str,
        placeholder: str,
        value_len: int,
        tool: str | None = None,
        method: str | None = None,
        rpc_id: object = None,
    ) -> dict:
        """Append one masking event and return the written record."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "direction": direction,
            "tool": tool,
            "method": method,
            "rpc_id": rpc_id,
            "class": cls,
            "placeholder": placeholder,
            "value_len": value_len,
        }
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry

    def read(self) -> list[dict]:
        """Return all audit entries (empty list if the log does not exist)."""
        if not self.path.exists():
            return []
        entries: list[dict] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

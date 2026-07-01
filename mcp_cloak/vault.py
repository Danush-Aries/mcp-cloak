"""The reversible vault: maps real values <-> stable placeholder tokens.

The vault is the heart of mcp-cloak's *reversibility* wedge. Each real value is
mapped to a deterministic placeholder like ``⟪EMAIL_1⟫``. The same real value
always yields the same placeholder within a session. Masking replaces detected
spans with placeholders; restoring replaces known placeholders with their real
values. By construction ``restore(mask(text)) == text``.

The mapping is persisted to a local JSON file so a separate process (e.g.
``mcp-cloak reveal``) can restore values for debugging. That file contains real
secrets and must never be committed — this is the honest cost of reversibility.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Callable

from .detectors import detect

# Placeholders use mathematical white brackets U+27EA / U+27EB which never occur
# in secrets or normal JSON, guaranteeing collision-free replacement.
OPEN = "⟪"
CLOSE = "⟫"
PLACEHOLDER_RE = re.compile(OPEN + r"[A-Z0-9_]+_\d+" + CLOSE)

MaskCallback = Callable[[str, str, str], None]  # (cls, placeholder, raw_len_str)


class Vault:
    """Bidirectional, persistent map between real values and placeholders."""

    def __init__(
        self,
        state_path: str | Path | None = None,
        *,
        enabled: set[str] | None = None,
        entropy_enabled: bool = True,
        entropy_threshold: float = 3.5,
        use_presidio: bool = False,
    ) -> None:
        self.state_path = Path(state_path) if state_path else None
        self.enabled = enabled
        self.entropy_enabled = entropy_enabled
        self.entropy_threshold = entropy_threshold
        self.use_presidio = use_presidio

        self._raw_to_ph: dict[str, str] = {}
        self._ph_to_raw: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._lock = threading.RLock()

        if self.state_path and self.state_path.exists():
            self._load()

    # --- persistence ------------------------------------------------------

    def _load(self) -> None:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        self._ph_to_raw = dict(data.get("placeholders", {}))
        self._raw_to_ph = {v: k for k, v in self._ph_to_raw.items()}
        self._counters = dict(data.get("counters", {}))

    def _persist(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "placeholders": self._ph_to_raw,
            "counters": self._counters,
        }
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    # --- core mapping -----------------------------------------------------

    def placeholder_for(self, value: str, cls: str) -> str:
        """Return the stable placeholder for ``value`` (creating it if new)."""
        with self._lock:
            existing = self._raw_to_ph.get(value)
            if existing is not None:
                return existing
            n = self._counters.get(cls, 0) + 1
            self._counters[cls] = n
            ph = f"{OPEN}{cls}_{n}{CLOSE}"
            self._raw_to_ph[value] = ph
            self._ph_to_raw[ph] = value
            self._persist()
            return ph

    def reveal(self, placeholder: str) -> str | None:
        """Return the real value behind a placeholder, or None if unknown."""
        with self._lock:
            return self._ph_to_raw.get(placeholder)

    # --- text-level mask / restore ---------------------------------------

    def mask_text(
        self,
        text: str,
        *,
        on_mask: MaskCallback | None = None,
    ) -> str:
        """Replace detected secrets/PII in ``text`` with placeholders."""
        matches = detect(
            text,
            enabled=self.enabled,
            entropy_enabled=self.entropy_enabled,
            entropy_threshold=self.entropy_threshold,
            use_presidio=self.use_presidio,
        )
        if not matches:
            return text
        out: list[str] = []
        last = 0
        for m in matches:
            out.append(text[last : m.start])
            ph = self.placeholder_for(m.value, m.cls)
            out.append(ph)
            if on_mask is not None:
                on_mask(m.cls, ph, str(len(m.value)))
            last = m.end
        out.append(text[last:])
        return "".join(out)

    def restore_text(self, text: str) -> str:
        """Replace any known placeholders in ``text`` with their real values."""
        if OPEN not in text:
            return text

        def _sub(match: re.Match[str]) -> str:
            ph = match.group(0)
            with self._lock:
                return self._ph_to_raw.get(ph, ph)

        return PLACEHOLDER_RE.sub(_sub, text)

    # --- JSON-level mask / restore ---------------------------------------

    def mask_json(
        self,
        obj: object,
        *,
        tool: str | None = None,
        on_mask: MaskCallback | None = None,
        allow: Callable[[str | None, str | None], bool] | None = None,
        _key: str | None = None,
    ) -> object:
        """Recursively mask string values inside a JSON-like structure.

        Args:
            obj: JSON-decoded value (dict/list/str/number/bool/None).
            tool: Current MCP tool name, used for allow/deny rule matching.
            on_mask: Callback invoked per masked value.
            allow: Predicate ``(tool, field) -> bool``. When it returns True the
                field is left untouched (allow-listed).
            _key: Internal — the JSON key currently being descended into.
        """
        if isinstance(obj, str):
            if allow is not None and allow(tool, _key):
                return obj
            return self.mask_text(obj, on_mask=on_mask)
        if isinstance(obj, dict):
            return {
                k: self.mask_json(v, tool=tool, on_mask=on_mask, allow=allow, _key=k)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [
                self.mask_json(v, tool=tool, on_mask=on_mask, allow=allow, _key=_key)
                for v in obj
            ]
        return obj

    def restore_json(self, obj: object) -> object:
        """Recursively restore placeholders inside a JSON-like structure."""
        if isinstance(obj, str):
            return self.restore_text(obj)
        if isinstance(obj, dict):
            return {k: self.restore_json(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.restore_json(v) for v in obj]
        return obj

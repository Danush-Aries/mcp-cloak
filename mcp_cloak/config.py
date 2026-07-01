"""Configuration loading (TOML) and allow/deny rules.

Config controls which directions are masked, detector tuning, and per-tool /
per-field allow/deny rules. Everything has a sensible default so mcp-cloak runs
with no config file at all.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# All detector class names known to the regex engine (plus entropy SECRET).
ALL_CLASSES = {
    "PRIVATE_KEY",
    "JWT",
    "AWS_KEY",
    "APIKEY",
    "EMAIL",
    "INTERNAL_HOST",
    "PRIVATE_IP",
    "PHONE",
    "SECRET",
}


@dataclass
class Rule:
    """An allow/deny rule matched against (tool, field).

    ``action == "allow"`` leaves the matching field un-masked (allow-list).
    ``action == "deny"`` forces masking (the default behaviour anyway).
    ``tool``/``field`` of None act as wildcards.
    """

    action: str
    tool: str | None = None
    field: str | None = None

    def matches(self, tool: str | None, field: str | None) -> bool:
        if self.tool is not None and self.tool != tool:
            return False
        if self.field is not None and self.field != field:
            return False
        return True


@dataclass
class Config:
    """Runtime configuration for the proxy."""

    mask_outbound: bool = True   # client -> downstream
    mask_inbound: bool = True    # downstream -> client
    restore_returning: bool = True  # restore known placeholders on return path
    entropy_enabled: bool = True
    entropy_threshold: float = 3.5
    use_presidio: bool = False
    enabled_classes: set[str] = field(default_factory=lambda: set(ALL_CLASSES))
    rules: list[Rule] = field(default_factory=list)

    def allow(self, tool: str | None, field_name: str | None) -> bool:
        """Return True if (tool, field) is explicitly allow-listed (skip mask)."""
        allowed = False
        for rule in self.rules:
            if rule.matches(tool, field_name):
                if rule.action == "allow":
                    allowed = True
                elif rule.action == "deny":
                    return False
        return allowed


def load_config(path: str | Path | None) -> Config:
    """Load config from a TOML file, or return defaults if path is None/missing."""
    cfg = Config()
    if path is None:
        return cfg
    p = Path(path)
    if not p.exists():
        return cfg

    data = tomllib.loads(p.read_text(encoding="utf-8"))
    cloak = data.get("cloak", {})
    cfg.mask_outbound = bool(cloak.get("mask_outbound", cfg.mask_outbound))
    cfg.mask_inbound = bool(cloak.get("mask_inbound", cfg.mask_inbound))
    cfg.restore_returning = bool(cloak.get("restore_returning", cfg.restore_returning))
    cfg.entropy_enabled = bool(cloak.get("entropy_enabled", cfg.entropy_enabled))
    cfg.entropy_threshold = float(cloak.get("entropy_threshold", cfg.entropy_threshold))
    cfg.use_presidio = bool(cloak.get("use_presidio", cfg.use_presidio))

    detectors = data.get("detectors")
    if isinstance(detectors, dict):
        enabled = {c for c in ALL_CLASSES if detectors.get(c.lower(), True)}
        cfg.enabled_classes = enabled

    rules: list[Rule] = []
    for raw in data.get("rules", []):
        action = raw.get("action", "deny")
        if action not in ("allow", "deny"):
            raise ValueError(f"invalid rule action: {action!r}")
        rules.append(Rule(action=action, tool=raw.get("tool"), field=raw.get("field")))
    cfg.rules = rules
    return cfg

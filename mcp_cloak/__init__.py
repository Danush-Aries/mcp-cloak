"""mcp-cloak — a local, reversible secret/PII redaction proxy for MCP traffic.

mcp-cloak sits between an AI agent (the MCP client) and a downstream MCP server,
intercepting JSON-RPC messages in both directions. It masks detected secrets and
PII with stable, reversible placeholder tokens (e.g. ``⟪EMAIL_1⟫``), records every
mask in an append-only audit log, and lets a developer restore the original value
locally for debugging.

Unlike one-way enterprise gateways (which strip data irreversibly) and scanners
(which only detect), mcp-cloak's wedge is *reversibility*: the real value never
leaves the machine, but can be recovered locally via the vault.
"""

from .vault import Vault
from .detectors import detect, Match
from .audit import AuditLog
from .config import Config, load_config

__version__ = "0.1.0"

__all__ = [
    "Vault",
    "detect",
    "Match",
    "AuditLog",
    "Config",
    "load_config",
    "__version__",
]

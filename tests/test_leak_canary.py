"""Leak-canary tests: no raw secret may appear in downstream-bound bytes."""

import json

from mcp_cloak.audit import AuditLog
from mcp_cloak.config import Config
from mcp_cloak.proxy import FROM_DOWNSTREAM, TO_DOWNSTREAM, Proxy
from mcp_cloak.vault import Vault
from tests.fixtures import RAW_SECRETS, SECRET_BLOB


def _proxy(tmp_path, config=None):
    vault = Vault(tmp_path / "vault.json")
    audit = AuditLog(tmp_path / "audit.jsonl")
    return Proxy(["true"], vault, audit, config or Config())


def test_no_raw_secret_in_outbound_bytes(tmp_path):
    proxy = _proxy(tmp_path)
    msg = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "crm.update", "arguments": dict(SECRET_BLOB)},
    }
    out = proxy.transform(msg, TO_DOWNSTREAM)
    serialized = json.dumps(out, ensure_ascii=False)
    for secret in RAW_SECRETS:
        assert secret not in serialized, f"LEAK: {secret} present in outbound bytes"
    assert "⟪" in serialized  # placeholders were inserted


def test_no_raw_secret_in_inbound_bytes(tmp_path):
    proxy = _proxy(tmp_path)
    msg = {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"structuredContent": dict(SECRET_BLOB)},
    }
    out = proxy.transform(msg, FROM_DOWNSTREAM)
    serialized = json.dumps(out, ensure_ascii=False)
    for secret in RAW_SECRETS:
        assert secret not in serialized, f"LEAK: {secret} present in inbound bytes"


def test_clean_field_survives_untouched(tmp_path):
    proxy = _proxy(tmp_path)
    msg = {"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": dict(SECRET_BLOB)}}
    out = proxy.transform(msg, FROM_DOWNSTREAM)
    assert out["result"]["structuredContent"]["clean"] == "The meeting is at 3pm."


def test_masking_is_audited(tmp_path):
    proxy = _proxy(tmp_path)
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "crm.update", "arguments": {"email": "alice@example.com"}}}
    proxy.transform(msg, TO_DOWNSTREAM)
    entries = proxy.audit.read()
    assert any(e["class"] == "EMAIL" for e in entries)
    # The audit log must never contain the raw secret.
    assert all("alice@example.com" not in json.dumps(e) for e in entries)

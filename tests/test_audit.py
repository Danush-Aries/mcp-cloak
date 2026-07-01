"""Audit-log format tests."""

import json

from mcp_cloak.audit import AuditLog


def test_record_and_read_roundtrip(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    entry = log.record(
        direction="to_downstream", cls="EMAIL", placeholder="⟪EMAIL_1⟫",
        value_len=17, tool="crm.update", method="tools/call", rpc_id=3,
    )
    assert entry["class"] == "EMAIL"
    assert entry["placeholder"] == "⟪EMAIL_1⟫"
    read = log.read()
    assert read == [entry]


def test_append_only_accumulates(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(3):
        log.record(direction="to_downstream", cls="EMAIL",
                   placeholder=f"⟪EMAIL_{i}⟫", value_len=10)
    assert len(log.read()) == 3


def test_each_line_is_valid_json(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record(direction="from_downstream", cls="APIKEY",
               placeholder="⟪APIKEY_1⟫", value_len=30)
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = json.loads(line)
        assert set(parsed) >= {"ts", "direction", "class", "placeholder", "value_len"}


def test_record_has_iso_timestamp(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    entry = log.record(direction="to_downstream", cls="PHONE",
                       placeholder="⟪PHONE_1⟫", value_len=12)
    # Parses as ISO-8601 with timezone.
    from datetime import datetime
    dt = datetime.fromisoformat(entry["ts"])
    assert dt.tzinfo is not None

"""Config loading and allow/deny rule behaviour."""

import textwrap

from mcp_cloak.audit import AuditLog
from mcp_cloak.config import Config, Rule, load_config
from mcp_cloak.proxy import TO_DOWNSTREAM, Proxy
from mcp_cloak.vault import Vault


def test_defaults_when_no_file():
    cfg = load_config(None)
    assert cfg.mask_outbound and cfg.mask_inbound
    assert cfg.restore_returning
    assert cfg.rules == []


def test_load_toml(tmp_path):
    p = tmp_path / "cloak.toml"
    p.write_text(textwrap.dedent("""
        [cloak]
        mask_inbound = false
        entropy_threshold = 4.0

        [detectors]
        phone = false

        [[rules]]
        tool = "crm.get_customer"
        field = "notes"
        action = "allow"
    """), encoding="utf-8")
    cfg = load_config(p)
    assert cfg.mask_inbound is False
    assert cfg.entropy_threshold == 4.0
    assert "PHONE" not in cfg.enabled_classes
    assert len(cfg.rules) == 1
    assert cfg.rules[0].action == "allow"


def test_allow_rule_skips_masking(tmp_path):
    cfg = Config(rules=[Rule(action="allow", tool="crm.get_customer", field="notes")])
    vault = Vault(tmp_path / "v.json")
    audit = AuditLog(tmp_path / "a.jsonl")
    proxy = Proxy(["true"], vault, audit, cfg)
    msg = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "crm.get_customer", "arguments": {
            "notes": "reach me at alice@example.com",   # allowed -> untouched
            "email": "bob@example.com",                 # not allowed -> masked
        }},
    }
    out = proxy.transform(msg, TO_DOWNSTREAM)
    args = out["params"]["arguments"]
    assert args["notes"] == "reach me at alice@example.com"
    assert args["email"].startswith("⟪EMAIL_")


def test_deny_rule_forces_masking(tmp_path):
    cfg = Config(rules=[Rule(action="allow", tool=None, field="notes"),
                        Rule(action="deny", tool="crm.get_customer", field="notes")])
    # deny wins for the specific tool, so notes gets masked here.
    assert cfg.allow("crm.get_customer", "notes") is False
    assert cfg.allow("other.tool", "notes") is True


def test_wildcard_field_allow():
    cfg = Config(rules=[Rule(action="allow", tool="safe.tool", field=None)])
    assert cfg.allow("safe.tool", "anything") is True
    assert cfg.allow("other.tool", "anything") is False

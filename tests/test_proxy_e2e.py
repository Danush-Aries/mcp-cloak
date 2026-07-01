"""End-to-end proxy test: real subprocess pipeline through the CLI.

demo_client behaviour is reproduced here as a test:
    pytest  ->  mcp-cloak wrap (subprocess)  ->  mock_crm_server (subprocess)
"""

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "examples" / "mock_crm_server.py"

RAW_SECRETS = [
    "sk-FAKE1234567890abcdefghijABCD",
    "alice@example.com",
    "AKIAFAKE1234567890XY",
    "10.1.2.3",
    "crm-db-01.internal",
]


def _recv(proc, want_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if msg.get("id") == want_id:
            return msg
    raise TimeoutError(f"no response for id={want_id}")


def test_end_to_end_masking_audit_and_reveal(tmp_path):
    state = tmp_path / "state"
    cmd = [sys.executable, "-m", "mcp_cloak.cli", "--state-dir", str(state),
           "wrap", "--", sys.executable, str(SERVER)]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
        cwd=str(ROOT),
    )
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                     "params": {}}) + "\n")
        proc.stdin.flush()
        _recv(proc, 1)
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                     "params": {"name": "crm.get_customer",
                                                "arguments": {"id": "cust_1001"}}}) + "\n")
        proc.stdin.flush()
        resp = _recv(proc, 2)
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.wait(timeout=10)

    record = resp["result"]["structuredContent"]
    client_bytes = json.dumps(record)

    # 1) Client sees placeholders, not raw secrets.
    for secret in RAW_SECRETS:
        assert secret not in client_bytes, f"LEAK: {secret}"
    assert record["email"].startswith("⟪EMAIL_")

    # 2) Audit log recorded masks (and never a raw secret).
    audit_out = subprocess.run(
        [sys.executable, "-m", "mcp_cloak.cli", "--state-dir", str(state),
         "audit", "--json"],
        cwd=str(ROOT), capture_output=True, text=True,
    ).stdout
    entries = json.loads(audit_out)
    classes = {e["class"] for e in entries}
    assert {"EMAIL", "APIKEY", "AWS_KEY"} <= classes
    for secret in RAW_SECRETS:
        assert secret not in audit_out

    # 3) reveal restores the real value locally.
    token = record["email"]
    reveal_out = subprocess.run(
        [sys.executable, "-m", "mcp_cloak.cli", "--state-dir", str(state),
         "reveal", token],
        cwd=str(ROOT), capture_output=True, text=True,
    ).stdout
    assert "alice@example.com" in reveal_out

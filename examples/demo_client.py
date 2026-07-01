#!/usr/bin/env python3
"""End-to-end demo driver for mcp-cloak.

Spawns the real proxy wrapping the real mock CRM server:

    demo_client  <->  mcp-cloak wrap  <->  mock_crm_server

then performs a genuine MCP handshake + tools/call, and shows that:

  1. the client receives ⟪PLACEHOLDER⟫ tokens instead of raw secrets/PII,
  2. the audit log recorded each mask (class + placeholder, never the secret),
  3. ``mcp-cloak reveal <token>`` restores the original value locally.

This is real MCP traffic through a real proxy. Only the CRM record is seeded.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".mcp-cloak-demo"


def _send(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def _recv(proc, want_id, timeout=10.0):
    """Read lines from the proxy until we see the response with want_id."""
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


def main() -> int:
    server = ROOT / "examples" / "mock_crm_server.py"
    cmd = [
        sys.executable, "-m", "mcp_cloak.cli",
        "--state-dir", str(STATE_DIR),
        "wrap", "--",
        sys.executable, str(server),
    ]
    print("=" * 68)
    print("STARTING:  demo_client  <->  mcp-cloak  <->  mock_crm_server")
    print("=" * 68)
    print("$ " + " ".join(cmd))
    print()

    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=sys.stderr, text=True, encoding="utf-8", bufsize=1, cwd=str(ROOT),
    )
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2024-11-05",
                                "capabilities": {}, "clientInfo": {"name": "demo"}}})
        _recv(proc, 1)
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": "crm.get_customer",
                                "arguments": {"id": "cust_1001"}}})
        resp = _recv(proc, 2)
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.wait(timeout=5)

    record = resp["result"]["structuredContent"]
    print("-" * 68)
    print("1) WHAT THE CLIENT (agent) RECEIVED  — secrets are masked:")
    print("-" * 68)
    print(json.dumps(record, indent=2, ensure_ascii=False))
    print()

    tokens = sorted({v for v in record.values()
                     if isinstance(v, str) and v.startswith("⟪")})

    print("-" * 68)
    print("2) AUDIT LOG  — each mask recorded (class + placeholder, no secret):")
    print("-" * 68)
    sys.stdout.flush()
    subprocess.run([sys.executable, "-m", "mcp_cloak.cli",
                    "--state-dir", str(STATE_DIR), "audit"], cwd=str(ROOT))
    print()

    print("-" * 68)
    print("3) LOCAL REVEAL  — restore the real values for debugging:")
    print("-" * 68)
    sys.stdout.flush()
    subprocess.run([sys.executable, "-m", "mcp_cloak.cli",
                    "--state-dir", str(STATE_DIR), "reveal", *tokens], cwd=str(ROOT))
    print()
    sys.stdout.flush()

    # Leak assertion: no raw secret should be present in the client-side bytes.
    raw_secrets = ["sk-FAKE1234567890abcdefghijABCD", "alice@example.com",
                   "AKIAFAKE1234567890XY", "10.1.2.3", "crm-db-01.internal"]
    client_bytes = json.dumps(record)
    leaked = [s for s in raw_secrets if s in client_bytes]
    if leaked:
        print(f"LEAK DETECTED: {leaked}", file=sys.stderr)
        return 1
    print("OK: no raw secret appeared in the client-bound payload.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

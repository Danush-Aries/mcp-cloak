#!/usr/bin/env python3
"""A minimal, REAL MCP-style server over stdio for the mcp-cloak demo.

It speaks newline-delimited JSON-RPC 2.0 (the MCP stdio framing) and exposes a
single ``crm.get_customer`` tool that returns a customer record seeded with
*obviously fake* secrets and PII. This is a stand-in for a third-party CRM MCP
server that an agent might connect to.

Nothing here is real: every secret is a clearly-fake placeholder (sk-FAKE...,
example.com, RFC1918 IPs). The point of the demo is that the *proxying and
masking* are genuine, not the data.
"""

from __future__ import annotations

import json
import sys

# Seeded record. Every value below is deliberately fake.
CUSTOMER = {
    "id": "cust_1001",
    "name": "Alice Example",
    "email": "alice@example.com",
    "phone": "+1-415-555-0142",
    "billing_contact": "bob@example.com",
    "api_key": "sk-FAKE1234567890abcdefghijABCD",
    "aws_access_key_id": "AKIAFAKE1234567890XY",
    "internal_host": "crm-db-01.internal",
    "internal_ip": "10.1.2.3",
    "session_jwt": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJmYWtlLXVzZXIiLCJyb2xlIjoiYWRtaW4ifQ"
        ".FAKEfakeSIGNATUREvalue1234567890"
    ),
    "notes": "VIP customer; prefers email contact.",
}

TOOLS = [
    {
        "name": "crm.get_customer",
        "description": "Fetch a customer record by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    }
]


def _reply(rpc_id, result):
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _error(rpc_id, code, message):
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def handle(msg):
    method = msg.get("method")
    rpc_id = msg.get("id")

    if method == "initialize":
        return _reply(
            rpc_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-crm", "version": "0.1.0"},
            },
        )
    if method == "notifications/initialized":
        return None  # notification, no response
    if method == "tools/list":
        return _reply(rpc_id, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params", {})
        if params.get("name") != "crm.get_customer":
            return _error(rpc_id, -32601, f"unknown tool: {params.get('name')}")
        record = dict(CUSTOMER)
        # MCP tool results wrap content; include both a text and structured form.
        return _reply(
            rpc_id,
            {
                "content": [{"type": "text", "text": json.dumps(record)}],
                "structuredContent": record,
                "isError": False,
            },
        )
    if rpc_id is not None:
        return _error(rpc_id, -32601, f"method not found: {method}")
    return None


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Newline-delimited JSON-RPC 2.0 framing over streams.

MCP's stdio transport frames each JSON-RPC message as a single line of JSON
terminated by ``\\n``. These helpers implement that framing cleanly, without
requiring the official SDK. Lines that are not valid JSON are surfaced verbatim
so the proxy can pass them through untouched rather than corrupting the stream.
"""

from __future__ import annotations

import json
from typing import IO, Iterator


class RawLine(str):
    """A line that could not be parsed as JSON (passed through verbatim)."""


def iter_messages(stream: IO[str]) -> Iterator[object | RawLine]:
    """Yield parsed JSON-RPC messages (or RawLine for non-JSON lines)."""
    for line in stream:
        stripped = line.rstrip("\n")
        if not stripped.strip():
            continue
        try:
            yield json.loads(stripped)
        except json.JSONDecodeError:
            yield RawLine(stripped)


def encode_message(msg: object) -> str:
    """Serialize a JSON-RPC message to a single newline-terminated line."""
    if isinstance(msg, RawLine):
        return str(msg) + "\n"
    return json.dumps(msg, ensure_ascii=False) + "\n"


def write_message(stream: IO[str], msg: object) -> None:
    """Write and flush a single framed JSON-RPC message."""
    stream.write(encode_message(msg))
    stream.flush()


def extract_tool(msg: object) -> str | None:
    """Best-effort extraction of the MCP tool name from a request message."""
    if isinstance(msg, dict) and msg.get("method") == "tools/call":
        params = msg.get("params")
        if isinstance(params, dict):
            name = params.get("name")
            if isinstance(name, str):
                return name
    return None


def message_method(msg: object) -> str | None:
    if isinstance(msg, dict):
        m = msg.get("method")
        return m if isinstance(m, str) else None
    return None


def message_id(msg: object) -> object:
    if isinstance(msg, dict):
        return msg.get("id")
    return None

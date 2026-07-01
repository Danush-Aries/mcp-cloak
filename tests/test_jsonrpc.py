"""JSON-RPC newline-delimited framing correctness."""

import io

from mcp_cloak import jsonrpc


def test_roundtrip_encode_decode():
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    line = jsonrpc.encode_message(msg)
    assert line.endswith("\n")
    assert "\n" not in line[:-1]  # single line
    (decoded,) = list(jsonrpc.iter_messages(io.StringIO(line)))
    assert decoded == msg


def test_multiple_messages_are_split_by_newline():
    a = {"jsonrpc": "2.0", "id": 1, "method": "a"}
    b = {"jsonrpc": "2.0", "id": 2, "method": "b"}
    stream = io.StringIO(jsonrpc.encode_message(a) + jsonrpc.encode_message(b))
    msgs = list(jsonrpc.iter_messages(stream))
    assert msgs == [a, b]


def test_blank_lines_are_skipped():
    stream = io.StringIO('\n\n{"jsonrpc":"2.0","id":1}\n\n')
    msgs = list(jsonrpc.iter_messages(stream))
    assert msgs == [{"jsonrpc": "2.0", "id": 1}]


def test_non_json_line_passes_through_as_rawline():
    stream = io.StringIO("this is not json\n")
    (msg,) = list(jsonrpc.iter_messages(stream))
    assert isinstance(msg, jsonrpc.RawLine)
    assert jsonrpc.encode_message(msg) == "this is not json\n"


def test_extract_tool_and_method_and_id():
    msg = {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
           "params": {"name": "crm.get_customer"}}
    assert jsonrpc.extract_tool(msg) == "crm.get_customer"
    assert jsonrpc.message_method(msg) == "tools/call"
    assert jsonrpc.message_id(msg) == 9
    assert jsonrpc.extract_tool({"method": "tools/list"}) is None

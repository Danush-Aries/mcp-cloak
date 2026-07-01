"""The stdio MCP passthrough proxy.

The proxy wraps a downstream MCP server command. It:

  * reads JSON-RPC messages from its own stdin (the agent / client),
  * masks detected secrets/PII on the way *to* the downstream server,
  * forwards them to the downstream server's stdin,
  * reads the downstream server's stdout,
  * restores any returning placeholders, masks newly-seen secrets/PII, and
  * forwards the result to its own stdout (back to the client).

Every mask is recorded in the audit log. The transformation logic is exposed as
:meth:`Proxy.transform` so it can be unit-tested without spawning processes.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from typing import IO

from . import jsonrpc
from .audit import AuditLog
from .config import Config
from .vault import Vault

TO_DOWNSTREAM = "to_downstream"
FROM_DOWNSTREAM = "from_downstream"


class Proxy:
    """A bidirectional masking passthrough for one downstream MCP server."""

    def __init__(
        self,
        downstream_cmd: list[str],
        vault: Vault,
        audit: AuditLog,
        config: Config,
    ) -> None:
        if not downstream_cmd:
            raise ValueError("downstream_cmd must not be empty")
        self.downstream_cmd = downstream_cmd
        self.vault = vault
        self.audit = audit
        self.config = config

    # --- pure transform (unit-testable) ----------------------------------

    def transform(self, msg: object, direction: str) -> object:
        """Mask/restore a single JSON-RPC message for the given direction.

        On the outbound path (to downstream) we mask so the third-party server
        never sees raw secrets. On the inbound path (from downstream) we first
        restore any placeholders the agent itself sent (round-trip correctness),
        then mask any newly-originated PII so it never reaches the agent's LLM.
        """
        if isinstance(msg, jsonrpc.RawLine):
            return msg

        tool = jsonrpc.extract_tool(msg)
        method = jsonrpc.message_method(msg)
        rpc_id = jsonrpc.message_id(msg)

        def on_mask(cls: str, placeholder: str, value_len: str) -> None:
            self.audit.record(
                direction=direction,
                cls=cls,
                placeholder=placeholder,
                value_len=int(value_len),
                tool=tool,
                method=method,
                rpc_id=rpc_id,
            )

        result = msg
        if direction == FROM_DOWNSTREAM and self.config.restore_returning:
            result = self.vault.restore_json(result)

        do_mask = (
            self.config.mask_outbound
            if direction == TO_DOWNSTREAM
            else self.config.mask_inbound
        )
        if do_mask:
            result = self.vault.mask_json(
                result,
                tool=tool,
                on_mask=on_mask,
                allow=self.config.allow,
            )
        return result

    # --- process plumbing ------------------------------------------------

    def _pump(
        self,
        src: IO[str],
        dst: IO[str],
        direction: str,
        on_eof: "callable | None" = None,
    ) -> None:
        try:
            for msg in jsonrpc.iter_messages(src):
                out = self.transform(msg, direction)
                jsonrpc.write_message(dst, out)
        except (BrokenPipeError, ValueError):
            pass
        finally:
            if on_eof is not None:
                on_eof()

    @staticmethod
    def _forward_stderr(src: IO[str]) -> None:
        try:
            for line in src:
                sys.stderr.write(line)
                sys.stderr.flush()
        except (BrokenPipeError, ValueError):
            pass

    def run(
        self,
        stdin: IO[str] | None = None,
        stdout: IO[str] | None = None,
    ) -> int:
        """Spawn the downstream server and pump both directions until EOF."""
        client_in = stdin or sys.stdin
        client_out = stdout or sys.stdout

        proc = subprocess.Popen(
            self.downstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        assert proc.stdin and proc.stdout and proc.stderr

        def close_downstream_stdin() -> None:
            try:
                proc.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass

        t_out = threading.Thread(
            target=self._pump,
            args=(client_in, proc.stdin, TO_DOWNSTREAM, close_downstream_stdin),
            daemon=True,
        )
        t_in = threading.Thread(
            target=self._pump,
            args=(proc.stdout, client_out, FROM_DOWNSTREAM),
            daemon=True,
        )
        t_err = threading.Thread(
            target=self._forward_stderr, args=(proc.stderr,), daemon=True
        )
        t_out.start()
        t_in.start()
        t_err.start()

        # The inbound pump ends when the downstream server closes stdout.
        t_in.join()
        rc = proc.wait()
        return rc

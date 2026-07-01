"""Command-line interface for mcp-cloak.

Subcommands:
  * ``wrap  -- <downstream cmd...>`` — run the masking proxy over a server.
  * ``audit`` — view the audit log.
  * ``reveal <token...>`` — locally restore real values from placeholders.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .audit import AuditLog
from .config import load_config
from .proxy import Proxy
from .vault import Vault

DEFAULT_STATE_DIR = ".mcp-cloak"


def _state_dir(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    return Path(os.environ.get("MCP_CLOAK_HOME", DEFAULT_STATE_DIR))


def _build_vault(state_dir: Path, cfg) -> Vault:
    return Vault(
        state_dir / "vault.json",
        enabled=cfg.enabled_classes,
        entropy_enabled=cfg.entropy_enabled,
        entropy_threshold=cfg.entropy_threshold,
        use_presidio=cfg.use_presidio,
    )


def _config_path(arg: str | None) -> str | None:
    if arg:
        return arg
    default = Path("cloak.toml")
    return str(default) if default.exists() else None


def cmd_wrap(args: argparse.Namespace) -> int:
    if not args.downstream:
        print("error: no downstream command given after '--'", file=sys.stderr)
        return 2
    state_dir = _state_dir(args.state_dir)
    cfg = load_config(_config_path(args.config))
    vault = _build_vault(state_dir, cfg)
    audit = AuditLog(state_dir / "audit.jsonl")
    proxy = Proxy(args.downstream, vault, audit, cfg)
    print(
        f"[mcp-cloak] wrapping: {' '.join(args.downstream)}  "
        f"(state={state_dir})",
        file=sys.stderr,
    )
    return proxy.run()


def cmd_audit(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args.state_dir)
    audit = AuditLog(state_dir / "audit.jsonl")
    entries = audit.read()
    if args.tail:
        entries = entries[-args.tail :]
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    if not entries:
        print("(audit log is empty)")
        return 0
    for e in entries:
        print(
            f"{e['ts']}  {e['direction']:<15}  {e['class']:<13}  "
            f"{e['placeholder']:<16}  tool={e.get('tool')}  method={e.get('method')}"
        )
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args.state_dir)
    cfg = load_config(_config_path(args.config))
    vault = _build_vault(state_dir, cfg)
    rc = 0
    for token in args.tokens:
        raw = vault.reveal(token)
        if raw is None:
            print(f"{token}\t<unknown placeholder>", file=sys.stderr)
            rc = 1
        else:
            print(f"{token}\t{raw}")
    return rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-cloak",
        description="Local, reversible secret/PII redaction proxy for MCP traffic.",
    )
    parser.add_argument(
        "--state-dir",
        help=f"Directory for vault + audit log (default: {DEFAULT_STATE_DIR} "
        "or $MCP_CLOAK_HOME).",
    )
    parser.add_argument(
        "--config",
        help="Path to cloak.toml (default: ./cloak.toml if present).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_wrap = sub.add_parser(
        "wrap", help="Run the masking proxy over a downstream MCP server."
    )
    p_wrap.add_argument(
        "downstream",
        nargs="*",
        default=[],
        help="Downstream server command after '--'.",
    )
    p_wrap.set_defaults(func=cmd_wrap)

    p_audit = sub.add_parser("audit", help="View the audit log.")
    p_audit.add_argument("--tail", type=int, help="Show only the last N entries.")
    p_audit.add_argument("--json", action="store_true", help="Emit JSON.")
    p_audit.set_defaults(func=cmd_audit)

    p_reveal = sub.add_parser(
        "reveal", help="Locally restore real values from placeholder tokens."
    )
    p_reveal.add_argument("tokens", nargs="+", help="Placeholder token(s).")
    p_reveal.set_defaults(func=cmd_reveal)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # Everything after the first "--" is the verbatim downstream command.
    if "--" in argv:
        idx = argv.index("--")
        head, tail = argv[:idx], argv[idx + 1 :]
        ns = parser.parse_args(head)
        if getattr(ns, "func", None) is not cmd_wrap:
            parser.error("'--' is only valid for the 'wrap' subcommand")
        ns.downstream = tail
        return ns.func(ns)
    ns = parser.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())

"""Trusted terminal client for the same core used by the browser and MCP."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .console import ConsoleUnavailable, read_secret
from .errors import VaultError
from .guard import GuardError


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agent-vault")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("open", "serve", "status", "connect", "init", "unlock", "login", "logout", "enroll", "decline", "grant", "revoke", "agents"):
        p = sub.add_parser(name)
        p.add_argument("--data-dir", default=os.environ.get("AGENT_VAULT_DATA_DIR", os.path.expanduser("~/.agent-vault")))
        p.add_argument("--port", type=int, default=int(os.environ.get("AGENT_VAULT_BROKER_PORT", "43122")))
        if name in ("init", "unlock", "login", "enroll", "grant", "revoke", "agents"):
            p.add_argument("--no-remember", action="store_true", help="Keep this login in memory only")
        if name == "connect":
            target = p.add_mutually_exclusive_group(required=True)
            target.add_argument("--local", action="store_true")
            target.add_argument("--server-url")
        if name in ("login", "enroll"):
            p.add_argument("--username")
        if name in ("enroll", "decline"):
            p.add_argument("request_id")
        if name in ("grant", "revoke"):
            p.add_argument("agent_id")
            p.add_argument("operations", nargs="+" if name == "grant" else "*")
    sub.add_parser("mock")
    arguments = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(arguments or ["open"])
    try:
        if args.command == "mock":
            from .mock import start_mock
            server = start_mock()
            try:
                server.serve_forever(.2)
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        from .broker import Broker, ensure_running
        from .ipc import CoreClient
        if args.command == "serve":
            if os.environ.get("AGENT_VAULT_TEST_DIAGNOSTICS") == "1":
                import faulthandler
                faulthandler.dump_traceback_later(8, file=sys.stderr)
                print("Synthetic startup: constructing broker", file=sys.stderr, flush=True)
            Broker(args.data_dir, args.port).serve_forever()
            return 0
        ensure_running(args.data_dir, args.port)
        client = CoreClient(args.data_dir, args.port)
        auth = {"owner_id": "local", "principal_id": "agent:" + os.environ.get("AGENT_VAULT_AGENT_ID", "default"), "client_id": "execution"}
        def status():
            return client.command("status", {})
        def login():
            state = status()
            if state["connected"]:
                return
            if state["phase"] == "needs_target":
                raise VaultError(409, "select_target_first")
            if state["phase"] == "reconnecting":
                raise VaultError(503, "reconnect_pending")
            password = read_secret("Master passphrase / vault password")
            client.command("login", {"selection_id": state["selection_id"],
                "username": getattr(args, "username", None), "passphrase": password,
                "remember_device": not getattr(args, "no_remember", False)})
        if args.command == "open":
            import webbrowser
            url = client.url + "/"
            webbrowser.open(url)
            print("Agent Vault: " + url)
            return 0
        if args.command == "status":
            result = status()
        elif args.command == "connect":
            result = client.call_tool("vault_select_target", {"mode": "local" if args.local else "remote",
                **({"server_url": args.server_url} if not args.local else {})}, auth)
        elif args.command == "init":
            selection = client.call_tool("vault_select_target", {"mode": "local"}, auth)
            if selection["phase"] != "needs_create":
                raise VaultError(409, "already_initialized")
            password = read_secret("New master passphrase (12+ chars)")
            confirm = read_secret("Confirm master passphrase")
            result = client.command("create", {"selection_id": selection["selection_id"],
                "passphrase": password, "confirm": confirm, "remember_device": not args.no_remember})
        elif args.command in ("unlock", "login"):
            login()
            result = status()
        elif args.command == "logout":
            result = client.command("logout", {})
        elif args.command == "enroll":
            login()
            result = client.command("complete", {"request_id": args.request_id,
                                    "secret": read_secret("Credential (no echo)")})
        elif args.command == "decline":
            result = client.call_tool("vault_decline", {"request_id": args.request_id}, auth)
        else:
            login()
            result = client.command("manage", {"method": args.command,
                "agent_id": getattr(args, "agent_id", None), "operations": getattr(args, "operations", None) or None})
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (VaultError, GuardError) as error:
        sys.stderr.write("Vault: " + error.code + "\n")
        return 1
    except (ConsoleUnavailable, TimeoutError):
        sys.stderr.write("Secure terminal input unavailable or timed out. Use the browser.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

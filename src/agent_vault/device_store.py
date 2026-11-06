"""Protect remembered authentication material, never expose it to MCP.

Windows: current-user DPAPI. POSIX: AES-GCM with a private 0600 key inside
0700 connector state; OS permissions are the trust boundary (full-disk
protection requires filesystem encryption). No desktop/keyring dependency.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import VaultError
from .guard import platform_guard, GuardError


class DeviceStore:
    def __init__(self, directory: str):
        self.folder = Path(os.path.abspath(directory) + ".connector")

    def _context(self, mode: str, server_url: str | None) -> bytes:
        return json.dumps({"version": 1, "scope": os.path.normcase(str(self.folder)),
                           "mode": mode, "server_url": server_url}, sort_keys=True).encode()

    def _posix_key(self, create: bool) -> bytes:
        guard = platform_guard()
        if create:
            guard.ensure_private_directory(str(self.folder), create=True)
        else:
            guard.check_directory(str(self.folder))
        path = self.folder / "device.key"
        if create and not path.exists():
            try:
                guard.create_private_file(str(path), os.urandom(32))
            except FileExistsError:
                pass
        guard.check_file(str(path))
        key = path.read_bytes()
        if len(key) != 32:
            raise VaultError(500, "device_protection_unavailable")
        return key

    def protect(self, mode: str, server_url: str | None, username: str | None, password: str) -> dict:
        payload = json.dumps({"username": username, "password": password}).encode()
        context = self._context(mode, server_url)
        try:
            if os.name == "nt":
                from .platform.dpapi import protect
                sealed = protect(len(context).to_bytes(4, "big") + context + payload)
                method = "windows-dpapi-user"
            else:
                nonce = os.urandom(12)
                sealed = nonce + AESGCM(self._posix_key(True)).encrypt(nonce, payload, context)
                method = "posix-private-key-aesgcm"
            return {"version": 1, "protection": method, "blob": base64.b64encode(sealed).decode()}
        except (GuardError, OSError, ValueError):
            raise VaultError(503, "device_protection_unavailable") from None

    def open(self, mode: str, server_url: str | None, envelope: object) -> dict:
        context = self._context(mode, server_url)
        try:
            if not isinstance(envelope, dict) or envelope.get("version") != 1:
                raise ValueError()
            sealed = base64.b64decode(envelope["blob"], validate=True)
            if len(sealed) > 65536:
                raise ValueError()
            if os.name == "nt" and envelope.get("protection") == "windows-dpapi-user":
                from .platform.dpapi import unprotect
                plain = unprotect(sealed)
                prefix = len(context).to_bytes(4, "big") + context
                if not plain.startswith(prefix):
                    raise ValueError()
                payload = plain[len(prefix):]
            elif os.name != "nt" and envelope.get("protection") == "posix-private-key-aesgcm":
                payload = AESGCM(self._posix_key(False)).decrypt(sealed[:12], sealed[12:], context)
            else:
                raise ValueError()
            value = json.loads(payload)
            if (not isinstance(value, dict) or not isinstance(value.get("password"), str)
                    or not 1 <= len(value["password"]) <= 1024
                    or (mode == "remote" and (not isinstance(value.get("username"), str)
                                              or not 1 <= len(value["username"]) <= 100))):
                raise ValueError()
            return value
        except Exception:
            # DPAPI, invalid AEAD tag, missing/wrong key, malformed JSON and
            # changed target all fail closed without echoing plaintext.
            raise VaultError(409, "remembered_device_unavailable") from None

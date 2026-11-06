"""Shared vault error surface: fixed low-signal codes, never secret material."""
from __future__ import annotations


class VaultError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code

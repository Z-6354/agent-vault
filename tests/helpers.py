"""Test helpers: private per-test directories under the user profile.

Test vaults live under the user profile rather than the shared temp
directory: temp trees often carry broad-grant ACLs or are watched by
security software, which the platform guard (correctly) refuses.
"""
from __future__ import annotations

import itertools
import os
import shutil

_COUNTER = itertools.count()


def test_directory(prefix: str = "vault-test-") -> str:
    from agent_vault.guard import platform_guard
    base = os.path.join(os.path.expanduser("~"), ".agent-vault-tests")
    os.makedirs(base, mode=0o700, exist_ok=True)
    path = os.path.join(base, f"{prefix}{os.getpid()}-{next(_COUNTER)}")
    os.makedirs(path, mode=0o700)
    # Harden against the profile tree's inherited Everyone grants.
    platform_guard().ensure_private_directory(path)
    return path


def cleanup(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)

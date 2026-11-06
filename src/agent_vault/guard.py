"""Private-file guard dispatcher.

The guard is the single filesystem trust boundary (UNIFICATION-PLAN §4 row 13).
Every vault entry point goes through it; there is no "skip checks on this
platform" path. Windows and Linux implementations enforce the equivalent of
POSIX owner+0700/0600: current-user ownership, no reparse/symlink/hardlink
components, no broad-grant ACL entries, and exclusive private creation.
"""
from __future__ import annotations

import os


class GuardError(Exception):
    """Fixed-surface filesystem trust failure."""


def platform_guard():
    if os.name == "nt":
        from .platform.win_guard import WindowsGuard
        return WindowsGuard()
    from .platform.posix_guard import PosixGuard
    return PosixGuard()

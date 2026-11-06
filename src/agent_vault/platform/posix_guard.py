"""POSIX private-file guard: uid ownership, 0700/0600 modes, no symlinks
or hardlinks, exclusive private creation. Direct port of src/files.ts
semantics (UNIFICATION-PLAN §4 row 13)."""
from __future__ import annotations

import os
import stat

from ..guard import GuardError


def _reject_symlink_components(path: str) -> None:
    absolute = os.path.abspath(path)
    current = os.path.splitdrive(absolute)[0] + os.sep if os.name != "nt" else os.path.splitdrive(absolute)[0] + os.sep
    parts = [part for part in absolute[len(current):].split(os.sep) if part]
    for part in parts:
        current = os.path.join(current, part)
        try:
            if os.path.islink(current):
                raise GuardError("symlink_rejected")
        except OSError as error:
            if getattr(error, "errno", None) == 2:  # ENOENT: remaining parts absent
                return
            raise GuardError("path_unavailable") from None


class PosixGuard:
    def check_directory(self, path: str) -> str:
        path = os.path.abspath(path)
        _reject_symlink_components(path)
        try:
            info = os.lstat(path)
        except OSError:
            raise GuardError("directory_missing") from None
        if not stat.S_ISDIR(info.st_mode):
            raise GuardError("not_a_directory")
        # Directories normally have links for '.' and their children. The
        # single-link rule applies to regular secret files, not directories.
        if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
            raise GuardError("owner_check_failed")
        return path

    def check_file(self, path: str) -> str:
        path = os.path.abspath(path)
        _reject_symlink_components(path)
        try:
            info = os.lstat(path)
        except OSError:
            raise GuardError("file_missing") from None
        if not stat.S_ISREG(info.st_mode):
            raise GuardError("not_a_regular_file")
        if info.st_nlink > 1:
            raise GuardError("hardlink_rejected")
        if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o600:
            raise GuardError("owner_check_failed")
        return path

    def ensure_private_directory(self, path: str, create: bool = False) -> str:
        path = os.path.abspath(path)
        _reject_symlink_components(path)
        if create and not os.path.exists(path):
            os.makedirs(path, mode=0o700, exist_ok=False)
        return self.check_directory(path)

    def create_private_file(self, path: str, data: bytes) -> str:
        path = os.path.abspath(path)
        _reject_symlink_components(os.path.dirname(path) or path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return self.check_file(path)

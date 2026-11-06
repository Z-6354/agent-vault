import os
import shutil
import stat
import unittest

from agent_vault.guard import GuardError, platform_guard
from agent_vault.platform import posix_guard  # noqa: F401  (import parity check)


@unittest.skipUnless(os.name == "posix", "POSIX guard tests")
class PosixGuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = platform_guard()
        self.root = os.path.realpath(
            __import__("tempfile").mkdtemp(prefix="vault-guard-posix-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_private_directory_and_file_pass(self):
        directory = self.guard.ensure_private_directory(
            os.path.join(self.root, "data"), create=True)
        path = self.guard.create_private_file(
            os.path.join(directory, "execution.key"), b"0" * 64)
        self.assertEqual(oct(stat.S_IMODE(os.stat(directory).st_mode)), "0o700")
        self.assertEqual(oct(stat.S_IMODE(os.stat(path).st_mode)), "0o600")

    def test_world_readable_file_rejected(self):
        path = self.guard.create_private_file(
            os.path.join(self.root, "key"), b"0" * 64)
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(GuardError, "owner_check_failed"):
            self.guard.check_file(path)

    def test_symlink_rejected(self):
        target = self.guard.create_private_file(
            os.path.join(self.root, "key"), b"0" * 64)
        link = os.path.join(self.root, "link")
        os.symlink(target, link)
        with self.assertRaisesRegex(GuardError, "symlink_rejected"):
            self.guard.check_file(link)

    def test_hardlink_rejected(self):
        path = self.guard.create_private_file(
            os.path.join(self.root, "key"), b"0" * 64)
        os.link(path, os.path.join(self.root, "hardlink"))
        with self.assertRaisesRegex(GuardError, "hardlink_rejected"):
            self.guard.check_file(path)

    def test_exclusive_creation_conflicts(self):
        self.guard.create_private_file(os.path.join(self.root, "key"), b"0" * 64)
        with self.assertRaises(OSError):
            self.guard.create_private_file(os.path.join(self.root, "key"), b"1" * 64)


if __name__ == "__main__":
    unittest.main()

import os
import shutil
import subprocess
import tempfile
import unittest

from agent_vault.guard import GuardError, platform_guard


@unittest.skipUnless(os.name == "nt", "Windows guard tests")
class WindowsGuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = platform_guard()
        parent = tempfile.mkdtemp(prefix="vault-guard-win-")
        self.addCleanup(shutil.rmtree, parent, True)
        self.root = self.guard.ensure_private_directory(os.path.join(parent, "private"), create=True)

    def _private_dir(self):
        return self.guard.ensure_private_directory(
            os.path.join(self.root, "data"), create=True)

    def test_private_directory_and_file_pass(self):
        directory = self._private_dir()
        path = self.guard.create_private_file(
            os.path.join(directory, "execution.key"), b"0" * 64)
        self.assertEqual(self.guard.check_file(path), os.path.abspath(path))
        self.assertEqual(self.guard.check_directory(directory),
                         os.path.abspath(directory))

    def test_binary_creation_preserves_newlines_and_all_byte_values(self):
        directory = self._private_dir()
        payload = bytes(range(256)) * 4 + b"\n\r\n\x00\x1a\n"
        path = self.guard.create_private_file(os.path.join(directory, "binary.key"), payload)
        with open(path, "rb") as stream:
            self.assertEqual(stream.read(), payload)
        with self.assertRaises(FileExistsError):
            self.guard.create_private_file(path, b"replacement")

    def test_current_user_is_owner(self):
        from agent_vault.platform import win_guard
        directory = self._private_dir()
        self.assertEqual(win_guard.current_user_sid(),
                         win_guard.current_user_sid())  # stable within process
        # The default profile-inherited ACL must pass the broad-grant check.
        self.guard.check_directory(directory)

    def test_everyone_grant_rejected(self):
        directory = self._private_dir()
        path = self.guard.create_private_file(
            os.path.join(directory, "execution.key"), b"0" * 64)
        grant = subprocess.run(
            ["icacls", path, "/grant", "*S-1-1-0:(R)"],
            capture_output=True, text=True)
        self.assertEqual(grant.returncode, 0, grant.stderr)
        with self.assertRaisesRegex(GuardError, "broad_grant_rejected"):
            self.guard.check_file(path)

    def test_authenticated_users_grant_rejected(self):
        directory = self._private_dir()
        path = self.guard.create_private_file(
            os.path.join(directory, "execution.key"), b"0" * 64)
        grant = subprocess.run(
            ["icacls", path, "/grant", "*S-1-5-11:(R)"],
            capture_output=True, text=True)
        self.assertEqual(grant.returncode, 0, grant.stderr)
        with self.assertRaisesRegex(GuardError, "broad_grant_rejected"):
            self.guard.check_file(path)

    def test_junction_rejected_as_reparse_point(self):
        target = self._private_dir()
        link = os.path.join(self.root, "junction")
        make = subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                              capture_output=True, text=True)
        if make.returncode != 0:
            self.skipTest(f"junction creation unavailable: {make.stderr.strip()}")
        self.addCleanup(lambda: os.path.exists(link) and os.rmdir(link))
        with self.assertRaisesRegex(GuardError, "reparse_point_rejected"):
            self.guard.check_directory(link)

    def test_missing_and_conflicting_paths(self):
        with self.assertRaisesRegex(GuardError, "file_missing"):
            self.guard.check_file(os.path.join(self.root, "absent.key"))
        path = self.guard.create_private_file(
            os.path.join(self.root, "key"), b"0" * 64)
        with self.assertRaises(OSError):
            self.guard.create_private_file(path, b"1" * 64)


@unittest.skipUnless(os.name == "nt", "DPAPI tests")
class DpapiTests(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        from agent_vault.platform import dpapi
        from agent_vault.guard import GuardError
        payload = b"session-token-material"
        protected = dpapi.protect(payload)
        self.assertNotIn(payload, protected)
        self.assertEqual(dpapi.unprotect(protected), payload)
        corrupted = bytearray(protected)
        corrupted[len(corrupted) // 2] ^= 0xFF
        with self.assertRaisesRegex(GuardError, "dpapi_unprotect_failed"):
            dpapi.unprotect(bytes(corrupted))


if __name__ == "__main__":
    unittest.main()

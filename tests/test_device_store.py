import json
import os
from pathlib import Path
import unittest

from agent_vault.device_store import DeviceStore
from agent_vault.errors import VaultError
from helpers import cleanup, test_directory


class DeviceStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = test_directory('remembered-device-')
        self.addCleanup(cleanup, self.root)
        self.store = DeviceStore(self.root + '/data')

    def test_roundtrip_is_encrypted_and_bound_to_target(self):
        password = 'synthetic-device-password-canary'
        envelope = self.store.protect('remote', 'https://vault.example', 'synthetic-user', password)
        self.assertNotIn(password, json.dumps(envelope))
        self.assertEqual(self.store.open('remote', 'https://vault.example', envelope),
                         {'username':'synthetic-user', 'password':password})
        with self.assertRaises(VaultError):
            self.store.open('remote', 'https://other.example', envelope)
        with self.assertRaises(VaultError):
            self.store.open('local', None, envelope)

    def test_corruption_and_different_scope_fail_closed(self):
        envelope = self.store.protect('local', None, None, 'synthetic-local-password')
        with self.assertRaises(VaultError):
            self.store.open('local', None, dict(envelope, blob='invalid-base64!'))
        other = DeviceStore(self.root + '/other')
        with self.assertRaises(VaultError):
            other.open('local', None, envelope)


if __name__ == '__main__':
    unittest.main()

import base64
import os
import unittest

from agent_vault import crypto
from agent_vault.crypto import CryptoError


class CryptoTests(unittest.TestCase):
    def test_seal_unseal_roundtrip(self):
        key = os.urandom(32)
        sealed = crypto.seal(key, b"secret-payload", "test:context")
        self.assertEqual(set(sealed), {"nonce", "ciphertext", "tag"})
        for value in sealed.values():
            base64.b64decode(value, validate=True)
        self.assertEqual(crypto.unseal(key, sealed, "test:context"), b"secret-payload")

    def test_nonce_is_random_per_seal(self):
        key = os.urandom(32)
        first = crypto.seal(key, b"same", "ctx")
        second = crypto.seal(key, b"same", "ctx")
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_context_mismatch_fails_closed(self):
        key = os.urandom(32)
        sealed = crypto.seal(key, b"payload", "vault:v4:one")
        with self.assertRaisesRegex(CryptoError, "invalid_tag"):
            crypto.unseal(key, sealed, "vault:v4:other")

    def test_wrong_key_fails_closed(self):
        sealed = crypto.seal(os.urandom(32), b"payload", "ctx")
        with self.assertRaisesRegex(CryptoError, "invalid_tag"):
            crypto.unseal(os.urandom(32), sealed, "ctx")

    def test_tampered_ciphertext_fails_closed(self):
        key = os.urandom(32)
        sealed = crypto.seal(key, b"payload", "ctx")
        raw = bytearray(base64.b64decode(sealed["ciphertext"]))
        raw[0] ^= 0xFF
        sealed["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaisesRegex(CryptoError, "invalid_tag"):
            crypto.unseal(key, sealed, "ctx")

    def test_scrypt_parameters_and_determinism(self):
        self.assertEqual(crypto.SCRYPT_N, 32768)
        self.assertEqual(crypto.SCRYPT_R, 8)
        self.assertEqual(crypto.SCRYPT_P, 1)
        first = crypto.derive_key("passphrase", b"salt-16-bytes-min!")
        second = crypto.derive_key("passphrase", b"salt-16-bytes-min!")
        other = crypto.derive_key("passphrase", b"another-16-bytes")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)
        self.assertNotEqual(first, other)

    def test_invalid_arguments_rejected(self):
        with self.assertRaisesRegex(CryptoError, "invalid_kdf_arguments"):
            crypto.derive_key("x", b"short")
        with self.assertRaisesRegex(CryptoError, "invalid_key_size"):
            crypto.seal(b"too-short", b"payload", "ctx")
        sealed = crypto.seal(os.urandom(32), b"payload", "ctx")
        sealed["tag"] = "AAAA"
        with self.assertRaisesRegex(CryptoError, "invalid_sealed"):
            crypto.unseal(os.urandom(32), sealed, "ctx")


if __name__ == "__main__":
    unittest.main()

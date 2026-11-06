"""AES-256-GCM sealing and scrypt key derivation.

Port of the TypeScript core's src/crypto.ts (UNIFICATION-PLAN §4 row 1):
- scrypt N=32768, r=8, p=1, 32-byte keys;
- AES-256-GCM with a random 12-byte nonce per seal and an authenticated
  context string (AAD) that must match exactly on unseal;
- base64 nonce/ciphertext/tag fields compatible with the existing schema v4
  encrypted blobs.

Key buffers are bytearrays where callers intend to wipe them; this module
never retains key material beyond a call.
"""
from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Buffer as _Buffer

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16


class CryptoError(Exception):
    """Fixed-surface crypto failure; message never carries secret material."""


def _key_bytes(key: _Buffer) -> bytes:
    raw = bytes(key)
    if len(raw) != KEY_BYTES:
        raise CryptoError("invalid_key_size")
    return raw


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str):
        raise CryptoError("invalid_kdf_arguments")
    salt = bytes(salt)
    if len(salt) < 16:
        raise CryptoError("invalid_kdf_arguments")
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM, dklen=KEY_BYTES,
    )


def seal(key: _Buffer, plaintext: bytes, context: str) -> dict:
    """Encrypt to {nonce, ciphertext, tag} base64 fields under a domain context."""
    key_bytes = _key_bytes(key)
    if not isinstance(context, str) or not context:
        raise CryptoError("invalid_context")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError("invalid_plaintext")
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(key_bytes).encrypt(nonce, bytes(plaintext), context.encode("utf-8"))
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(sealed[:-TAG_BYTES]).decode("ascii"),
        "tag": base64.b64encode(sealed[-TAG_BYTES:]).decode("ascii"),
    }


def unseal(key: _Buffer, sealed: dict, context: str) -> bytes:
    """Decrypt a seal() result; any tampering or context mismatch fails closed."""
    key_bytes = _key_bytes(key)
    if not isinstance(context, str) or not context:
        raise CryptoError("invalid_context")
    if not isinstance(sealed, dict):
        raise CryptoError("invalid_sealed")
    try:
        nonce = base64.b64decode(sealed["nonce"], validate=True)
        ciphertext = base64.b64decode(sealed["ciphertext"], validate=True)
        tag = base64.b64decode(sealed["tag"], validate=True)
    except (KeyError, ValueError, TypeError):
        raise CryptoError("invalid_sealed") from None
    if len(nonce) != NONCE_BYTES or len(tag) != TAG_BYTES or not ciphertext:
        raise CryptoError("invalid_sealed")
    try:
        return AESGCM(key_bytes).decrypt(
            nonce, ciphertext + tag, context.encode("utf-8"))
    except InvalidTag:
        raise CryptoError("invalid_tag") from None

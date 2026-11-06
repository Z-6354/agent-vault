"""Windows DPAPI current-user protection for session/key material.

Current-user CryptProtectData with UI forbidden (flag 1), not machine-scope,
so the blob is decryptable only by the same Windows
user account on the same machine. Never returns data to tools; callers persist
the protected form only.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

from ..guard import GuardError

_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class _DataBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD),
                ("data", ctypes.POINTER(ctypes.c_ubyte))]


_crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(_DataBlob), ctypes.c_wchar_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
_crypt32.CryptProtectData.restype = wintypes.BOOL
_crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(_DataBlob), ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p

_DESCRIPTION = "agent-vault session"
_UI_FORBIDDEN = 0x1


def _blob(data: bytes) -> _DataBlob:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))


def _free(blob: _DataBlob) -> None:
    if blob.data:
        _kernel32.LocalFree(ctypes.cast(blob.data, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    """Protect bytes so only the current Windows user can unprotect them."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise GuardError("dpapi_invalid_input")
    source = _blob(bytes(data))
    output = _DataBlob()
    if not _crypt32.CryptProtectData(ctypes.byref(source), _DESCRIPTION,
                                     None, None, None, _UI_FORBIDDEN,
                                     ctypes.byref(output)):
        raise GuardError("dpapi_protect_failed")
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        _free(output)


def unprotect(protected: bytes) -> bytes:
    """Reverse protect(); fails closed on any tampering or user mismatch."""
    if not isinstance(protected, (bytes, bytearray)) or not protected:
        raise GuardError("dpapi_invalid_input")
    source = _blob(bytes(protected))
    output = _DataBlob()
    description = ctypes.c_wchar_p()
    if not _crypt32.CryptUnprotectData(ctypes.byref(source), ctypes.byref(description),
                                       None, None, None, _UI_FORBIDDEN, ctypes.byref(output)):
        raise GuardError("dpapi_unprotect_failed")
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        _free(output)
        if description:
            _kernel32.LocalFree(ctypes.cast(description, ctypes.c_void_p))

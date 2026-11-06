"""Windows private-file guard: current-user ownership, no reparse points,
no broad-grant DACL entries, exclusive private creation.

Equivalence to POSIX 0700/0600 for this product:
- owner must be the current process user (same boundary as uid check);
- reparse points (symlinks AND junctions) are rejected on every checked path;
- the DACL must not grant read/write to Everyone (S-1-1-0), Authenticated
  Users (S-1-5-11) or Builtin Users (S-1-5-32-545); SYSTEM/Administrators/
  CREATOR OWNER entries are the normal user-profile shape and are allowed;
- hardlink counts are not meaningful for Windows trust here and are not used.

Implemented with ctypes only: no pywin32 dependency.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

from ..guard import GuardError

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

SE_FILE_OBJECT = 0
OWNER_SECURITY_INFORMATION = 0x1
DACL_SECURITY_INFORMATION = 0x4
TOKEN_QUERY = 0x8
TOKEN_USER = 1
ACL_SIZE_INFORMATION = 2
ACCESS_ALLOWED_ACE_TYPE = 0
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_GENERIC_READ = 0x120089
FILE_GENERIC_WRITE = 0x120116
ERROR_SUCCESS = 0
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ACL_REVISION = 2
OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2
FILE_ALL_ACCESS_MASK = 0x1F01FF
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"

BROAD_GRANT_SIDS = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545"})

_advapi32.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                        ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
_advapi32.GetFileSecurityW.restype = wintypes.BOOL
_advapi32.GetSecurityDescriptorOwner.argtypes = [ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(wintypes.BOOL)]
_advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
_advapi32.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(wintypes.BOOL),
                                                ctypes.POINTER(ctypes.c_void_p),
                                                ctypes.POINTER(wintypes.BOOL)]
_advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
_advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                             ctypes.POINTER(wintypes.LPWSTR)]
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.HANDLE)]
_advapi32.OpenProcessToken.restype = wintypes.BOOL
_advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]
_advapi32.GetTokenInformation.restype = wintypes.BOOL
_advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                             ctypes.POINTER(ctypes.c_void_p)]
_advapi32.GetAce.restype = wintypes.BOOL
_advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        wintypes.DWORD, wintypes.DWORD]
_advapi32.GetAclInformation.restype = wintypes.BOOL
_advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
_advapi32.InitializeAcl.restype = wintypes.BOOL
_advapi32.AddAccessAllowedAceEx.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                            wintypes.DWORD, wintypes.DWORD,
                                            ctypes.c_void_p]
_advapi32.AddAccessAllowedAceEx.restype = wintypes.BOOL
_advapi32.InitializeSecurityDescriptor.argtypes = [ctypes.c_void_p, wintypes.DWORD]
_advapi32.InitializeSecurityDescriptor.restype = wintypes.BOOL
_advapi32.SetSecurityDescriptorOwner.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL]
_advapi32.SetSecurityDescriptorOwner.restype = wintypes.BOOL
_advapi32.SetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, wintypes.BOOL,
                                                ctypes.c_void_p, wintypes.BOOL]
_advapi32.SetSecurityDescriptorDacl.restype = wintypes.BOOL
_advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
_advapi32.SetFileSecurityW.restype = wintypes.BOOL
_advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
_advapi32.GetLengthSid.restype = wintypes.DWORD
_advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR,
                                             ctypes.POINTER(ctypes.c_void_p)]
_advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
_kernel32.GetFileAttributesW.restype = wintypes.DWORD


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _AceHeader(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("Size", ctypes.c_ushort)]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [("Header", _AceHeader), ("Mask", wintypes.DWORD),
                ("SidStart", wintypes.DWORD)]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD)]


def _local_free(pointer: int) -> None:
    if pointer:
        _kernel32.LocalFree(ctypes.c_void_p(pointer))


def _sid_to_string(sid: ctypes.c_void_p) -> str:
    text = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise GuardError("sid_conversion_failed")
    try:
        return text.value or ""
    finally:
        _local_free(ctypes.cast(text, ctypes.c_void_p).value)


def _security_buffer(path: str, information: int) -> ctypes.Buffer:
    """Self-relative security descriptor buffer via GetFileSecurityW.

    GetNamedSecurityInfoW/A return ERROR_INVALID_PARAMETER in some hardened
    environments; GetFileSecurityW is the compatible retrieval path.
    """
    needed = wintypes.DWORD(0)
    _advapi32.GetFileSecurityW(str(path), information, None, 0, ctypes.byref(needed))
    if needed.value == 0:
        raise GuardError("security_descriptor_unavailable")
    buffer = ctypes.create_string_buffer(needed.value)
    if not _advapi32.GetFileSecurityW(str(path), information, buffer,
                                      needed.value, ctypes.byref(needed)):
        raise GuardError("security_descriptor_unavailable")
    return buffer


def current_user_sid() -> str:
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), TOKEN_QUERY,
                                      ctypes.byref(token)):
        raise GuardError("process_token_unavailable")
    try:
        needed = wintypes.DWORD()
        _advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            raise GuardError("process_token_unavailable")
        buffer = ctypes.create_string_buffer(needed.value)
        if not _advapi32.GetTokenInformation(token, TOKEN_USER, buffer,
                                             needed.value, ctypes.byref(needed)):
            raise GuardError("process_token_unavailable")
        user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        sid = _sid_to_string(user.User.Sid)
        if not sid:
            raise GuardError("process_token_unavailable")
        return sid
    finally:
        _kernel32.CloseHandle(token)


def _string_to_sid(text: str) -> int:
    """LocalAlloc'd SID pointer; caller must _local_free it."""
    sid = ctypes.c_void_p()
    if not _advapi32.ConvertStringSidToSidW(text, ctypes.byref(sid)):
        raise GuardError("sid_conversion_failed")
    return sid.value


def _own_new_object(path: str, user_sid: str) -> None:
    """Elevated Windows tokens may default new objects to Administrators.
    Set the owner of our newly created object to the actual user SID; never
    take ownership of an unrelated existing directory or file.
    """
    sid = _string_to_sid(user_sid)
    try:
        descriptor = ctypes.create_string_buffer(64)
        if (not _advapi32.InitializeSecurityDescriptor(descriptor, 1)
                or not _advapi32.SetSecurityDescriptorOwner(descriptor, ctypes.c_void_p(sid), False)
                or not _advapi32.SetFileSecurityW(path, OWNER_SECURITY_INFORMATION, descriptor)):
            raise GuardError("owner_assignment_failed")
    finally:
        _local_free(sid)


def _harden_dacl(path: str, user_sid: str) -> None:
    """Strip broad/unknown allow ACEs and inheritance; keep the least privilege.

    Some environments (this machine included) carry Everyone grants inherited
    from the profile root. A vault directory must be private regardless of its
    parent, so creation rebuilds the DACL with exactly three allow entries —
    current user, SYSTEM, Administrators — and protects it against further
    inheritance. Deny-only semantics of removed entries are dominated by the
    resulting allow set, so the result is strictly tighter.
    """
    total = 8  # ACL header
    entries = [(user_sid, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
               (SYSTEM_SID, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
               (ADMINISTRATORS_SID, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)]
    pointers = []
    try:
        for text, _flags in entries:
            sid = _string_to_sid(text)
            pointers.append(sid)
            total += 8 + _advapi32.GetLengthSid(ctypes.c_void_p(sid))
        acl = ctypes.create_string_buffer(total)
        if not _advapi32.InitializeAcl(acl, total, ACL_REVISION):
            raise GuardError("dacl_hardening_failed")
        for sid, flags in zip(pointers, [flags for _text, flags in entries]):
            if not _advapi32.AddAccessAllowedAceEx(acl, ACL_REVISION, flags,
                                                   FILE_ALL_ACCESS_MASK,
                                                   ctypes.c_void_p(sid)):
                raise GuardError("dacl_hardening_failed")
        descriptor = ctypes.create_string_buffer(64)
        SECURITY_DESCRIPTOR_REVISION = 1
        if not _advapi32.InitializeSecurityDescriptor(descriptor,
                                                      SECURITY_DESCRIPTOR_REVISION):
            raise GuardError("dacl_hardening_failed")
        if not _advapi32.SetSecurityDescriptorDacl(descriptor, True, acl, False):
            raise GuardError("dacl_hardening_failed")
        if not _advapi32.SetFileSecurityW(str(path),
                                          DACL_SECURITY_INFORMATION |
                                          PROTECTED_DACL_SECURITY_INFORMATION,
                                          descriptor):
            raise GuardError("dacl_hardening_failed")
    finally:
        for sid in pointers:
            _local_free(sid)


def _reject_reparse(path: str) -> None:
    attributes = _kernel32.GetFileAttributesW(str(path))
    if attributes == INVALID_FILE_ATTRIBUTES:
        raise GuardError("path_unavailable")
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise GuardError("reparse_point_rejected")


def _owner_is_current_user(path: str, expected_sid: str) -> None:
    buffer = _security_buffer(path, OWNER_SECURITY_INFORMATION)
    owner = ctypes.c_void_p()
    defaulted = wintypes.BOOL()
    if not _advapi32.GetSecurityDescriptorOwner(buffer, ctypes.byref(owner),
                                                ctypes.byref(defaulted)):
        raise GuardError("security_descriptor_unavailable")
    if not owner.value or _sid_to_string(owner.value) != expected_sid:
        raise GuardError("owner_check_failed")


def _reject_broad_grants(path: str) -> None:
    buffer = _security_buffer(path, DACL_SECURITY_INFORMATION)
    present = wintypes.BOOL()
    defaulted = wintypes.BOOL()
    dacl = ctypes.c_void_p()
    if not _advapi32.GetSecurityDescriptorDacl(buffer, ctypes.byref(present),
                                               ctypes.byref(dacl),
                                               ctypes.byref(defaulted)):
        raise GuardError("security_descriptor_unavailable")
    if not present.value or not dacl.value:
        return
    size = _AclSizeInformation()
    if not _advapi32.GetAclInformation(dacl.value, ctypes.byref(size),
                                       ctypes.sizeof(size), ACL_SIZE_INFORMATION):
        raise GuardError("dacl_unreadable")
    for index in range(size.AceCount):
        ace = ctypes.c_void_p()
        if not _advapi32.GetAce(dacl.value, index, ctypes.byref(ace)):
            raise GuardError("dacl_unreadable")
        header = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents
        if header.Type != ACCESS_ALLOWED_ACE_TYPE:
            continue
        allowed = ctypes.cast(ace, ctypes.POINTER(_AccessAllowedAce)).contents
        if not allowed.Mask & (FILE_GENERIC_READ | FILE_GENERIC_WRITE):
            continue
        sid = _sid_to_string(
            ctypes.c_void_p(ace.value + _AccessAllowedAce.SidStart.offset))
        if sid in BROAD_GRANT_SIDS:
            raise GuardError("broad_grant_rejected")


class WindowsGuard:
    def __init__(self) -> None:
        self._user_sid = current_user_sid()

    def check_directory(self, path: str) -> str:
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            raise GuardError("directory_missing")
        _reject_reparse(path)
        _owner_is_current_user(path, self._user_sid)
        _reject_broad_grants(path)
        return path

    def check_file(self, path: str) -> str:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise GuardError("file_missing")
        _reject_reparse(path)
        _owner_is_current_user(path, self._user_sid)
        _reject_broad_grants(path)
        return path

    def ensure_private_directory(self, path: str, create: bool = False) -> str:
        path = os.path.abspath(path)
        if create and not os.path.exists(path):
            os.makedirs(path, mode=0o700, exist_ok=False)
            _reject_reparse(path)
            _own_new_object(path, self._user_sid)
        _reject_reparse(path)
        _owner_is_current_user(path, self._user_sid)
        # Fix the environment, then verify strictly: profile trees on this
        # machine inherit Everyone grants; the vault directory itself must
        # not. Hardening only REMOVES access, never adds any.
        _harden_dacl(path, self._user_sid)
        _reject_broad_grants(path)
        return path

    def create_private_file(self, path: str, data: bytes) -> str:
        path = os.path.abspath(path)
        parent = os.path.dirname(path)
        if not os.path.isdir(parent):
            raise GuardError("parent_directory_missing")
        self.check_directory(parent)
        # Windows CRT defaults to text mode without O_BINARY: random key
        # bytes containing LF would be translated to CRLF. Keep exclusive
        # creation and writing on one binary descriptor, with no reopen gap.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            _own_new_object(path, self._user_sid)
            self.check_file(path)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        with open(path, "rb") as stream:
            actual = stream.read()
        if actual != data:
            raise GuardError("write_verification_failed")
        return self.check_file(path)

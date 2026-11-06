"""No-echo secret input from the user's real terminal (Windows CONIN$ /
POSIX controlling terminal).

Port of the proven field implementation with one hardening fix required by
UNIFICATION-PLAN P3: disabling echo MUST succeed or input is refused — the
reader never falls back to an echoed read.
"""
from __future__ import annotations

import os


class ConsoleUnavailable(Exception):
    """No safe no-echo channel; callers must refuse the secret, not fall back."""


def read_secret(prompt_text: str, timeout_s: int = 120) -> str:
    if not isinstance(prompt_text, str) or not prompt_text or not 1 <= timeout_s <= 3600:
        raise ValueError("invalid_console_arguments")
    if os.name == "nt":
        return _read_windows(prompt_text, timeout_s)
    return _read_posix(prompt_text, timeout_s)


def _read_windows(prompt_text: str, timeout_s: int) -> str:
    import ctypes
    import msvcrt
    import time
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetConsoleMode.restype = wintypes.BOOL
    kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.SetConsoleMode.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.ReadConsoleW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                   ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.ReadConsoleW.restype = wintypes.BOOL
    try:
        descriptor = os.open("CONIN$", os.O_RDWR | os.O_BINARY)
    except OSError:
        raise ConsoleUnavailable("console_unavailable") from None
    output = None
    original = wintypes.DWORD()
    changed = False
    characters = []
    try:
        handle = msvcrt.get_osfhandle(descriptor)
        if not kernel.GetConsoleMode(handle, ctypes.byref(original)):
            raise ConsoleUnavailable("console_unavailable")
        # Character mode avoids a blocking line read after a single key event;
        # every character is preceded by a bounded wait, and echo stays off.
        if not kernel.SetConsoleMode(handle, original.value & ~(0x2 | 0x4)):
            raise ConsoleUnavailable("echo_disable_failed")
        changed = True
        output = os.open("CONOUT$", os.O_WRONLY | os.O_BINARY)
        os.write(output, (prompt_text + ": ").encode("utf-8"))
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                raise TimeoutError("console_input_timeout")
            wait = kernel.WaitForSingleObject(handle, min(remaining, 500))
            if wait == 258:
                continue
            if wait != 0:
                raise ConsoleUnavailable("console_read_failed")
            character = (wintypes.WCHAR * 1)()
            count = wintypes.DWORD()
            if not kernel.ReadConsoleW(handle, character, 1, ctypes.byref(count), None):
                raise ConsoleUnavailable("console_read_failed")
            if not count.value:
                continue
            value = character[0]
            if value in ("\r", "\n"):
                break
            if value == "\x03":
                raise KeyboardInterrupt
            if value in ("\x08", "\x7f"):
                if characters:
                    last = characters.pop()
                    if 0xDC00 <= ord(last) <= 0xDFFF and characters:
                        characters.pop()
            elif value != "\x00":
                characters.append(value)
        os.write(output, b"\r\n")
        return "".join(characters).encode("utf-16-le", "surrogatepass").decode("utf-16-le")
    finally:
        if changed:
            kernel.SetConsoleMode(msvcrt.get_osfhandle(descriptor), original.value)
        if output is not None:
            os.close(output)
        os.close(descriptor)


def _read_posix(prompt_text: str, timeout_s: int) -> str:
    import select
    import termios
    import time

    try:
        descriptor = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        raise ConsoleUnavailable("console_unavailable") from None
    line = bytearray()
    try:
        saved = termios.tcgetattr(descriptor)
        try:
            termios.tcsetattr(descriptor, termios.TCSAFLUSH,
                              saved[:3] + [saved[3] & ~termios.ECHO] + saved[4:])
        except termios.error:
            raise ConsoleUnavailable("echo_disable_failed") from None
        try:
            os.write(descriptor, (prompt_text + ": ").encode(errors="replace"))
            deadline = time.monotonic() + timeout_s
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("console_input_timeout")
                if not select.select([descriptor], [], [], remaining)[0]:
                    raise TimeoutError("console_input_timeout")
                byte = os.read(descriptor, 1)
                if not byte or byte in (b"\r", b"\n"):
                    break
                if byte == b"\x03":
                    raise KeyboardInterrupt
                if byte in (b"\x7f", b"\x08"):
                    if line:
                        line.pop()
                else:
                    line.extend(byte)
            os.write(descriptor, b"\n")
        finally:
            termios.tcsetattr(descriptor, termios.TCSADRAIN, saved)
    finally:
        os.close(descriptor)
    return line.decode("utf-8")

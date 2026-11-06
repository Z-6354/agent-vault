"""Real POSIX controlling-terminal tests with synthetic secrets only."""
import os
import select
import subprocess
import sys
import time
import unittest


@unittest.skipUnless(os.name == "posix", "POSIX controlling terminal")
class ConsolePTYTests(unittest.TestCase):
    def run_terminal(self, source, text):
        import pty
        master, slave = pty.openpty()
        program = """import fcntl, os, termios
os.setsid()
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
from agent_vault.console import read_secret
""" + source
        child = subprocess.Popen([sys.executable, "-B", "-c", program], stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = bytearray()
        try:
            deadline = time.monotonic() + 8
            while b"Prompt: " not in output:
                if time.monotonic() >= deadline:
                    self.fail("terminal prompt did not appear")
                if select.select([master], [], [], .1)[0]:
                    output.extend(os.read(master, 4096))
            if text is not None:
                os.write(master, text)
            while time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try:
                        output.extend(os.read(master, 4096))
                    except OSError:
                        break
                if child.poll() is not None:
                    break
            child.wait(timeout=2)
            return child.returncode, bytes(output)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(2)
            os.close(master)

    def test_no_echo_preserves_spaces_and_unicode(self):
        code, output = self.run_terminal(
            "value=read_secret('Prompt', 3)\nprint('EXACT' if value==' synthetic-秘密 ' else 'WRONG')\n",
            " synthetic-秘密 \n".encode())
        self.assertEqual(code, 0)
        self.assertIn(b"EXACT", output)
        self.assertNotIn("synthetic-秘密".encode(), output, "secret must not echo to terminal")

    def test_terminal_input_has_a_deadline(self):
        code, output = self.run_terminal(
            "try: read_secret('Prompt', 1)\nexcept TimeoutError: print('BOUNDED')\n", None)
        self.assertEqual(code, 0)
        self.assertIn(b"BOUNDED", output)

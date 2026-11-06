# Contributing

Python 3.12+ is required. Use a private virtual environment; do not install dependencies into a managed Agent host's interpreter.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -B -W error::ResourceWarning -m unittest discover -s tests -v
.venv/bin/python -B scripts/acceptance.py
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -B -W error::ResourceWarning -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -B scripts\acceptance.py
```

Browser acceptance uses an isolated synthetic backend and browser profile. It requires Node.js 22+ and Chrome/Edge/Chromium:

```bash
python -B scripts/browser_acceptance.py
```

Set `VAULT_TEST_BROWSER` to a browser executable when automatic discovery is unavailable. Never test credential handling by printing a real secret. Do not open production device-memory files, databases or credentials stores for documentation checks.

When changing a transport, test the actual CLI/stdio/HTTP boundary, successful and failed paths, and resource cleanup. A passed unit test does not establish that a running host loaded the new source. Do not replay a state-changing request after an ambiguous network failure.

CI validates installed packages on Windows, Linux and macOS. Skipped OS-specific tests must remain distinguished from passing tests. Update the Chinese and English user guides together when commands change.

See [AGENTS.md](AGENTS.md) for tool and project boundaries and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

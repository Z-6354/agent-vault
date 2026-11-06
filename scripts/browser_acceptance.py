"""Isolated real browser harness. No production vault or login data is used.
Requires Chrome/Edge and Node with WebSocket support. Captures empty/synthetic UI.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]
from agent_vault.broker import Broker
from agent_vault.ipc import CoreClient
from agent_vault.mcp_server import McpServer
from test_broker import RemoteFixture
from helpers import cleanup, test_directory


def main():
    browser_path = os.environ.get('VAULT_TEST_BROWSER') or next((str(p) for p in [
        Path('C:/Program Files/Google/Chrome/Application/chrome.exe'),
        Path('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe')]
        if p.exists()), None) or shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('chromium-browser')
    node = shutil.which('node')
    if not browser_path or not node:
        raise SystemExit('Set VAULT_TEST_BROWSER and provide Node for browser acceptance.')
    root = test_directory('browser-acceptance-')
    evidence = ROOT.parent / 'browser-evidence'
    evidence.mkdir(exist_ok=True)
    remote = RemoteFixture()
    broker = Broker(root + '/data', 0, allow_loopback_http=True)
    server = broker.build_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = CoreClient(root + '/data', broker.port)
    mcp = McpServer(client, agent_id='browser-test')
    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def serve(self):
            nonlocal broker, server, thread
            if self.path == '/restart':
                port = broker.port
                server.shutdown()
                server.server_close()
                thread.join(3)
                broker = Broker(root + '/data', port, allow_loopback_http=True)
                server = broker.build_server()
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                result = mcp.call_tool('vault_status', {})
            elif self.path.startswith('/result'):
                identifier = parse_qs(urlsplit(self.path).query)['id'][0]
                result = mcp.call_tool('vault_result', {'request_id':identifier})
            else:
                result = mcp.call_tool('vault_begin_enrollment', {'service':'deepseek-api','account':'main'})
            data = result['content'][0]['text'].encode()
            self.send_response(200)
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        do_GET=serve
        do_POST=serve
    fixture = ThreadingHTTPServer(('127.0.0.1',0), Fixture)
    fixture_thread=threading.Thread(target=fixture.serve_forever,daemon=True)
    fixture_thread.start()
    browser = None
    try:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1',0))
            debug_port=reserve.getsockname()[1]
        browser_args = [browser_path, '--headless=new', '--no-first-run', '--no-default-browser-check',
            '--remote-debugging-address=127.0.0.1', f'--remote-debugging-port={debug_port}',
            '--user-data-dir='+root+'/browser-profile', 'about:blank']
        if os.name == 'posix' and (os.geteuid() == 0 or os.environ.get('VAULT_TEST_NO_SANDBOX') == '1'):
            # Only the isolated synthetic test browser, never production UI.
            browser_args.insert(1, '--no-sandbox')
        browser=subprocess.Popen(browser_args,
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        result=subprocess.run([node,str(ROOT/'scripts/browser-acceptance.cjs'),str(debug_port),client.url,
            remote.url,str(evidence),f'http://127.0.0.1:{fixture.server_port}'],timeout=80)
        return result.returncode
    finally:
        if browser:
            browser.terminate()
            browser.wait(10)
        server.shutdown()
        server.server_close()
        thread.join(3)
        fixture.shutdown()
        fixture.server_close()
        fixture_thread.join(3)
        broker.core.logout()
        remote.close()
        cleanup(root)


if __name__=='__main__':
    raise SystemExit(main())

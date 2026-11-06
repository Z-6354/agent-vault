import io
import json
import socket
import ssl
import unittest
from unittest.mock import patch
import urllib.error

from agent_vault.errors import VaultError
from agent_vault.remote import Remote, normalize_url


class Response(io.BytesIO):
    def __init__(self, code, value):
        super().__init__(json.dumps(value).encode())
        self.code = code


class RemoteTests(unittest.TestCase):
    def test_connection_errors_are_specific_and_never_echo_reason(self):
        cases = [(socket.gaierror('secret-dns-reason'), 'dns_failed'),
                 (TimeoutError('secret-timeout-reason'), 'connection_timeout'),
                 (ConnectionRefusedError('secret-refused-reason'), 'connection_refused'),
                 (ssl.SSLError('secret-tls-reason'), 'tls_failed'),
                 (OSError('secret-other-reason'), 'network_unavailable')]
        for reason, expected in cases:
            remote = Remote('https://vault.example')
            with patch.object(remote.opener, 'open', side_effect=urllib.error.URLError(reason)):
                with self.assertRaises(VaultError) as raised:
                    remote.probe()
                self.assertEqual(raised.exception.code, expected)
                self.assertNotIn('secret-', str(raised.exception))

    def test_http_errors_are_not_missing_database(self):
        for code in (401, 403, 404, 500):
            remote = Remote('https://vault.example')
            error = urllib.error.HTTPError('https://vault.example', code, 'secret-error', {}, io.BytesIO(b'secret-body'))
            with patch.object(remote.opener, 'open', side_effect=error):
                with self.assertRaisesRegex(VaultError, 'vault_service_not_verified'):
                    remote.probe()
            self.assertEqual(remote.initialization, 'unknown')

    def test_url_normalization_rejects_plain_http_credentials_query_and_fragments(self):
        self.assertEqual(normalize_url('https://vault.example/prefix/'), 'https://vault.example/prefix')
        for url in ('http://vault.example', 'https://u:p@vault.example', 'https://vault.example?token=x',
                    'https://vault.example/#fragment', 'file:///etc/passwd', 'https://vault.example:99999',
                    'https://vault.example/../other'):
            with self.assertRaises(VaultError):
                normalize_url(url)

    def test_no_login_success_from_an_arbitrary_200(self):
        remote = Remote('https://vault.example')
        with patch.object(remote.opener, 'open', return_value=Response(200, {'status':'error'})):
            with self.assertRaisesRegex(VaultError, 'login_unconfirmed'):
                remote.login('synthetic-user', 'synthetic-password')
        self.assertFalse(remote.authenticated)

    def test_advertised_setup_contract_is_required_and_auth_confirmed(self):
        remote = Remote('https://vault.example')
        paths = {p:{} for p in ['/api/v1/auth/login','/api/v1/auth/status','/api/v1/credentials','/api/v1/setup/status']}
        paths['/api/v1/setup']={'post':{'requestBody':{'content':{'application/json':{'schema':{
            'type':'object', 'required':['username','password'], 'properties':{'username':{'type':'string'},'password':{'type':'string'}}}}}}}}
        replies=[Response(200,{'paths':paths}),Response(200,{'initialized':False}),
                 Response(201,{}),Response(200,{'token':'synthetic-token-session'}),Response(200,{'status':'connected'})]
        with patch.object(remote.opener, 'open', side_effect=replies):
            self.assertTrue(remote.probe()['creation_supported'])
            remote.create('synthetic-user','synthetic-password','synthetic-password')
            self.assertTrue(remote.authenticated)


if __name__=='__main__':
    unittest.main()

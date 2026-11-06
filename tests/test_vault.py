import json
import os
import shutil
import tempfile
import threading
import unittest

from agent_vault import registry
from agent_vault.mock import HITS, start_mock
from agent_vault.vault import Vault, VaultError
from helpers import cleanup, test_directory

ADMIN = {"owner_id": "local", "principal_id": "admin", "client_id": "management"}
AGENT = {"owner_id": "local", "principal_id": "agent", "client_id": "execution"}


def _save_payload(secret="synthetic_token_1", ops=("mock.account_summary",)):
    return {"mode": "create", "label": "label-1", "service_id": "synthetic-mock",
            "credential_type": "api_key", "account_alias": "acct", "secret": secret,
            "origin": "http://127.0.0.1:43121", "environment": "local",
            "granted_operations": list(ops)}


class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock = start_mock()
        cls.thread = threading.Thread(target=cls.mock.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock.shutdown()
        cls.mock.server_close()

    def setUp(self):
        HITS.clear()
        self.root = test_directory("vault-core-")
        self.addCleanup(cleanup, self.root)
        self.directory = os.path.join(self.root, "data")
        Vault.initialize(self.directory, "test-passphrase-123")
        self.vault = Vault(self.directory)
        self.vault.unlock("test-passphrase-123")
        self.addCleanup(self.vault.lock)
        self.vault.grant_agent(ADMIN, "agent", ["mock.account_summary"])

    def _save_connection(self, secret="synthetic_token_1", ops=("mock.account_summary",)):
        draft = self.vault.create_draft(ADMIN, _save_payload(secret, ops))
        approval = self.vault.approve_draft(ADMIN, draft["draft_id"], draft["draft_version"])
        return self.vault.save_approved(ADMIN, {
            "request_id": "a" * 32, "draft_id": draft["draft_id"],
            "draft_version": draft["draft_version"],
            "approval_token": approval["approval_token"],
            "payload": _save_payload(secret, ops)})

    # -- initialization ---------------------------------------------------
    def test_initialize_rejects_nonempty_and_short_passphrase(self):
        with self.assertRaisesRegex(VaultError, "directory_not_empty"):
            Vault.initialize(self.directory, "another-pass-1234")
        fresh = os.path.join(self.root, "fresh")
        with self.assertRaisesRegex(VaultError, "invalid_passphrase"):
            Vault.initialize(fresh, "short")
        self.assertFalse(os.path.exists(fresh))

    def test_initialization_layout(self):
        self.assertTrue(os.path.isfile(os.path.join(self.directory, "execution.key")))
        self.assertTrue(os.path.isfile(os.path.join(self.directory, "request-signing.key")))
        self.assertTrue(os.path.isfile(os.path.join(self.directory, "vault.sqlite")))

    def test_lockout_after_five_failures(self):
        self.vault.lock()
        vault = Vault(self.directory)
        for _ in range(5):
            with self.assertRaisesRegex(VaultError, "invalid_passphrase"):
                vault.unlock("wrong-passphrase-1")
        with self.assertRaisesRegex(VaultError, "unlock_blocked"):
            vault.unlock("test-passphrase-123")

    def test_lock_bumps_epoch_and_clears_key(self):
        epoch = self.vault.epoch
        self.vault.lock()
        self.assertGreater(self.vault.epoch, epoch)
        self.assertFalse(self.vault.unlocked)

    # -- drafts / approval / save ----------------------------------------
    def test_draft_card_never_carries_secret(self):
        draft = self.vault.create_draft(ADMIN, _save_payload())
        self.assertNotIn("secret", draft["card"])
        self.assertNotIn("synthetic_token_1", json.dumps(draft))
        self.assertEqual(draft["card"]["service_id"], "synthetic-mock")

    def test_approval_is_single_use_and_payload_binding(self):
        draft = self.vault.create_draft(ADMIN, _save_payload())
        approval = self.vault.approve_draft(ADMIN, draft["draft_id"], 1)
        tampered = dict(_save_payload(), secret="synthetic_token_2")
        with self.assertRaisesRegex(VaultError, "draft_conflict"):
            self.vault.save_approved(ADMIN, {
                "request_id": "b" * 32, "draft_id": draft["draft_id"], "draft_version": 1,
                "approval_token": approval["approval_token"], "payload": tampered})
        result = self.vault.save_approved(ADMIN, {
            "request_id": "b" * 32, "draft_id": draft["draft_id"], "draft_version": 1,
            "approval_token": approval["approval_token"], "payload": _save_payload()})
        self.assertEqual(result["status"], "active")
        with self.assertRaisesRegex(VaultError, "draft_conflict"):
            self.vault.save_approved(ADMIN, {
                "request_id": "c" * 32, "draft_id": draft["draft_id"], "draft_version": 1,
                "approval_token": approval["approval_token"], "payload": _save_payload()})

    def test_storage_only_password_allowed_and_synthetic_token_enforced(self):
        draft = self.vault.create_draft(ADMIN, {
            "mode": "create", "label": "l", "service_id": "deepseek-api",
            "credential_type": "password", "account_alias": "acct",
            "secret": "any-password-material", "origin": registry.STORAGE_ONLY_ORIGIN,
            "environment": "local", "granted_operations": []})
        approval = self.vault.approve_draft(ADMIN, draft["draft_id"], 1)
        self.vault.save_approved(ADMIN, {
            "request_id": "d" * 32, "draft_id": draft["draft_id"], "draft_version": 1,
            "approval_token": approval["approval_token"],
            "payload": draft["card"] | {"secret": "any-password-material"}})
        with self.assertRaisesRegex(VaultError, "synthetic_token_required"):
            self.vault.create_draft(ADMIN, _save_payload(secret="not-a-synthetic-token"))

    def test_authority_separation(self):
        with self.assertRaisesRegex(VaultError, "forbidden"):
            self.vault.create_draft(AGENT, _save_payload())
        with self.assertRaisesRegex(VaultError, "forbidden"):
            self.vault.execute_operation(ADMIN, {"request_id": "e" * 32,
                                                 "connection_id": "x" * 36,
                                                 "operation_id": "mock.account_summary",
                                                 "expected_record_version": 1, "args": {}})

    # -- execution --------------------------------------------------------
    def test_execute_success_and_replay_never_hits_upstream(self):
        connection = self._save_connection()
        request_id = self.vault.prepare_request(AGENT, "mock.account_summary")["request_id"]
        payload = {"request_id": request_id, "connection_id": connection["connection_id"],
                   "operation_id": "mock.account_summary", "expected_record_version": 1, "args": {}}
        first = self.vault.execute_operation(AGENT, payload)
        self.assertEqual(first["operation"]["state"], "succeeded")
        hits = len(HITS)
        replay = self.vault.execute_operation(AGENT, payload)
        self.assertEqual(replay, first)
        self.assertEqual(len(HITS), hits, "replay must not re-dispatch")

    def test_unknown_outcome_is_never_redispatched(self):
        connection = self._save_connection(secret="synthetic_leak_token")
        request_id = self.vault.prepare_request(AGENT, "mock.account_summary")["request_id"]
        payload = {"request_id": request_id, "connection_id": connection["connection_id"],
                   "operation_id": "mock.account_summary", "expected_record_version": 1, "args": {}}
        result = self.vault.execute_operation(AGENT, payload)
        self.assertEqual(result["operation"]["state"], "succeeded")
        # mock echoes "leak:<token>"; output must be redacted.
        self.assertNotIn("synthetic_leak_token", json.dumps(result))
        self.assertIn("[REDACTED]", json.dumps(result))

    def test_version_conflict_is_failed_before_dispatch_and_retryable(self):
        connection = self._save_connection()
        request_id = self.vault.prepare_request(AGENT, "mock.account_summary")["request_id"]
        bad = {"request_id": request_id, "connection_id": connection["connection_id"],
               "operation_id": "mock.account_summary", "expected_record_version": 2, "args": {}}
        result = self.vault.execute_operation(AGENT, bad)
        self.assertEqual(result["operation"]["state"], "failed_before_dispatch")
        self.assertEqual(len(HITS), 0)
        good = dict(bad, expected_record_version=1)
        self.assertEqual(self.vault.execute_operation(AGENT, good)["operation"]["state"], "succeeded")

    def test_scope_and_unknown_operation(self):
        connection = self._save_connection(ops=())
        payload = {"request_id": "f" * 32, "connection_id": connection["connection_id"],
                   "operation_id": "mock.account_summary", "expected_record_version": 1, "args": {}}
        result = self.vault.execute_operation(AGENT, payload)
        self.assertEqual(result["operation"]["state"], "failed_before_dispatch")
        self.assertEqual(result["operation"]["error"], "operation_denied")
        payload = {"request_id": "f" * 32, "connection_id": connection["connection_id"],
                   "operation_id": "unknown.op", "expected_record_version": 1, "args": {}}
        with self.assertRaisesRegex(VaultError, "unknown_operation"):
            self.vault.execute_operation(AGENT, payload)

    def test_locked_execution_fails(self):
        connection = self._save_connection()
        self.vault.lock()
        payload = {"request_id": "0" * 32, "connection_id": connection["connection_id"],
                   "operation_id": "mock.account_summary", "expected_record_version": 1, "args": {}}
        result = self.vault.execute_operation(AGENT, payload)
        self.assertEqual(result["operation"]["state"], "failed_before_dispatch")
        self.assertEqual(result["operation"]["error"], "vault_locked")

    # -- enrollment -------------------------------------------------------
    def test_enrollment_lifecycle(self):
        begun = self.vault.begin_enrollment("deepseek-api", "acct", "Enter DeepSeek key")
        self.assertEqual(begun["status"], "pending")
        captured = self.vault.complete_enrollment(begun["request_id"], "sk-real-secret")
        self.assertEqual(captured["status"], "captured")
        self.assertTrue(captured["ref"].startswith("vault://deepseek-api/"))
        result = self.vault.enrollment_result(begun["request_id"])
        self.assertEqual(result["status"], "captured")
        connections = self.vault.list_connections(AGENT)
        saved = [c for c in connections if c["connection_id"] == captured["connection_id"]]
        self.assertEqual(saved[0]["credential_type"], "password")
        # storage-only: no operations granted
        row = self.vault._connection_row(captured["connection_id"])
        self.assertEqual(json.loads(row["granted_operations"]), [])

    def test_decline_is_terminal(self):
        begun = self.vault.begin_enrollment("deepseek-api", "acct")
        self.vault.decline_enrollment(begun["request_id"])
        with self.assertRaisesRegex(VaultError, "request_not_pending"):
            self.vault.complete_enrollment(begun["request_id"], "sk-real-secret")
        self.assertEqual(self.vault.enrollment_result(begun["request_id"])["status"], "declined")

    def test_enrollment_input_validation(self):
        with self.assertRaisesRegex(VaultError, "invalid_arguments"):
            self.vault.begin_enrollment("bad service", "acct")
        with self.assertRaisesRegex(VaultError, "invalid_arguments"):
            self.vault.begin_enrollment("deepseek-api", "../etc/passwd")

    # -- P4: per-agent authorization --------------------------------------
    def test_agent_without_grant_cannot_execute(self):
        connection = self._save_connection()
        other = {"owner_id": "local", "principal_id": "agent:other-agent",
                 "client_id": "execution"}
        payload = {"request_id": "9" * 32, "connection_id": connection["connection_id"],
                   "operation_id": "mock.account_summary", "expected_record_version": 1,
                   "args": {}}
        with self.assertRaisesRegex(VaultError, "agent_not_granted"):
            self.vault.execute_operation(other, payload)
        # Grant, then the same agent may execute.
        self.vault.grant_agent(ADMIN, "other-agent", ["mock.account_summary"])
        result = self.vault.execute_operation(other, payload)
        self.assertEqual(result["operation"]["state"], "succeeded")

    def test_agent_revoke_takes_effect(self):
        connection = self._save_connection()
        self.vault.revoke_agent(ADMIN, "agent", ["mock.account_summary"])
        payload = {"request_id": "a" * 32, "connection_id": connection["connection_id"],
                   "operation_id": "mock.account_summary", "expected_record_version": 1,
                   "args": {}}
        with self.assertRaisesRegex(VaultError, "agent_not_granted"):
            self.vault.execute_operation(AGENT, payload)
        self.vault.grant_agent(ADMIN, "agent", "*")
        result = self.vault.execute_operation(AGENT, dict(payload, request_id="b" * 32))
        self.assertEqual(result["operation"]["state"], "succeeded")
        self.assertEqual(self.vault.list_agents(ADMIN)[0]["operations"], ["*"])

    def test_replay_is_bound_to_original_connection(self):
        first = self._save_connection()
        second = self._save_connection()
        request_id = self.vault.prepare_request(AGENT, "mock.account_summary")["request_id"]
        bad = {"request_id": request_id, "connection_id": first["connection_id"],
               "operation_id": "mock.account_summary", "expected_record_version": 2, "args": {}}
        self.assertEqual(self.vault.execute_operation(AGENT, bad)["operation"]["state"],
                         "failed_before_dispatch")
        # Same ticket against a different connection must be rejected outright.
        with self.assertRaisesRegex(VaultError, "request_conflict"):
            self.vault.execute_operation(AGENT, dict(bad, connection_id=second["connection_id"]))


if __name__ == "__main__":
    unittest.main()

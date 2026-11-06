"""Core self-healing: a dead core is transparently respawned on next use."""
import threading
import unittest

import agent_vault.broker as broker_module
from agent_vault.broker import Broker
from agent_vault.ipc import CoreClient
from helpers import cleanup, test_directory


class SelfHealTests(unittest.TestCase):
    def setUp(self):
        self.root = test_directory("selfheal-")
        self.addCleanup(cleanup, self.root)
        self.directory = self.root + "/data"
        self.broker = Broker(self.directory, 0)
        self.server = self.broker.build_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._teardown)
        self.client = CoreClient(self.directory, self.broker.port)

    def _teardown(self):
        # Terminate any core process respawned by the self-healing client.
        for child in broker_module._CHILDREN:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(5)
                except Exception:
                    child.kill()
        broker_module._CHILDREN.clear()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def test_client_respawns_dead_core(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        state = self.client.command("status", {})
        # A fresh core with no saved target starts at target selection.
        self.assertEqual(state["phase"], "needs_target", "client must respawn the core transparently")
        # The respawned core must answer subsequent commands too.
        self.assertEqual(self.client.command("status", {})["phase"], "needs_target")

    def test_health_check_survives_healthy_core(self):
        self.assertTrue(self.client.verify())
        self.assertEqual(self.client.command("status", {})["phase"], "needs_target")


if __name__ == "__main__":
    unittest.main()

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mimosa.web.config import FirewallConfigStore


class FirewallConfigStoreEnvTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env_backup = os.environ.copy()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_seeds_config_from_initial_firewall_variables(self) -> None:
        os.environ.update(
            {
                "INITIAL_FIREWALL_NAME": "seeded-fw",
                "INITIAL_FIREWALL_TYPE": "opnsense",
                "INITIAL_FIREWALL_BASE_URL": "https://fw.example",
                "INITIAL_FIREWALL_API_KEY": "api-key",
                "INITIAL_FIREWALL_API_SECRET": "api-secret",
                "INITIAL_FIREWALL_ALIAS_NAME": "custom_alias",
                "INITIAL_FIREWALL_VERIFY_SSL": "false",
                "INITIAL_FIREWALL_TIMEOUT": "8",
                "INITIAL_FIREWALL_APPLY_CHANGES": "0",
            }
        )

        with TemporaryDirectory() as tmp:
            store = FirewallConfigStore(path=Path(tmp) / "firewalls.json")

            configs = store.list()
            self.assertEqual(len(configs), 1)

            cfg = configs[0]
            self.assertEqual(cfg.name, "seeded-fw")
            self.assertEqual(cfg.type, "opnsense")
            self.assertEqual(cfg.base_url, "https://fw.example")
            self.assertEqual(cfg.api_key, "api-key")
            self.assertEqual(cfg.api_secret, "api-secret")
            self.assertEqual(cfg.alias_name, "custom_alias")
            self.assertFalse(cfg.verify_ssl)
            self.assertEqual(cfg.timeout, 8)
            self.assertFalse(cfg.apply_changes)

    def test_seeds_config_with_defaults(self) -> None:
        os.environ.update(
            {
                "INITIAL_FIREWALL_NAME": "seeded-fw",
                "REQUEST_TIMEOUT": "15",
            }
        )

        with TemporaryDirectory() as tmp:
            store = FirewallConfigStore(path=Path(tmp) / "firewalls.json")

            configs = store.list()
            self.assertEqual(len(configs), 1)

            cfg = configs[0]
            self.assertEqual(cfg.type, "pfsense")
            self.assertIsNone(cfg.base_url)
            self.assertIsNone(cfg.api_key)
            self.assertIsNone(cfg.api_secret)
            self.assertEqual(cfg.alias_name, "mimosa_blocklist")
            self.assertTrue(cfg.verify_ssl)
            self.assertEqual(cfg.timeout, 15)
            self.assertTrue(cfg.apply_changes)


if __name__ == "__main__":
    unittest.main()

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

    def test_seeds_config_from_mimosa_variables(self) -> None:
        os.environ.update(
            {
                "MIMOSA_FIREWALL_NAME": "seeded-fw",
                "MIMOSA_FIREWALL_TYPE": "opnsense",
                "MIMOSA_FIREWALL_BASE_URL": "https://fw.example",
                "MIMOSA_FIREWALL_API_KEY": "api-key",
                "MIMOSA_FIREWALL_API_SECRET": "api-secret",
                "MIMOSA_FIREWALL_ALIAS_NAME": "custom_alias",
                "MIMOSA_FIREWALL_VERIFY_SSL": "false",
                "MIMOSA_FIREWALL_TIMEOUT": "8",
                "MIMOSA_FIREWALL_APPLY_CHANGES": "0",
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

    def test_seeds_config_falling_back_to_pfsense_variables(self) -> None:
        os.environ.update(
            {
                "MIMOSA_FIREWALL_NAME": "seeded-fw",
                "PFSENSE_BASE_URL": "https://fw.example",
                "PFSENSE_API_KEY": "legacy-key",
                "PFSENSE_API_SECRET": "legacy-secret",
                "PFSENSE_ALIAS_NAME": "legacy_alias",
                "VERIFY_FIREWALL_SSL": "true",
                "REQUEST_TIMEOUT": "15",
            }
        )

        with TemporaryDirectory() as tmp:
            store = FirewallConfigStore(path=Path(tmp) / "firewalls.json")

            configs = store.list()
            self.assertEqual(len(configs), 1)

            cfg = configs[0]
            self.assertEqual(cfg.type, "pfsense")
            self.assertEqual(cfg.base_url, "https://fw.example")
            self.assertEqual(cfg.api_key, "legacy-key")
            self.assertEqual(cfg.api_secret, "legacy-secret")
            self.assertEqual(cfg.alias_name, "legacy_alias")
            self.assertTrue(cfg.verify_ssl)
            self.assertEqual(cfg.timeout, 15)
            self.assertTrue(cfg.apply_changes)


if __name__ == "__main__":
    unittest.main()

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mimosa.web.config import FirewallConfig, FirewallConfigStore


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
            self.assertFalse(cfg.verify_ssl)
            self.assertEqual(cfg.timeout, 8)
            self.assertFalse(cfg.apply_changes)

    def test_seeds_config_with_defaults(self) -> None:
        for key in list(os.environ):
            if key.startswith("INITIAL_FIREWALL_"):
                os.environ.pop(key, None)
        os.environ.update(
            {
                "INITIAL_FIREWALL_NAME": "seeded-fw",
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
            self.assertTrue(cfg.verify_ssl)
            self.assertEqual(cfg.timeout, 15)
            self.assertTrue(cfg.apply_changes)

    def test_does_not_seed_when_configs_already_exist(self) -> None:
        seed_env = {"INITIAL_FIREWALL_NAME": "seeded-fw"}

        with TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "firewalls.json"

            os.environ.pop("INITIAL_FIREWALL_NAME", None)

            existing = FirewallConfigStore(path=store_path)
            existing.add(
                FirewallConfig.new(
                    name="existing-fw",
                    type="opnsense",
                    base_url="https://fw.local",
                    api_key="key",
                    api_secret="secret",
                    verify_ssl=False,
                    timeout=7,
                    apply_changes=False,
                )
            )

            os.environ.update(seed_env)
            reloaded = FirewallConfigStore(path=store_path)
            configs = reloaded.list()

            self.assertEqual(len(configs), 1)
            cfg = configs[0]
            self.assertEqual(cfg.name, "existing-fw")
            self.assertFalse(cfg.verify_ssl)
            self.assertEqual(cfg.timeout, 7)


if __name__ == "__main__":
    unittest.main()

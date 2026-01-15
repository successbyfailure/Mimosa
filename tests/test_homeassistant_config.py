import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mimosa.core.homeassistant_config import HomeAssistantConfigStore


class HomeAssistantConfigStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env_backup = os.environ.copy()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_seeds_from_env(self) -> None:
        os.environ.update(
            {
                "HOMEASSISTANT_ENABLED": "true",
                "HOMEASSISTANT_TOKEN": "seeded-token",
            }
        )
        with TemporaryDirectory() as tmp:
            store = HomeAssistantConfigStore(db_path=Path(tmp) / "mimosa.db")
            config = store.get_config()
            self.assertTrue(config.enabled)
            self.assertEqual(config.api_token, "seeded-token")

    def test_update_client_state(self) -> None:
        with TemporaryDirectory() as tmp:
            store = HomeAssistantConfigStore(db_path=Path(tmp) / "mimosa.db")
            store.update_client_state("ha-main", last_offense_id=10, last_block_id=5)
            state = store.get_client_state("ha-main")
            self.assertEqual(state["last_offense_id"], 10)
            self.assertEqual(state["last_block_id"], 5)

    def test_rotate_token_changes_value(self) -> None:
        with TemporaryDirectory() as tmp:
            store = HomeAssistantConfigStore(db_path=Path(tmp) / "mimosa.db")
            initial = store.get_config().api_token
            rotated = store.rotate_token()
            self.assertNotEqual(initial, rotated)
            refreshed = store.get_config().api_token
            self.assertEqual(refreshed, rotated)


if __name__ == "__main__":
    unittest.main()

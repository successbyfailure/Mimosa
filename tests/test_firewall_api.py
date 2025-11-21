import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.web.app import FirewallInput, create_app
from mimosa.web.config import FirewallConfigStore


def build_client(tmp_dir: str) -> tuple[TestClient, FirewallConfigStore]:
    storage_dir = Path(tmp_dir)
    config_store = FirewallConfigStore(path=storage_dir / "firewalls.json")
    offense_store = OffenseStore(db_path=storage_dir / "mimosa.db")
    app = create_app(
        offense_store=offense_store,
        block_manager=BlockManager(db_path=offense_store.db_path),
        config_store=config_store,
    )
    return TestClient(app), config_store


class FirewallApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.client, self.config_store = build_client(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _dummy_payload(self) -> dict:
        return FirewallInput(
            name="dummy-fw",
            type="dummy",
            base_url=None,
            api_key=None,
            api_secret=None,
            alias_name="mimosa_blocklist",
            verify_ssl=True,
            timeout=5.0,
        ).model_dump()

    def test_create_firewall_persists_configuration(self) -> None:
        response = self.client.post("/api/firewalls", json=self._dummy_payload())
        self.assertEqual(response.status_code, 201)
        data = response.json()

        stored = self.config_store.get(data["id"])
        self.assertIsNotNone(stored)
        self.assertEqual(data["name"], stored.name)

        listing = self.client.get("/api/firewalls")
        self.assertEqual(listing.status_code, 200)
        ids = {cfg["id"] for cfg in listing.json()}
        self.assertIn(data["id"], ids)

    def test_test_firewall_accepts_body_payload(self) -> None:
        response = self.client.post("/api/firewalls/test", json=self._dummy_payload())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["online"])

    def test_block_manager_endpoints_allow_add_and_remove(self) -> None:
        created = self.client.post("/api/firewalls", json=self._dummy_payload()).json()
        config_id = created["id"]

        listing = self.client.get(f"/api/firewalls/{config_id}/blocks")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["items"], [])

        add_resp = self.client.post(
            f"/api/firewalls/{config_id}/blocks",
            json={"ip": "203.0.113.10", "reason": "manual"},
        )
        self.assertEqual(add_resp.status_code, 201)

        refreshed = self.client.get(f"/api/firewalls/{config_id}/blocks")
        self.assertIn("203.0.113.10", refreshed.json()["items"])

        delete_resp = self.client.delete(
            f"/api/firewalls/{config_id}/blocks/203.0.113.10"
        )
        self.assertEqual(delete_resp.status_code, 204)

        final_listing = self.client.get(f"/api/firewalls/{config_id}/blocks")
        self.assertEqual(final_listing.json()["items"], [])


if __name__ == "__main__":
    unittest.main()

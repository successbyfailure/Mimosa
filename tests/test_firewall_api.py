import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from conftest import ensure_test_env
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


def _as_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.lower() not in {"false", "0", "no"}


def _opnsense_env_payload() -> FirewallInput | None:
    if not ensure_test_env(
        [
            "TEST_FIREWALL_OPNSENSE_BASE_URL",
            "TEST_FIREWALL_OPNSENSE_API_KEY",
            "TEST_FIREWALL_OPNSENSE_API_SECRET",
        ]
    ):
        return None

    base_url = os.getenv("TEST_FIREWALL_OPNSENSE_BASE_URL")
    api_key = os.getenv("TEST_FIREWALL_OPNSENSE_API_KEY")
    api_secret = os.getenv("TEST_FIREWALL_OPNSENSE_API_SECRET")
    if not base_url or not api_key or not api_secret:
        return None
    return FirewallInput(
        name=os.getenv("TEST_FIREWALL_OPNSENSE_NAME", "opnsense-env"),
        type="opnsense",
        base_url=base_url,
        api_key=api_key,
        api_secret=api_secret,
        alias_name=os.getenv("TEST_FIREWALL_OPNSENSE_ALIAS_NAME", "mimosa_blocklist"),
        verify_ssl=_as_bool(os.getenv("TEST_FIREWALL_OPNSENSE_VERIFY_SSL"), True),
        timeout=float(os.getenv("TEST_FIREWALL_TIMEOUT") or 15),
        apply_changes=_as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), True),
    )


def _pfsense_env_payload() -> FirewallInput | None:
    if not ensure_test_env(
        [
            "TEST_FIREWALL_PFSENSE_BASE_URL",
            "TEST_FIREWALL_PFSENSE_API_KEY",
            "TEST_FIREWALL_PFSENSE_API_SECRET",
        ]
    ):
        return None

    base_url = os.getenv("TEST_FIREWALL_PFSENSE_BASE_URL")
    api_key = os.getenv("TEST_FIREWALL_PFSENSE_API_KEY")
    api_secret = os.getenv("TEST_FIREWALL_PFSENSE_API_SECRET", api_key)
    if not base_url or not api_key or not api_secret:
        return None
    return FirewallInput(
        name=os.getenv("TEST_FIREWALL_PFSENSE_NAME", "pfsense-env"),
        type="pfsense",
        base_url=base_url,
        api_key=api_key,
        api_secret=api_secret,
        alias_name=os.getenv("TEST_FIREWALL_PFSENSE_ALIAS_NAME", "mimosa_blocklist"),
        verify_ssl=_as_bool(os.getenv("TEST_FIREWALL_PFSENSE_VERIFY_SSL"), True),
        timeout=float(os.getenv("TEST_FIREWALL_TIMEOUT") or 15),
        apply_changes=_as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), True),
    )


def _legacy_env_payload() -> FirewallInput | None:
    if not ensure_test_env(
        [
            "TEST_FIREWALL_BASE_URL",
            "TEST_FIREWALL_API_KEY",
            "TEST_FIREWALL_API_SECRET",
        ]
    ):
        return None

    base_url = os.getenv("TEST_FIREWALL_BASE_URL")
    api_key = os.getenv("TEST_FIREWALL_API_KEY")
    api_secret = os.getenv("TEST_FIREWALL_API_SECRET")
    if not base_url or not api_key or not api_secret:
        return None
    return FirewallInput(
        name=os.getenv("TEST_FIREWALL_NAME", "env-firewall"),
        type=os.getenv("TEST_FIREWALL_TYPE", "opnsense"),
        base_url=base_url,
        api_key=api_key,
        api_secret=api_secret,
        alias_name=os.getenv("TEST_FIREWALL_ALIAS_NAME", "mimosa_blocklist"),
        verify_ssl=_as_bool(os.getenv("TEST_FIREWALL_VERIFY_SSL"), True),
        timeout=float(os.getenv("TEST_FIREWALL_TIMEOUT") or 15),
        apply_changes=_as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), True),
    )


def _env_firewall_payload() -> FirewallInput | None:
    return _opnsense_env_payload() or _pfsense_env_payload() or _legacy_env_payload()


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

    def test_block_rule_stats_returns_error_for_dummy(self) -> None:
        created = self.client.post("/api/firewalls", json=self._dummy_payload()).json()
        config_id = created["id"]

        stats = self.client.get(f"/api/firewalls/{config_id}/block_rule_stats")
        self.assertEqual(stats.status_code, 501)

    def test_flush_states_returns_error_for_dummy(self) -> None:
        created = self.client.post("/api/firewalls", json=self._dummy_payload()).json()
        config_id = created["id"]

        response = self.client.post(f"/api/firewalls/{config_id}/flush_states")
        self.assertEqual(response.status_code, 501)

    def test_rule_endpoints_allow_add_and_delete(self) -> None:
        initial = self.client.get("/api/rules")
        self.assertEqual(initial.status_code, 200)
        initial_count = len(initial.json())

        create_resp = self.client.post(
            "/api/rules",
            json={
                "plugin": "auth",
                "severity": "alto",
                "description": "intentos fallidos",
                "min_last_hour": 2,
                "min_total": 3,
                "min_blocks_total": 1,
                "block_minutes": 90,
            },
        )
        self.assertEqual(create_resp.status_code, 201)
        created = create_resp.json()

        listing = self.client.get("/api/rules")
        self.assertEqual(len(listing.json()), initial_count + 1)
        self.assertEqual(created["plugin"], "auth")

        delete_resp = self.client.delete(f"/api/rules/{created['id']}")
        self.assertEqual(delete_resp.status_code, 204)

        final_listing = self.client.get("/api/rules")
        self.assertEqual(len(final_listing.json()), initial_count)
class FirewallEnvIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.client, self.config_store = build_client(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @unittest.skipUnless(
        _env_firewall_payload(),
        "Variables de entorno de firewall no configuradas",
    )
    def test_block_rule_stats_with_env_firewall(self) -> None:
        payload = _env_firewall_payload()
        self.assertIsNotNone(payload)
        response = self.client.post("/api/firewalls", json=payload.model_dump())
        self.assertEqual(response.status_code, 201)
        config_id = response.json()["id"]

        stats = self.client.get(f"/api/firewalls/{config_id}/block_rule_stats")
        self.assertIn(stats.status_code, (200, 501))

    @unittest.skipUnless(
        _env_firewall_payload(),
        "Variables de entorno de firewall no configuradas",
    )
    def test_flush_states_with_env_firewall(self) -> None:
        payload = _env_firewall_payload()
        self.assertIsNotNone(payload)
        response = self.client.post("/api/firewalls", json=payload.model_dump())
        self.assertEqual(response.status_code, 201)
        config_id = response.json()["id"]

        flush = self.client.post(f"/api/firewalls/{config_id}/flush_states")
        self.assertIn(flush.status_code, (200, 501, 502))




if __name__ == "__main__":
    unittest.main()

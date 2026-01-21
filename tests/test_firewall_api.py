import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from conftest import ensure_test_env
from fastapi import HTTPException
from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.web.app import (
    BlacklistInput,
    BlockInput,
    FirewallInput,
    RuleInput,
    create_app,
)
from mimosa.web.config import FirewallConfigStore
from tests.helpers import MemoryFirewall


def _get_endpoint(app, path: str, method: str = "GET"):
    for route in app.router.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", {"GET"}):
            return route.endpoint
    raise AssertionError(f"No se encontró el endpoint {path}")


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
        verify_ssl=_as_bool(os.getenv("TEST_FIREWALL_OPNSENSE_VERIFY_SSL"), True),
        timeout=float(os.getenv("TEST_FIREWALL_TIMEOUT") or 15),
        apply_changes=_as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), True),
    )


def _env_firewall_payload() -> FirewallInput | None:
    return _opnsense_env_payload()


class FirewallApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        storage_dir = Path(self._tmp.name)
        self.config_store = FirewallConfigStore(
            db_path=storage_dir / "mimosa.db", path=storage_dir / "firewalls.json"
        )
        self.offense_store = OffenseStore(db_path=storage_dir / "mimosa.db")
        self.gateway_patcher = patch(
            "mimosa.web.app.build_firewall_gateway", lambda cfg: MemoryFirewall()
        )
        self.status_patcher = patch(
            "mimosa.web.app.check_firewall_status",
            lambda cfg: {
                "id": cfg.id,
                "name": cfg.name,
                "type": cfg.type,
                "online": True,
                "message": "Conexión OK",
                "alias_ready": True,
                "alias_created": False,
                "applied_changes": False,
            },
        )
        self.gateway_patcher.start()
        self.status_patcher.start()
        self.app = create_app(
            offense_store=self.offense_store,
            block_manager=BlockManager(db_path=self.offense_store.db_path),
            config_store=self.config_store,
        )

    def tearDown(self) -> None:
        self.gateway_patcher.stop()
        self.status_patcher.stop()
        self._tmp.cleanup()

    def _stub_payload(self) -> FirewallInput:
        return FirewallInput(
            name="opnsense-stub",
            type="opnsense",
            base_url=None,
            api_key=None,
            api_secret=None,
            verify_ssl=True,
            timeout=5.0,
        )

    def _create_firewall(self, payload: FirewallInput) -> object:
        endpoint = _get_endpoint(self.app, "/api/firewalls", "POST")
        return endpoint(payload)

    def test_create_firewall_persists_configuration(self) -> None:
        created = self._create_firewall(self._stub_payload())

        stored = self.config_store.get(created.id)
        self.assertIsNotNone(stored)
        self.assertEqual(created.name, stored.name)

        listing_endpoint = _get_endpoint(self.app, "/api/firewalls")
        listing = listing_endpoint()
        ids = {cfg.id for cfg in listing}
        self.assertIn(created.id, ids)

    def test_test_firewall_accepts_body_payload(self) -> None:
        test_endpoint = _get_endpoint(self.app, "/api/firewalls/test", "POST")
        result = test_endpoint(self._stub_payload())
        self.assertTrue(result["online"])

    def test_block_manager_endpoints_allow_add_and_remove(self) -> None:
        created = self._create_firewall(self._stub_payload())
        config_id = created.id

        list_blocks = _get_endpoint(self.app, "/api/firewalls/{config_id}/blocks", "GET")
        add_block = _get_endpoint(self.app, "/api/firewalls/{config_id}/blocks", "POST")
        delete_block = _get_endpoint(self.app, "/api/firewalls/{config_id}/blocks/{ip}", "DELETE")

        listing = list_blocks(config_id)
        self.assertEqual(listing["items"], [])

        add_block(config_id, BlockInput(ip="203.0.113.10", reason="manual"))
        refreshed = list_blocks(config_id)
        self.assertIn("203.0.113.10", refreshed["items"])

        delete_block(config_id, "203.0.113.10")
        final_listing = list_blocks(config_id)
        self.assertEqual(final_listing["items"], [])

    def test_blacklist_endpoints_allow_add_and_remove(self) -> None:
        created = self._create_firewall(self._stub_payload())
        config_id = created.id

        list_blacklist = _get_endpoint(self.app, "/api/firewalls/{config_id}/blacklist", "GET")
        add_blacklist = _get_endpoint(self.app, "/api/firewalls/{config_id}/blacklist", "POST")
        delete_blacklist = _get_endpoint(
            self.app, "/api/firewalls/{config_id}/blacklist/{ip}", "DELETE"
        )

        self.assertEqual(list_blacklist(config_id)["items"], [])
        add_blacklist(config_id, BlacklistInput(ip="203.0.113.40", reason="manual"))
        listing = list_blacklist(config_id)
        self.assertIn("203.0.113.40", listing["items"])
        delete_blacklist(config_id, "203.0.113.40")
        self.assertEqual(list_blacklist(config_id)["items"], [])

    def test_rule_endpoints_allow_add_and_delete(self) -> None:
        list_rules = _get_endpoint(self.app, "/api/rules", "GET")
        create_rule = _get_endpoint(self.app, "/api/rules", "POST")
        delete_rule = _get_endpoint(self.app, "/api/rules/{rule_id}", "DELETE")

        initial_count = len(list_rules())
        created = create_rule(
            RuleInput(
                plugin="auth",
                severity="alto",
                description="intentos fallidos",
                min_last_hour=2,
                min_total=3,
                min_blocks_total=1,
                block_minutes=90,
            )
        )

        self.assertEqual(len(list_rules()), initial_count + 1)
        delete_rule(created["id"])
        self.assertEqual(len(list_rules()), initial_count)


class FirewallEnvIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        storage_dir = Path(self._tmp.name)
        self.config_store = FirewallConfigStore(
            db_path=storage_dir / "mimosa.db", path=storage_dir / "firewalls.json"
        )
        self.offense_store = OffenseStore(db_path=storage_dir / "mimosa.db")
        self.app = create_app(
            offense_store=self.offense_store,
            block_manager=BlockManager(db_path=self.offense_store.db_path),
            config_store=self.config_store,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @unittest.skipUnless(
        _env_firewall_payload(),
        "Variables de entorno de firewall no configuradas",
    )
    def test_block_rule_stats_with_env_firewall(self) -> None:
        payload = _env_firewall_payload()
        self.assertIsNotNone(payload)
        create_firewall = _get_endpoint(self.app, "/api/firewalls", "POST")
        block_rule_stats = _get_endpoint(
            self.app, "/api/firewalls/{config_id}/block_rule_stats", "GET"
        )

        created = create_firewall(payload)
        try:
            stats = block_rule_stats(created.id)
        except HTTPException as exc:
            self.assertIn(exc.status_code, (501, 502))
            return
        self.assertIsInstance(stats, dict)

    @unittest.skipUnless(
        _env_firewall_payload(),
        "Variables de entorno de firewall no configuradas",
    )
    def test_flush_states_with_env_firewall(self) -> None:
        payload = _env_firewall_payload()
        self.assertIsNotNone(payload)
        create_firewall = _get_endpoint(self.app, "/api/firewalls", "POST")
        flush_states = _get_endpoint(self.app, "/api/firewalls/{config_id}/flush_states", "POST")

        created = create_firewall(payload)
        try:
            result = flush_states(created.id)
        except HTTPException as exc:
            self.assertIn(exc.status_code, (501, 502))
            return
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()

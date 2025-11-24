import json
import os
import unittest

import httpx

from mimosa.core.sense import OPNsenseClient


def _as_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


class OPNsenseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alias_created = False
        self.alias_name = "mimosa_blocklist"
        self.requests: list[tuple[str, str, int]] = []
        self.alias_addresses: set[str] = set()
        self.fallback_after_additem_404 = False
        self.fallback_after_delete_404 = False

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/core/firmware/info":
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == f"/api/firewall/alias/searchItem":
                rows = (
                    [{"name": self.alias_name, "uuid": "alias-uuid"}]
                    if self.alias_created
                    else []
                )
                response = httpx.Response(
                    200,
                    json={
                        "rows": rows,
                        "rowCount": len(rows),
                        "total": len(rows),
                        "current": 1,
                    },
                )
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == f"/api/firewall/alias_util/list/{self.alias_name}":
                if self.alias_created:
                    response = httpx.Response(
                        200,
                        json={
                            "total": len(self.alias_addresses),
                            "rowCount": len(self.alias_addresses),
                            "current": 1,
                            "rows": [
                                {"ip": address} for address in sorted(self.alias_addresses)
                            ],
                        },
                    )
                else:
                    response = httpx.Response(404, json={"error": "alias missing"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == "/api/firewall/alias/addItem":
                if self.fallback_after_additem_404:
                    response = httpx.Response(404, json={"error": "missing endpoint"})
                else:
                    payload = json.loads(request.content or b"{}")
                    alias = payload.get("alias", {})
                    self.alias_created = alias.get("name") == self.alias_name
                    response = httpx.Response(200, json={"uuid": "alias-uuid"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == "/api/firewall/alias_util/add":
                payload = json.loads(request.content or b"{}")
                self.alias_created = payload.get("name") == self.alias_name
                response = httpx.Response(200, json={"result": "saved"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == f"/api/firewall/alias_util/add/{self.alias_name}":
                payload = json.loads(request.content or b"{}")
                ip = payload.get("address")
                if ip:
                    self.alias_addresses.add(ip)
                    self.alias_created = True
                    response = httpx.Response(200, json={"status": "done"})
                else:
                    response = httpx.Response(400, json={"status": "failed"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == f"/api/firewall/alias_util/delete/{self.alias_name}":
                if self.fallback_after_delete_404:
                    response = httpx.Response(404, json={"error": "missing endpoint"})
                else:
                    payload = json.loads(request.content or b"{}")
                    ip = payload.get("address")
                    if ip and ip in self.alias_addresses:
                        self.alias_addresses.remove(ip)
                        response = httpx.Response(200, json={"status": "done"})
                    else:
                        response = httpx.Response(404, json={"status": "not found"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == f"/api/firewall/alias_util/flush/{self.alias_name}":
                self.alias_addresses.clear()
                response = httpx.Response(200, json={"status": "done"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == "/api/firewall/filter/apply":
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            response = httpx.Response(500, json={"error": "unexpected"})
            self.requests.append((request.method, request.url.path, response.status_code))
            return response

        self.transport = httpx.MockTransport(handler)
        self.client = httpx.Client(transport=self.transport, base_url="http://fw")
        self.firewall = OPNsenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            alias_name=self.alias_name,
            client=self.client,
        )

    def tearDown(self) -> None:
        self.client.close()

    def test_ensure_ready_creates_alias_via_alias_util(self) -> None:
        self.firewall.ensure_ready()

        self.assertTrue(self.alias_created)
        self.assertIn(
            ("POST", "/api/firewall/alias/addItem", 200),
            self.requests,
        )

        items = self.firewall.list_blocks()
        self.assertEqual(items, [])
        statuses = [status for *_, status in self.requests]
        self.assertEqual(statuses.count(404), 0)

    def test_list_blocks_recovers_from_missing_alias(self) -> None:
        blocks = self.firewall.list_blocks()

        self.assertTrue(self.alias_created)
        self.assertEqual(blocks, [])
        self.assertIn(
            ("POST", "/api/firewall/alias/addItem", 200),
            self.requests,
        )

    def test_falls_back_to_legacy_alias_util_creation(self) -> None:
        self.fallback_after_additem_404 = True

        blocks = self.firewall.list_blocks()

        self.assertTrue(self.alias_created)
        self.assertEqual(blocks, [])
        self.assertIn(
            ("POST", "/api/firewall/alias/addItem", 404),
            self.requests,
        )
        self.assertIn(
            ("POST", "/api/firewall/alias_util/add", 200),
            self.requests,
        )

    def test_block_and_unblock_trigger_reload(self) -> None:
        self.firewall.block_ip("203.0.113.10", reason="prueba")
        self.firewall.unblock_ip("203.0.113.10")

        apply_calls = [req for req in self.requests if req[1] == "/api/firewall/filter/apply"]
        self.assertEqual(len(apply_calls), 2)

    def test_unblock_ip_preserves_other_entries(self) -> None:
        self.firewall.block_ip("203.0.113.10", reason="prueba")
        self.firewall.block_ip("203.0.113.11", reason="prueba")

        self.firewall.unblock_ip("203.0.113.10")

        self.assertNotIn("203.0.113.10", self.alias_addresses)
        self.assertIn("203.0.113.11", self.alias_addresses)

    def test_unblock_ip_uses_delete_endpoint_when_available(self) -> None:
        self.firewall.block_ip("203.0.113.12", reason="prueba")

        self.firewall.unblock_ip("203.0.113.12")

        self.assertNotIn("203.0.113.12", self.alias_addresses)
        self.assertIn(
            ("POST", f"/api/firewall/alias_util/delete/{self.alias_name}", 200),
            self.requests,
        )

    def test_unblock_ip_falls_back_when_delete_endpoint_missing(self) -> None:
        self.fallback_after_delete_404 = True
        self.firewall.block_ip("203.0.113.13", reason="prueba")

        self.firewall.unblock_ip("203.0.113.13")

        self.assertNotIn("203.0.113.13", self.alias_addresses)
        self.assertIn(
            ("POST", f"/api/firewall/alias_util/delete/{self.alias_name}", 404),
            self.requests,
        )
        self.assertIn(
            ("POST", f"/api/firewall/alias_util/flush/{self.alias_name}", 200),
            self.requests,
        )

    def test_ensure_ready_applies_when_creating_alias(self) -> None:
        self.firewall.ensure_ready()

        apply_calls = [req for req in self.requests if req[1] == "/api/firewall/filter/apply"]
        self.assertEqual(len(apply_calls), 1)
        self.assertTrue(self.alias_created)

    def test_can_disable_apply_calls_for_tests(self) -> None:
        firewall = OPNsenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            alias_name=self.alias_name,
            client=self.client,
            apply_changes=False,
        )

        firewall.block_ip("203.0.113.10")
        firewall.unblock_ip("203.0.113.10")

        apply_calls = [req for req in self.requests if req[1] == "/api/firewall/filter/apply"]
        self.assertEqual(len(apply_calls), 0)

    def test_get_status_reports_alias_preparation(self) -> None:
        status = self.firewall.get_status()

        self.assertTrue(status.get("available"))
        self.assertTrue(status.get("alias_ready"))
        self.assertTrue(status.get("alias_created"))
        self.assertTrue(status.get("applied_changes"))
        self.assertIn(("POST", "/api/firewall/filter/apply", 200), self.requests)

    def test_live_opnsense_calls_use_environment(self) -> None:
        base_url = os.getenv("OPNSENSE_BASE_URL") or os.getenv("OPNSENSE_URL")
        api_key = os.getenv("OPNSENSE_API_KEY")
        api_secret = os.getenv("OPNSENSE_API_SECRET")
        alias_name = os.getenv("OPNSENSE_ALIAS_NAME", "mimosa_blocklist")
        test_ip = os.getenv("OPNSENSE_TEST_IP", "198.51.100.250")

        if not base_url or not api_key or not api_secret:
            self.skipTest("Entorno OPNsense no configurado")

        firewall = OPNsenseClient(
            base_url=base_url,
            api_key=api_key,
            api_secret=api_secret,
            alias_name=alias_name,
            verify_ssl=os.getenv("OPNSENSE_VERIFY_SSL", "true").lower() not in {"0", "false", "no"},
            apply_changes=False,
        )

        firewall.check_connection()
        firewall.ensure_ready()
        firewall.block_ip(test_ip, reason="prueba-ci")
        try:
            self.assertIn(test_ip, firewall.list_blocks())
        finally:
            firewall.unblock_ip(test_ip)

    def test_live_opnsense_calls_use_test_environment(self) -> None:
        base_url = os.getenv("TEST_FIREWALL_OPNSENSE_BASE_URL")
        api_key = os.getenv("TEST_FIREWALL_OPNSENSE_API_KEY")
        api_secret = os.getenv("TEST_FIREWALL_OPNSENSE_API_SECRET")
        alias_name = os.getenv("TEST_FIREWALL_OPNSENSE_ALIAS_NAME", "mimosa_blocklist")
        verify_ssl = _as_bool(os.getenv("TEST_FIREWALL_OPNSENSE_VERIFY_SSL"), True)
        apply_changes = _as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), False)
        timeout_str = os.getenv("TEST_FIREWALL_TIMEOUT")
        timeout = float(timeout_str) if timeout_str else 10.0
        test_ip = os.getenv("TEST_FIREWALL_OPNSENSE_TEST_IP", "198.51.100.251")

        if not base_url or not api_key or not api_secret:
            self.skipTest("Entorno de pruebas OPNsense incompleto")

        firewall = OPNsenseClient(
            base_url=base_url,
            api_key=api_key,
            api_secret=api_secret,
            alias_name=alias_name,
            verify_ssl=verify_ssl,
            timeout=timeout,
            apply_changes=apply_changes,
        )

        firewall.check_connection()
        firewall.ensure_ready()
        firewall.block_ip(test_ip, reason="prueba-ci-env")
        try:
            blocks = firewall.list_blocks()
            self.assertIn(test_ip, blocks)
        finally:
            firewall.unblock_ip(test_ip)


if __name__ == "__main__":
    unittest.main()

import json
import unittest

import httpx

from mimosa.core.pfsense import OPNsenseClient


class OPNsenseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alias_created = False
        self.alias_name = "mimosa_blocklist"
        self.requests: list[tuple[str, str, int]] = []
        self.alias_addresses: set[str] = set()
        self.fallback_after_additem_404 = False

        def handler(request: httpx.Request) -> httpx.Response:
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


if __name__ == "__main__":
    unittest.main()

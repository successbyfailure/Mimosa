import json
import unittest

import httpx

from mimosa.core.pfsense import PFSenseClient


class PFSenseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests: list[tuple[str, str, int]] = []
        self.alias_name = "mimosa_blocklist"
        self.alias_exists = True
        self.alias_addresses: set[str] = set()

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/status/system":
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((request.method, path, response.status_code))
                return response

            if path == f"/api/v1/firewall/alias/{self.alias_name}":
                if not self.alias_exists:
                    response = httpx.Response(404, json={"error": "missing"})
                else:
                    response = httpx.Response(
                        200,
                        json={
                            "addresses": [
                                {"address": ip} for ip in sorted(self.alias_addresses)
                            ]
                        },
                    )
                self.requests.append((request.method, path, response.status_code))
                return response

            if path.startswith(f"/api/v1/firewall/alias/{self.alias_name}/address"):
                if request.method == "POST":
                    address = request.url.path.rsplit("/", maxsplit=1)[-1]
                    if not address or address == "address":
                        content = request.content or b"{}"
                        payload = json.loads(content.decode())
                        address = payload.get("address", "")
                    self.alias_exists = True
                    if address:
                        self.alias_addresses.add(address)
                    response = httpx.Response(200, json={"saved": address})
                else:
                    address = request.url.path.rsplit("/", maxsplit=1)[-1]
                    self.alias_addresses.discard(address)
                    response = httpx.Response(200, json={"removed": address})
                self.requests.append((request.method, path, response.status_code))
                return response

            if path == "/api/v1/firewall/alias":
                self.alias_exists = True
                response = httpx.Response(200, json={"created": self.alias_name})
                self.requests.append((request.method, path, response.status_code))
                return response

            if path == "/api/v1/diagnostics/filter/reload":
                response = httpx.Response(200, json={"status": "applied"})
                self.requests.append((request.method, path, response.status_code))
                return response

            response = httpx.Response(500, json={"error": "unexpected"})
            self.requests.append((request.method, path, response.status_code))
            return response

        self.transport = httpx.MockTransport(handler)
        self.client = httpx.Client(transport=self.transport, base_url="http://fw")
        self.firewall = PFSenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            alias_name=self.alias_name,
            client=self.client,
        )

    def tearDown(self) -> None:
        self.client.close()

    def test_check_connection_uses_status_endpoint(self) -> None:
        self.firewall.check_connection()

        self.assertIn(("GET", "/api/v1/status/system", 200), self.requests)

    def test_check_connection_raises_permission_error_on_unauthorized(self) -> None:
        def unauthorized_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v1/status/system":
                response = httpx.Response(401, json={"error": "unauthorized"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            response = httpx.Response(500, json={"error": "unexpected"})
            self.requests.append((request.method, request.url.path, response.status_code))
            return response

        transport = httpx.MockTransport(unauthorized_handler)
        client = httpx.Client(transport=transport, base_url="http://fw")
        firewall = PFSenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            alias_name="mimosa_blocklist",
            client=client,
        )

        with self.assertRaises(PermissionError):
            firewall.check_connection()

        client.close()

    def test_block_and_unblock_trigger_reload(self) -> None:
        self.firewall.block_ip("203.0.113.20")
        self.firewall.unblock_ip("203.0.113.20")

        apply_calls = [req for req in self.requests if req[1] == "/api/v1/diagnostics/filter/reload"]
        self.assertEqual(len(apply_calls), 2)

    def test_ensure_ready_applies_when_creating_alias(self) -> None:
        self.alias_exists = False
        self.firewall.ensure_ready()

        apply_calls = [req for req in self.requests if req[1] == "/api/v1/diagnostics/filter/reload"]
        self.assertEqual(len(apply_calls), 1)
        self.assertTrue(self.alias_exists)

    def test_can_disable_apply_calls_for_tests(self) -> None:
        firewall = PFSenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            alias_name=self.alias_name,
            client=self.client,
            apply_changes=False,
        )

        firewall.block_ip("203.0.113.21")
        firewall.unblock_ip("203.0.113.21")

        apply_calls = [req for req in self.requests if req[1] == "/api/v1/diagnostics/filter/reload"]
        self.assertEqual(len(apply_calls), 0)


if __name__ == "__main__":
    unittest.main()

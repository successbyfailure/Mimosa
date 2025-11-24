import json
import json
import os
import unittest

import httpx

from conftest import ensure_test_env
from mimosa.core.sense import PFSenseClient


def _as_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


class PFSenseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests: list[tuple[str, str, int]] = []
        self.alias_name = "mimosa_blocklist"
        self.alias_exists = True
        self.alias_addresses: set[str] = set()
        self.port_aliases_created: set[str] = set()
        self.alias_entries: dict[str, set[str]] = {self.alias_name: self.alias_addresses}

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/status/system":
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((request.method, path, response.status_code))
                return response

            if path.startswith("/api/v1/firewall/alias/") and "/address" not in path:
                alias_name = path.rsplit("/", maxsplit=1)[-1]
                alias_exists = (
                    alias_name == self.alias_name and self.alias_exists
                ) or alias_name in self.port_aliases_created
                if not alias_exists:
                    response = httpx.Response(404, json={"error": "missing"})
                else:
                    entries = self.alias_entries.setdefault(alias_name, set())
                    response = httpx.Response(
                        200,
                        json={
                            "addresses": [
                                {"address": ip} for ip in sorted(entries)
                            ]
                        },
                    )
                self.requests.append((request.method, path, response.status_code))
                return response

            if path.startswith("/api/v1/firewall/alias/") and "/address" in path:
                alias_name = path.split("/")[5]
                if request.method == "POST":
                    address = request.url.path.rsplit("/", maxsplit=1)[-1]
                    if not address or address == "address":
                        content = request.content or b"{}"
                        payload = json.loads(content.decode())
                        address = payload.get("address", "")
                    if alias_name == self.alias_name:
                        self.alias_exists = True
                    else:
                        self.port_aliases_created.add(alias_name)
                    if address:
                        entries = self.alias_entries.setdefault(alias_name, set())
                        entries.add(address)
                    response = httpx.Response(200, json={"saved": address})
                else:
                    address = request.url.path.rsplit("/", maxsplit=1)[-1]
                    entries = self.alias_entries.setdefault(alias_name, set())
                    entries.discard(address)
                    response = httpx.Response(200, json={"removed": address})
                self.requests.append((request.method, path, response.status_code))
                return response

            if path == "/api/v1/firewall/alias":
                payload = json.loads(request.content or b"{}")
                alias_name = payload.get("name")
                if alias_name == self.alias_name:
                    self.alias_exists = True
                elif alias_name:
                    self.port_aliases_created.add(alias_name)
                if alias_name:
                    self.alias_entries.setdefault(alias_name, set())
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

    def test_check_connection_falls_back_to_rest_prefix_on_404(self) -> None:
        seen: list[tuple[str, int]] = []

        def rest_handler(request: httpx.Request) -> httpx.Response:
            seen.append((request.url.path, request.method))
            if request.url.path == "/api/v1/status/system":
                return httpx.Response(404, json={"error": "missing"})
            if request.url.path == "/rest/status/system":
                return httpx.Response(200, json={"status": "ok"})
            return httpx.Response(500, json={"error": "unexpected"})

        client = httpx.Client(
            transport=httpx.MockTransport(rest_handler), base_url="http://fw"
        )
        firewall = PFSenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            alias_name="mimosa_blocklist",
            client=client,
        )

        firewall.check_connection()
        client.close()

        self.assertIn(("/api/v1/status/system", "GET"), seen)
        self.assertIn(("/rest/status/system", "GET"), seen)

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
        self.assertIn("mimosa_ports_tcp", self.port_aliases_created)
        self.assertIn("mimosa_ports_udp", self.port_aliases_created)

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

    def test_get_status_reports_alias_creation(self) -> None:
        self.alias_exists = False

        status = self.firewall.get_status()

        self.assertTrue(status.get("available"))
        self.assertTrue(status.get("alias_ready"))
        self.assertTrue(status.get("alias_created"))
        self.assertTrue(status.get("applied_changes"))
        self.assertTrue(self.alias_exists)
        self.assertIn("mimosa_ports_tcp", self.port_aliases_created)
        self.assertIn("mimosa_ports_udp", self.port_aliases_created)

    def test_live_pfsense_calls_use_test_environment(self) -> None:
        required_vars = [
            "TEST_FIREWALL_PFSENSE_BASE_URL",
            "TEST_FIREWALL_PFSENSE_API_KEY",
            "TEST_FIREWALL_PFSENSE_API_SECRET",
        ]

        if not ensure_test_env(required_vars):
            self.skipTest("Entorno de pruebas pfSense incompleto")

        base_url = os.getenv("TEST_FIREWALL_PFSENSE_BASE_URL")
        api_key = os.getenv("TEST_FIREWALL_PFSENSE_API_KEY")
        api_secret = os.getenv("TEST_FIREWALL_PFSENSE_API_SECRET", api_key)
        alias_name = os.getenv("TEST_FIREWALL_PFSENSE_ALIAS_NAME", "mimosa_blocklist")
        verify_ssl = _as_bool(os.getenv("TEST_FIREWALL_PFSENSE_VERIFY_SSL"), True)
        apply_changes = _as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), False)
        timeout_str = os.getenv("TEST_FIREWALL_TIMEOUT")
        timeout = float(timeout_str) if timeout_str else 10.0
        test_ip = os.getenv("TEST_FIREWALL_PFSENSE_TEST_IP", "198.51.100.252")

        firewall = PFSenseClient(
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

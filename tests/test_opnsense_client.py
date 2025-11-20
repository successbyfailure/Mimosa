import json
import unittest

import httpx

from mimosa.core.pfsense import OPNsenseClient


class OPNsenseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alias_created = False
        self.alias_name = "mimosa_blocklist"
        self.requests: list[tuple[str, str, int]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == f"/api/firewall/alias_util/list/{self.alias_name}":
                if self.alias_created:
                    response = httpx.Response(200, json={"items": []})
                else:
                    response = httpx.Response(404, json={"error": "alias missing"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path == "/api/firewall/alias_util/add":
                payload = json.loads(request.content or b"{}")
                self.alias_created = payload.get("name") == self.alias_name
                response = httpx.Response(200, json={"result": "saved"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            if request.url.path.startswith(
                f"/api/firewall/alias_util/add/{self.alias_name}/"
            ):
                ip = request.url.path.rsplit("/", maxsplit=1)[-1]
                self.alias_created = True
                response = httpx.Response(200, json={"added": ip})
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
            ("POST", "/api/firewall/alias_util/add", 200),
            self.requests,
        )

        items = self.firewall.list_blocks()
        self.assertEqual(items, [])
        statuses = [status for *_, status in self.requests]
        self.assertEqual(statuses.count(404), 1)

    def test_list_blocks_recovers_from_missing_alias(self) -> None:
        blocks = self.firewall.list_blocks()

        self.assertTrue(self.alias_created)
        self.assertEqual(blocks, [])
        self.assertIn(
            ("POST", "/api/firewall/alias_util/add", 200),
            self.requests,
        )


if __name__ == "__main__":
    unittest.main()

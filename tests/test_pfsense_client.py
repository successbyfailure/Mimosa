import unittest

import httpx

from mimosa.core.pfsense import PFSenseClient


class PFSenseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests: list[tuple[str, str, int]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v1/system/status":
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((request.method, request.url.path, response.status_code))
                return response

            response = httpx.Response(500, json={"error": "unexpected"})
            self.requests.append((request.method, request.url.path, response.status_code))
            return response

        self.transport = httpx.MockTransport(handler)
        self.client = httpx.Client(transport=self.transport, base_url="http://fw")
        self.firewall = PFSenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            alias_name="mimosa_blocklist",
            client=self.client,
        )

    def tearDown(self) -> None:
        self.client.close()

    def test_check_connection_uses_status_endpoint(self) -> None:
        self.firewall.check_connection()

        self.assertIn(("GET", "/api/v1/system/status", 200), self.requests)

    def test_check_connection_raises_permission_error_on_unauthorized(self) -> None:
        def unauthorized_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v1/system/status":
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


if __name__ == "__main__":
    unittest.main()

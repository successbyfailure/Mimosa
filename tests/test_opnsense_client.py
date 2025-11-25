import json
import os
import unittest
from typing import Dict, Set

import httpx

from conftest import ensure_test_env
from mimosa.core.sense import (
    BLACKLIST_ALIAS_NAME,
    TEMPORAL_ALIAS_NAME,
    OPNsenseClient,
)


def _as_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


class OPNsenseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests: list[tuple[str, str, int]] = []
        self.alias_entries: Dict[str, Set[str]] = {
            TEMPORAL_ALIAS_NAME: set(),
            BLACKLIST_ALIAS_NAME: set(),
        }
        self.created_aliases: Set[str] = set(self.alias_entries.keys())
        self.port_aliases: Set[str] = set()

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            method = request.method

            if path == "/api/core/firmware/info":
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((method, path, response.status_code))
                return response

            if path == "/api/firewall/filter/apply" and method == "POST":
                response = httpx.Response(200, json={"status": "applied"})
                self.requests.append((method, path, response.status_code))
                return response

            if path == "/api/firewall/alias/searchItem":
                rows = [{"name": name, "uuid": f"{name}-uuid"} for name in sorted(self.created_aliases)]
                response = httpx.Response(200, json={"rows": rows})
                self.requests.append((method, path, response.status_code))
                return response

            if path == "/api/firewall/alias/addItem" and method == "POST":
                payload = json.loads(request.content or b"{}")
                alias = payload.get("alias", {})
                alias_name = alias.get("name")
                alias_type = alias.get("type")
                if alias_name:
                    self.created_aliases.add(alias_name)
                    if alias_type == "port":
                        self.port_aliases.add(alias_name)
                    self.alias_entries.setdefault(alias_name, set())
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((method, path, response.status_code))
                return response

            if path.startswith("/api/firewall/alias/deleteItem/") and method == "POST":
                alias_name = path.rsplit("/", maxsplit=1)[-1]
                self.created_aliases.discard(alias_name)
                self.alias_entries.pop(alias_name, None)
                response = httpx.Response(200, json={"status": "ok"})
                self.requests.append((method, path, response.status_code))
                return response

            if path.startswith("/api/firewall/alias_util/list/"):
                alias_name = path.rsplit("/", maxsplit=1)[-1]
                if alias_name not in self.created_aliases:
                    response = httpx.Response(404, json={"error": "missing"})
                else:
                    entries = sorted(self.alias_entries.get(alias_name, set()))
                    response = httpx.Response(
                        200,
                        json={"rows": [{"ip": entry} for entry in entries]},
                    )
                self.requests.append((method, path, response.status_code))
                return response

            if path.startswith("/api/firewall/alias_util/add/"):
                alias_name = path.rsplit("/", maxsplit=1)[-1]
                payload = json.loads(request.content or b"{}")
                address = payload.get("address")
                if address:
                    self.alias_entries.setdefault(alias_name, set()).add(str(address))
                    self.created_aliases.add(alias_name)
                response = httpx.Response(200, json={"status": "done"})
                self.requests.append((method, path, response.status_code))
                return response

            if path.startswith("/api/firewall/alias_util/delete/"):
                alias_name = path.rsplit("/", maxsplit=1)[-1]
                payload = json.loads(request.content or b"{}")
                address = payload.get("address")
                if address:
                    self.alias_entries.setdefault(alias_name, set()).discard(str(address))
                response = httpx.Response(200, json={"status": "done"})
                self.requests.append((method, path, response.status_code))
                return response

            response = httpx.Response(500, json={"error": "unexpected"})
            self.requests.append((method, path, response.status_code))
            return response

        self.transport = httpx.MockTransport(handler)
        self.client = httpx.Client(transport=self.transport, base_url="http://fw")
        self.firewall = OPNsenseClient(
            base_url="http://fw",
            api_key="apikey",
            api_secret="apisecret",
            client=self.client,
        )

    def tearDown(self) -> None:
        self.client.close()

    def test_check_connection_reaches_status_endpoint(self) -> None:
        self.firewall.check_connection()
        self.assertIn(("GET", "/api/core/firmware/info", 200), self.requests)

    def test_alias_workflow_sequence_with_mock(self) -> None:
        # 1. Online
        self.firewall.check_connection()
        # 2. Crear alias IP
        self.firewall.create_alias(
            name="mimosa_test_alias_ip",
            alias_type="host",
            description="alias ip test",
        )
        # 3. Crear alias puertos
        self.firewall.create_alias(
            name="mimosa_test_alias_ports",
            alias_type="port",
            description="alias ports test",
        )
        # 4. Comprobar existencia
        self.assertTrue(self.firewall._alias_exists("mimosa_test_alias_ip"))  # type: ignore[attr-defined]
        self.assertTrue(self.firewall._alias_exists("mimosa_test_alias_ports"))  # type: ignore[attr-defined]
        # 5. Eliminar alias
        self.firewall._request("POST", "/api/firewall/alias/deleteItem/mimosa_test_alias_ip")  # type: ignore[attr-defined]
        self.firewall._request("POST", "/api/firewall/alias/deleteItem/mimosa_test_alias_ports")  # type: ignore[attr-defined]
        # 6. Verificar eliminación
        self.assertFalse(self.firewall._alias_exists("mimosa_test_alias_ip"))  # type: ignore[attr-defined]
        self.assertFalse(self.firewall._alias_exists("mimosa_test_alias_ports"))  # type: ignore[attr-defined]
        # 7. Crear alias de puertos con entradas
        self.firewall.create_alias(
            name="mimosa_test_alias_ports",
            alias_type="port",
            description="alias ports test",
        )
        self.firewall._request(  # type: ignore[attr-defined]
            "POST",
            "/api/firewall/alias_util/add/mimosa_test_alias_ports",
            json={"address": "1234"},
        )
        self.firewall._request(  # type: ignore[attr-defined]
            "POST",
            "/api/firewall/alias_util/add/mimosa_test_alias_ports",
            json={"address": "4321"},
        )
        # 8. Comprobar contenido
        ports = self.firewall._list_alias_values("mimosa_test_alias_ports")  # type: ignore[attr-defined]
        self.assertIn("1234", ports)
        self.assertIn("4321", ports)
        # 9. Eliminar puerto 4321
        self.firewall._request(  # type: ignore[attr-defined]
            "POST",
            "/api/firewall/alias_util/delete/mimosa_test_alias_ports",
            json={"address": "4321"},
        )
        ports_after = self.firewall._list_alias_values("mimosa_test_alias_ports")  # type: ignore[attr-defined]
        self.assertEqual(ports_after, ["1234"])
        # 10. Eliminar alias final
        self.firewall._request("POST", "/api/firewall/alias/deleteItem/mimosa_test_alias_ports")  # type: ignore[attr-defined]
        self.assertFalse(self.firewall._alias_exists("mimosa_test_alias_ports"))  # type: ignore[attr-defined]

    def test_live_opnsense_alias_workflow_optional(self) -> None:
        required_vars = [
            "TEST_FIREWALL_OPNSENSE_BASE_URL",
            "TEST_FIREWALL_OPNSENSE_API_KEY",
            "TEST_FIREWALL_OPNSENSE_API_SECRET",
        ]

        if not ensure_test_env(required_vars):
            self.skipTest("Entorno de pruebas OPNsense incompleto")

        base_url = os.getenv("TEST_FIREWALL_OPNSENSE_BASE_URL")
        api_key = os.getenv("TEST_FIREWALL_OPNSENSE_API_KEY")
        api_secret = os.getenv("TEST_FIREWALL_OPNSENSE_API_SECRET")
        verify_ssl = _as_bool(os.getenv("TEST_FIREWALL_OPNSENSE_VERIFY_SSL"), True)
        apply_changes = _as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), False)
        timeout_str = os.getenv("TEST_FIREWALL_TIMEOUT")
        timeout = float(timeout_str) if timeout_str else 10.0

        if not base_url or not str(base_url).startswith(("http://", "https://")):
            self.skipTest("TEST_FIREWALL_OPNSENSE_BASE_URL no es válido")

        firewall = OPNsenseClient(
            base_url=base_url,
            api_key=api_key,
            api_secret=api_secret,
            verify_ssl=verify_ssl,
            timeout=timeout,
            apply_changes=apply_changes,
        )

        alias_ip = "mimosa_test_alias_ip"
        alias_ports = "mimosa_test_alias_ports"

        firewall.check_connection()  # 1
        firewall.create_alias(name=alias_ip, alias_type="host", description="ci-ip")  # 2
        firewall.create_alias(name=alias_ports, alias_type="port", description="ci-ports")  # 3
        self.assertTrue(firewall._alias_exists(alias_ip))  # type: ignore[attr-defined]  # 4
        self.assertTrue(firewall._alias_exists(alias_ports))  # type: ignore[attr-defined]
        firewall._request("POST", f"/api/firewall/alias/deleteItem/{alias_ip}")  # type: ignore[attr-defined]  # 5
        firewall._request("POST", f"/api/firewall/alias/deleteItem/{alias_ports}")  # type: ignore[attr-defined]
        self.assertFalse(firewall._alias_exists(alias_ip))  # type: ignore[attr-defined]  # 6
        self.assertFalse(firewall._alias_exists(alias_ports))  # type: ignore[attr-defined]
        firewall.create_alias(name=alias_ports, alias_type="port", description="ci-ports")  # 7
        firewall._request("POST", f"/api/firewall/alias_util/add/{alias_ports}", json={"address": "1234"})  # type: ignore[attr-defined]
        firewall._request("POST", f"/api/firewall/alias_util/add/{alias_ports}", json={"address": "4321"})  # type: ignore[attr-defined]
        ports = firewall._list_alias_values(alias_ports)  # type: ignore[attr-defined]  # 8
        self.assertIn("1234", ports)
        self.assertIn("4321", ports)
        firewall._request("POST", f"/api/firewall/alias_util/delete/{alias_ports}", json={"address": "4321"})  # type: ignore[attr-defined]  # 9
        ports_after = firewall._list_alias_values(alias_ports)  # type: ignore[attr-defined]
        self.assertIn("1234", ports_after)
        self.assertNotIn("4321", ports_after)
        firewall._request("POST", f"/api/firewall/alias/deleteItem/{alias_ports}")  # type: ignore[attr-defined]  # 10
        self.assertFalse(firewall._alias_exists(alias_ports))  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()

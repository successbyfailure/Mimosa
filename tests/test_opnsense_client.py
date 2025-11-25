import os
import unittest

import httpx

from conftest import ensure_test_env
from mimosa.core.sense import OPNsenseClient


def _as_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


class OPNsenseClientLiveTests(unittest.TestCase):
    required_vars = {
        "TEST_FIREWALL_OPNSENSE_BASE_URL",
        "TEST_FIREWALL_OPNSENSE_API_KEY",
        "TEST_FIREWALL_OPNSENSE_API_SECRET",
    }

    def setUp(self) -> None:
        if not ensure_test_env(self.required_vars):
            self.skipTest("Entorno de pruebas OPNsense incompleto")

        self.base_url = os.getenv("TEST_FIREWALL_OPNSENSE_BASE_URL")
        api_key = os.getenv("TEST_FIREWALL_OPNSENSE_API_KEY")
        api_secret = os.getenv("TEST_FIREWALL_OPNSENSE_API_SECRET")
        verify_ssl = _as_bool(os.getenv("TEST_FIREWALL_OPNSENSE_VERIFY_SSL"), True)
        apply_changes = _as_bool(os.getenv("TEST_FIREWALL_APPLY_CHANGES"), False)
        timeout_str = os.getenv("TEST_FIREWALL_TIMEOUT")
        timeout = float(timeout_str) if timeout_str else 10.0

        if not self.base_url or not str(self.base_url).startswith(("http://", "https://")):
            self.skipTest("TEST_FIREWALL_OPNSENSE_BASE_URL no es válido")

        self.firewall = OPNsenseClient(
            base_url=self.base_url,
            api_key=api_key,
            api_secret=api_secret,
            verify_ssl=verify_ssl,
            timeout=timeout,
            apply_changes=apply_changes,
        )

        try:
            status = self.firewall.get_status()
        except httpx.HTTPStatusError as exc:
            self.skipTest(f"Conexión OPNsense no disponible: {exc}")

        if not status.get("available"):
            self.skipTest("Firewall OPNsense no disponible")

        self.test_ip = "198.51.100.20"
        self.original_ports = self.firewall.get_ports()
        self.addCleanup(self._restore_state)

    def _restore_state(self) -> None:
        try:
            self.firewall.unblock_ip(self.test_ip)
        except httpx.HTTPError:
            pass

        original_tcp_ports = self.original_ports.get("tcp", [])
        try:
            self.firewall.set_ports_alias("tcp", original_tcp_ports)
        except httpx.HTTPError:
            pass

    def test_live_opnsense_alias_workflow(self) -> None:
        self.firewall.block_ip(self.test_ip, "ci-ip")
        table = self.firewall.list_table()
        self.assertIn(self.test_ip, table)

        self.firewall.unblock_ip(self.test_ip)
        self.assertNotIn(self.test_ip, self.firewall.list_table())

        self.firewall.add_to_blacklist("203.0.113.5", "deny")
        blacklist = self.firewall.list_blacklist()
        self.assertIn("203.0.113.5", blacklist)
        self.firewall.remove_from_blacklist("203.0.113.5")
        self.assertNotIn("203.0.113.5", self.firewall.list_blacklist())

        self.firewall.set_ports_alias("tcp", [1234, 4321])
        ports = self.firewall.get_ports()["tcp"]
        self.assertIn(1234, ports)
        self.assertIn(4321, ports)


if __name__ == "__main__":
    unittest.main()

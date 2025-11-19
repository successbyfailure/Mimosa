"""Integración simplificada con un firewall externo."""
from typing import List

from mimosa.core.api import FirewallGateway


class DummyFirewall(FirewallGateway):
    """Implementación de ejemplo para pruebas locales."""

    def __init__(self) -> None:
        self._blocked: List[str] = []

    def block_ip(self, ip: str, reason: str) -> None:
        if ip not in self._blocked:
            self._blocked.append(ip)
        print(f"[FIREWALL] Bloqueando {ip}: {reason}")

    def list_blocks(self) -> List[str]:
        return list(self._blocked)

    def unblock_ip(self, ip: str) -> None:
        if ip in self._blocked:
            self._blocked.remove(ip)
        print(f"[FIREWALL] Desbloqueando {ip}")

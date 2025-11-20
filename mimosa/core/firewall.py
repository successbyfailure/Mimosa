"""Integración simplificada con un firewall externo."""
from typing import List

from mimosa.core.api import FirewallGateway


class DummyFirewall(FirewallGateway):
    """Implementación de ejemplo para pruebas locales."""

    def __init__(self) -> None:
        self._blocked: List[str] = []

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:
        if ip not in self._blocked:
            self._blocked.append(ip)
        suffix = f" por {duration_minutes}m" if duration_minutes else ""
        print(f"[FIREWALL] Bloqueando {ip}: {reason}{suffix}")

    def list_blocks(self) -> List[str]:
        return list(self._blocked)

    def unblock_ip(self, ip: str) -> None:
        if ip in self._blocked:
            self._blocked.remove(ip)
        print(f"[FIREWALL] Desbloqueando {ip}")

    def check_connection(self) -> None:
        """Dummy siempre responde como disponible."""

        return None

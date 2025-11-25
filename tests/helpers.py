from __future__ import annotations

from typing import Dict, List

from mimosa.core.api import FirewallGateway


class MemoryFirewall(FirewallGateway):
    """Firewall en memoria para pruebas unitarias."""

    def __init__(self) -> None:
        self._blocks: List[str] = []
        self._ports: Dict[str, List[int]] = {"tcp": [], "udp": []}
        self._blacklist: List[str] = []

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:  # noqa: ARG002
        if ip not in self._blocks:
            self._blocks.append(ip)

    def list_blocks(self) -> List[str]:
        return list(self._blocks)

    def unblock_ip(self, ip: str) -> None:
        if ip in self._blocks:
            self._blocks.remove(ip)

    def apply_changes(self) -> None:
        return None

    def check_connection(self) -> None:
        return None

    def ensure_ready(self) -> None:
        return None

    def get_status(self) -> dict:
        return {"available": True, "alias_ready": True}

    def get_ports(self) -> Dict[str, List[int]]:
        return {protocol: list(ports) for protocol, ports in self._ports.items()}

    def set_ports_alias(self, protocol: str, ports: List[int]) -> None:
        self._ports[protocol] = sorted({int(port) for port in ports})

    def list_blacklist(self) -> List[str]:
        return list(self._blacklist)

    def add_to_blacklist(self, ip: str, reason: str = "") -> None:  # noqa: ARG002
        if ip not in self._blacklist:
            self._blacklist.append(ip)

    def remove_from_blacklist(self, ip: str) -> None:
        if ip in self._blacklist:
            self._blacklist.remove(ip)

    def block_rule_stats(self) -> Dict[str, object]:
        raise NotImplementedError("Stats no disponibles en MemoryFirewall")

    def flush_states(self) -> None:
        raise NotImplementedError("Flush no disponible en MemoryFirewall")

from __future__ import annotations

from typing import Dict, List

from mimosa.core.api import FirewallGateway


class InMemoryFirewall(FirewallGateway):
    """Implementación en memoria para pruebas unitarias."""

    def __init__(self) -> None:
        self.blocks: List[str] = []
        self.blacklist: List[str] = []
        self.ports: Dict[str, List[int]] = {"tcp": [], "udp": []}

    def apply_changes(self) -> None:
        return None

    def get_status(self) -> dict:
        return {"available": True, "alias_ready": True, "alias_created": False}

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:  # noqa: ARG002
        if ip not in self.blocks:
            self.blocks.append(ip)

    def list_blocks(self) -> List[str]:
        return list(self.blocks)

    def unblock_ip(self, ip: str) -> None:
        if ip in self.blocks:
            self.blocks.remove(ip)

    def ensure_ready(self) -> None:
        return None

    def check_connection(self) -> None:
        return None

    def get_ports(self) -> Dict[str, List[int]]:
        return {protocol: list(values) for protocol, values in self.ports.items()}

    def list_blacklist(self) -> List[str]:
        return list(self.blacklist)

    def add_to_blacklist(self, ip: str, reason: str = "") -> None:  # noqa: ARG002
        if ip not in self.blacklist:
            self.blacklist.append(ip)

    def remove_from_blacklist(self, ip: str) -> None:
        if ip in self.blacklist:
            self.blacklist.remove(ip)

    def block_rule_stats(self) -> Dict[str, object]:
        return {"supported": False}

    def flush_states(self) -> None:
        return None

"""Gestión de bloqueos de IPs sospechosas."""
from typing import Dict, List


class BlockManager:
    """Registra y maneja bloqueos de direcciones IP."""

    def __init__(self) -> None:
        self._blocks: Dict[str, str] = {}

    def add(self, ip: str, reason: str) -> None:
        """Añade un bloqueo en memoria."""

        self._blocks[ip] = reason

    def remove(self, ip: str) -> None:
        """Elimina un bloqueo registrado."""

        self._blocks.pop(ip, None)

    def list(self) -> List[str]:
        """Devuelve la lista de IPs bloqueadas."""

        return list(self._blocks.keys())

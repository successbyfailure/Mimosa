"""Gestión de bloqueos de IPs sospechosas."""
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List


@dataclass
class BlockEntry:
    """Entrada de bloqueo registrada localmente."""

    ip: str
    reason: str
    created_at: datetime


class BlockManager:
    """Registra y maneja bloqueos de direcciones IP."""

    def __init__(self) -> None:
        self._blocks: Dict[str, BlockEntry] = {}

    def add(self, ip: str, reason: str) -> None:
        """Añade un bloqueo en memoria."""

        self._blocks[ip] = BlockEntry(ip=ip, reason=reason, created_at=datetime.utcnow())

    def remove(self, ip: str) -> None:
        """Elimina un bloqueo registrado."""

        self._blocks.pop(ip, None)

    def list(self) -> List[BlockEntry]:
        """Devuelve la lista de IPs bloqueadas ordenada por fecha."""

        return sorted(self._blocks.values(), key=lambda entry: entry.created_at, reverse=True)

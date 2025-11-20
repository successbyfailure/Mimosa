"""Gestión de bloqueos de IPs sospechosas."""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict


@dataclass
class BlockEntry:
    """Entrada de bloqueo registrada localmente."""

    ip: str
    reason: str
    created_at: datetime
    expires_at: Optional[datetime] = None


class BlockManager:
    """Registra y maneja bloqueos de direcciones IP."""

    def __init__(self) -> None:
        self._blocks: Dict[str, BlockEntry] = {}
        self._history: List[BlockEntry] = []

    def add(self, ip: str, reason: str, duration_minutes: Optional[int] = None) -> BlockEntry:
        """Añade un bloqueo en memoria y devuelve la entrada creada."""

        now = datetime.utcnow()
        expires_at = (
            now + timedelta(minutes=duration_minutes)
            if duration_minutes and duration_minutes > 0
            else None
        )
        entry = BlockEntry(ip=ip, reason=reason, created_at=now, expires_at=expires_at)
        self._blocks[ip] = entry
        self._history.append(entry)
        return entry

    def remove(self, ip: str) -> None:
        """Elimina un bloqueo registrado."""

        self._blocks.pop(ip, None)

    def purge_expired(self) -> None:
        """Elimina de la lista activa cualquier bloqueo caducado."""

        now = datetime.utcnow()
        expired = [ip for ip, entry in self._blocks.items() if entry.expires_at and entry.expires_at <= now]
        for ip in expired:
            self.remove(ip)

    def list(self, *, include_expired: bool = False) -> List[BlockEntry]:
        """Devuelve la lista de IPs bloqueadas ordenada por fecha."""

        self.purge_expired()
        entries = list(self._blocks.values()) if include_expired else [entry for entry in self._blocks.values() if not entry.expires_at or entry.expires_at > datetime.utcnow()]
        return sorted(entries, key=lambda entry: entry.created_at, reverse=True)

    def history(self) -> List[BlockEntry]:
        """Devuelve el historial completo de bloqueos (incluidos expirados)."""

        return sorted(self._history, key=lambda entry: entry.created_at, reverse=True)

    def timeline(self, window: timedelta, *, bucket: str = "hour") -> List[Dict[str, str | int]]:
        """Devuelve recuentos de bloqueos agrupados por intervalo temporal."""

        cutoff = datetime.utcnow() - window
        format_map = {
            "day": "%Y-%m-%d",
            "hour": "%Y-%m-%d %H:00",
            "minute": "%Y-%m-%d %H:%M",
        }
        if bucket not in format_map:
            raise ValueError(f"Bucket desconocido: {bucket}")

        pattern = format_map[bucket]
        grouped: Dict[str, int] = defaultdict(int)
        for entry in self._history:
            if entry.created_at < cutoff:
                continue
            grouped[entry.created_at.strftime(pattern)] += 1

        return [
            {"bucket": bucket_label, "count": count}
            for bucket_label, count in sorted(grouped.items())
        ]

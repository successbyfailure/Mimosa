"""Modelo de dominio para bloqueos de IPs."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Optional


@dataclass
class BlockEntry:
    """Entrada de bloqueo registrada localmente.

    Representa un bloqueo de IP con toda su metadata asociada.
    Este es un modelo de dominio puro sin lógica de persistencia.
    """

    id: int
    ip: str
    reason: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    source: str = "manual"
    active: bool = True
    synced_at: Optional[datetime] = None
    removed_at: Optional[datetime] = None
    sync_with_firewall: bool = True
    trigger_offense_id: Optional[int] = None
    rule_id: Optional[str] = None
    firewall_id: Optional[str] = None
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    reason_code: Optional[str] = None
    expires_at_epoch: Optional[int] = None

    def to_dict(self) -> Dict[str, object]:
        """Serializa el bloqueo a diccionario con fechas en formato ISO."""
        payload = asdict(self)

        def _iso(dt: Optional[datetime]) -> Optional[str]:
            if not dt:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat()

        payload["created_at"] = _iso(self.created_at)
        payload["expires_at"] = _iso(self.expires_at)
        payload["synced_at"] = _iso(self.synced_at)
        payload["removed_at"] = _iso(self.removed_at)
        payload["acknowledged_at"] = _iso(self.acknowledged_at)
        return payload

    def is_expired(self, now: datetime) -> bool:
        """Verifica si el bloqueo ha expirado."""
        return self.expires_at is not None and self.expires_at <= now

    def is_active(self, now: datetime) -> bool:
        """Verifica si el bloqueo está activo y no ha expirado."""
        return self.active and not self.is_expired(now)


__all__ = ["BlockEntry"]

"""Modelos de dominio para reglas de escalado de ofensas."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Optional


@dataclass
class OffenseEvent:
    """Evento de ofensa enriquecido para evaluación de reglas.

    Representa un evento que será evaluado contra las reglas
    para determinar si debe escalar a bloqueo.
    """

    source_ip: str
    plugin: str
    event_id: str
    severity: str
    description: str


@dataclass
class OffenseRule:
    """Regla que define cuándo una ofensa debe escalar a bloqueo.

    Permite configurar patrones de matching (plugin, event_id, severity)
    y umbrales (ofensas por hora, totales, bloqueos previos) para
    decidir automáticamente cuándo bloquear una IP.
    """

    plugin: str = "*"
    event_id: str = "*"
    severity: str = "*"
    description: str = "*"
    min_last_hour: int = 0
    min_total: int = 0
    min_blocks_total: int = 0
    block_minutes: Optional[int] = None
    id: Optional[int] = None

    def matches(
        self,
        event: OffenseEvent,
        *,
        last_hour: int,
        total: int,
        total_blocks: int,
    ) -> bool:
        """Comprueba si la regla aplica al evento y cumple umbrales."""
        return self.matches_fields(event) and self.passes_thresholds(
            last_hour=last_hour,
            total=total,
            total_blocks=total_blocks,
        )

    def matches_fields(self, event: OffenseEvent) -> bool:
        """Verifica si los campos del evento coinciden con los patrones de la regla."""
        if not self._match(self.plugin, event.plugin):
            return False
        if not self._match(self.event_id, event.event_id):
            return False
        if not self._match(self.severity, event.severity):
            return False
        if not self._match(self.description, event.description):
            return False
        return True

    def passes_thresholds(self, *, last_hour: int, total: int, total_blocks: int) -> bool:
        """Verifica si se cumplen los umbrales de la regla."""
        return (
            self._passes_threshold(last_hour, self.min_last_hour)
            and self._passes_threshold(total, self.min_total)
            and self._passes_threshold(total_blocks, self.min_blocks_total)
        )

    def _is_wildcard(self, field: str) -> bool:
        return field == "*" or field == ""

    def _match(self, field: str, value: str) -> bool:
        """Verifica si un valor coincide con un patrón (soporta wildcards)."""
        if self._is_wildcard(field):
            return True
        if "*" in field or "?" in field:
            return fnmatchcase(value, field)
        return field == value

    def _passes_threshold(self, observed: int, threshold: int) -> bool:
        """Verifica si un valor observado supera un umbral."""
        if threshold <= 0:
            return True
        return observed > threshold

    def reason_for(
        self, event: OffenseEvent, *, last_hour: int, total: int, total_blocks: int
    ) -> str:
        """Genera mensaje de razón para el bloqueo basado en la regla."""
        base = self.description if self.description != "*" else event.description
        summary = (
            f"{base} · {total} ofensas totales, {last_hour} en 1h, "
            f"{total_blocks} bloqueos previos"
        )
        return summary


__all__ = ["OffenseEvent", "OffenseRule"]

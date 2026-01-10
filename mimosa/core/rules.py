"""Motor sencillo de reglas que promueven ofensas a bloqueos."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Iterable, List, Optional

import sqlite3

from mimosa.core.storage import DEFAULT_DB_PATH, ensure_database

from mimosa.core.blocking import BlockEntry, BlockManager
from mimosa.core.offenses import OffenseStore


@dataclass
class OffenseEvent:
    """Evento de ofensa enriquecido para evaluación de reglas."""

    source_ip: str
    plugin: str
    event_id: str
    severity: str
    description: str


@dataclass
class OffenseRule:
    """Regla que define cuándo una ofensa debe escalar a bloqueo."""

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

        def _is_wildcard(field: str) -> bool:
            return field == "*" or field == ""

        def _match(field: str, value: str) -> bool:
            if _is_wildcard(field):
                return True
            if "*" in field or "?" in field:
                return fnmatchcase(value, field)
            return field == value

        def _passes_threshold(observed: int, threshold: int) -> bool:
            if threshold <= 0:
                return True
            return observed > threshold

        if not _match(self.plugin, event.plugin):
            return False
        if not _match(self.event_id, event.event_id):
            return False
        if not _match(self.severity, event.severity):
            return False
        if not _match(self.description, event.description):
            return False
        return (
            _passes_threshold(last_hour, self.min_last_hour)
            and _passes_threshold(total, self.min_total)
            and _passes_threshold(total_blocks, self.min_blocks_total)
        )

    def reason_for(
        self, event: OffenseEvent, *, last_hour: int, total: int, total_blocks: int
    ) -> str:
        base = self.description if self.description != "*" else event.description
        summary = (
            f"{base} · {total} ofensas totales, {last_hour} en 1h, "
            f"{total_blocks} bloqueos previos"
        )
        return summary


class OffenseRuleStore:
    """Persistencia simple de reglas de escalado de ofensas."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def list(self) -> List[OffenseRule]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, plugin, event_id, severity, description, min_last_hour, min_total,
                       min_blocks_total, block_minutes
                FROM offense_rules
                ORDER BY id ASC;
                """
            ).fetchall()

        return [
            OffenseRule(
                id=row[0],
                plugin=row[1],
                event_id=row[2],
                severity=row[3],
                description=row[4],
                min_last_hour=row[5],
                min_total=row[6],
                min_blocks_total=row[7],
                block_minutes=row[8],
            )
            for row in rows
        ]

    def add(self, rule: OffenseRule) -> OffenseRule:
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO offense_rules
                    (plugin, event_id, severity, description, min_last_hour, min_total, min_blocks_total, block_minutes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    rule.plugin,
                    rule.event_id,
                    rule.severity,
                    rule.description,
                    rule.min_last_hour,
                    rule.min_total,
                    rule.min_blocks_total,
                    rule.block_minutes,
                ),
            )
            rule.id = cursor.lastrowid
        return rule

    def update(self, rule_id: int, rule: OffenseRule) -> Optional[OffenseRule]:
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE offense_rules
                SET plugin = ?, event_id = ?, severity = ?, description = ?,
                    min_last_hour = ?, min_total = ?, min_blocks_total = ?, block_minutes = ?
                WHERE id = ?;
                """,
                (
                    rule.plugin,
                    rule.event_id,
                    rule.severity,
                    rule.description,
                    rule.min_last_hour,
                    rule.min_total,
                    rule.min_blocks_total,
                    rule.block_minutes,
                    rule_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
        rule.id = rule_id
        return rule

    def delete(self, rule_id: int) -> None:
        with self._connection() as conn:
            conn.execute("DELETE FROM offense_rules WHERE id = ?;", (rule_id,))


class RuleManager:
    """Gestiona reglas y genera bloqueos en base a ofensas observadas."""

    def __init__(
        self,
        offense_store: OffenseStore,
        block_manager: BlockManager,
        firewall_gateway: "FirewallGateway",
        *,
        rules: Optional[Iterable[OffenseRule]] = None,
    ) -> None:
        self.offense_store = offense_store
        self.block_manager = block_manager
        self.firewall_gateway = firewall_gateway
        self.rules: List[OffenseRule] = list(rules) if rules else [OffenseRule()]

    def add_rule(self, rule: OffenseRule) -> None:
        self.rules.append(rule)

    def process_offense(self, event: OffenseEvent) -> Optional[BlockEntry]:
        """Evalúa las reglas y aplica el primer bloqueo coincidente."""

        if event.source_ip in self.block_manager._blocks:  # pragma: no cover - acceso intencional
            return self.block_manager._blocks[event.source_ip]

        sync_with_firewall = self.block_manager.should_sync(event.source_ip)

        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        last_hour_count = self.offense_store.count_by_ip_since(event.source_ip, last_hour)
        total_count = self.offense_store.count_by_ip(event.source_ip)
        block_count = self.block_manager.count_for_ip(event.source_ip)

        for rule in self.rules:
            if not rule.matches(
                event,
                last_hour=last_hour_count,
                total=total_count,
                total_blocks=block_count,
            ):
                continue

            duration = (
                rule.block_minutes
                if rule.block_minutes is not None
                else self.block_manager.default_duration_minutes
            )
            reason = rule.reason_for(
                event,
                last_hour=last_hour_count,
                total=total_count,
                total_blocks=block_count,
            )
            entry = self.block_manager.add(
                event.source_ip,
                reason,
                duration_minutes=duration,
                source=f"rule:{rule.plugin}/{rule.event_id}",
            )
            if sync_with_firewall:
                duration_for_firewall: Optional[int] = None
                if entry.expires_at:
                    delta = entry.expires_at - datetime.utcnow()
                    duration_for_firewall = max(int(delta.total_seconds() // 60), 1)
                self.firewall_gateway.block_ip(
                    event.source_ip,
                    reason,
                    duration_minutes=duration_for_firewall,
                )
            return entry

        return None

    def unblock_ip(self, ip: str) -> None:
        """Elimina un bloqueo tanto local como en el firewall."""

        self.block_manager.remove(ip)
        self.firewall_gateway.unblock_ip(ip)


__all__ = ["OffenseEvent", "OffenseRule", "OffenseRuleStore", "RuleManager"]

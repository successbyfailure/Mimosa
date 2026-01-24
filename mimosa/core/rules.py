"""Motor sencillo de reglas que promueven ofensas a bloqueos.

ARQUITECTURA: Este módulo está en migración a Clean Architecture.
- Modelos de dominio → mimosa.core.domain.rule
- Repository (en desarrollo) → mimosa.core.repositories.rule_repository
- Service (futuro) → mimosa.core.services.rule_service

Ver MIGRATION_PLAN.md para detalles completos.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Optional


from mimosa.core.database import DEFAULT_DB_PATH, get_database, insert_returning_id
from mimosa.core.storage import ensure_database

from mimosa.core.blocking import BlockEntry, BlockManager
from mimosa.core.offenses import OffenseStore

# Importar modelos de dominio desde nueva ubicación
from mimosa.core.domain.rule import OffenseEvent, OffenseRule  # noqa: F401

# Re-export para backward compatibility (TODO: Remover en 2.0.0)
__all__ = ["OffenseEvent", "OffenseRule", "OffenseRuleStore", "RuleManager"]


# Nota: La clase OffenseRule original incluía métodos de lógica.
# Ahora se importa desde domain/, donde mantiene la misma implementación.
# En el futuro, esta lógica podría moverse a un RuleMatchingService.


class OffenseRuleStore:
    """Persistencia simple de reglas de escalado de ofensas."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)
        self._db = get_database(db_path=self.db_path)

    def _connection(self):
        return self._db.connect()

    def list(self) -> List[OffenseRule]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, name, plugin, event_id, severity, description, min_last_hour, min_total,
                       min_blocks_total, block_minutes, enabled
                FROM offense_rules
                ORDER BY id ASC;
                """
            ).fetchall()

        return [
            OffenseRule(
                id=row[0],
                name=row[1],
                plugin=row[2],
                event_id=row[3],
                severity=row[4],
                description=row[5],
                min_last_hour=row[6],
                min_total=row[7],
                min_blocks_total=row[8],
                block_minutes=row[9],
                enabled=bool(row[10]) if len(row) > 10 else True,
            )
            for row in rows
        ]

    def get(self, rule_id: int) -> Optional[OffenseRule]:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT id, name, plugin, event_id, severity, description, min_last_hour, min_total,
                       min_blocks_total, block_minutes, enabled
                FROM offense_rules
                WHERE id = ?;
                """,
                (rule_id,),
            ).fetchone()
        if not row:
            return None
        return OffenseRule(
            id=row[0],
            name=row[1],
            plugin=row[2],
            event_id=row[3],
            severity=row[4],
            description=row[5],
            min_last_hour=row[6],
            min_total=row[7],
            min_blocks_total=row[8],
            block_minutes=row[9],
            enabled=bool(row[10]) if len(row) > 10 else True,
        )

    def add(self, rule: OffenseRule) -> OffenseRule:
        with self._connection() as conn:
            rule.id = insert_returning_id(
                conn,
                """
                INSERT INTO offense_rules
                    (name, plugin, event_id, severity, description, min_last_hour, min_total,
                     min_blocks_total, block_minutes, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    rule.name,
                    rule.plugin,
                    rule.event_id,
                    rule.severity,
                    rule.description,
                    rule.min_last_hour,
                    rule.min_total,
                    rule.min_blocks_total,
                    rule.block_minutes,
                    int(rule.enabled),
                ),
                self._db.backend,
            )
        return rule

    def update(self, rule_id: int, rule: OffenseRule) -> Optional[OffenseRule]:
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE offense_rules
                SET name = ?, plugin = ?, event_id = ?, severity = ?, description = ?,
                    min_last_hour = ?, min_total = ?, min_blocks_total = ?, block_minutes = ?, enabled = ?
                WHERE id = ?;
                """,
                (
                    rule.name,
                    rule.plugin,
                    rule.event_id,
                    rule.severity,
                    rule.description,
                    rule.min_last_hour,
                    rule.min_total,
                    rule.min_blocks_total,
                    rule.block_minutes,
                    int(rule.enabled),
                    rule_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
        rule.id = rule_id
        return rule

    def toggle(self, rule_id: int) -> bool:
        """Activa o desactiva una regla. Retorna el nuevo estado (True = enabled)."""
        with self._connection() as conn:
            # Obtener estado actual
            row = conn.execute(
                "SELECT enabled FROM offense_rules WHERE id = ?;", (rule_id,)
            ).fetchone()
            if not row:
                return False

            # Invertir estado
            new_state = not bool(row[0])
            conn.execute(
                "UPDATE offense_rules SET enabled = ? WHERE id = ?;",
                (int(new_state), rule_id),
            )
            return new_state

    def set_enabled(self, rule_id: int, enabled: bool) -> bool:
        """Fuerza el estado de una regla. Retorna False si no existe."""
        with self._connection() as conn:
            cursor = conn.execute(
                "UPDATE offense_rules SET enabled = ? WHERE id = ?;",
                (int(enabled), rule_id),
            )
            if cursor.rowcount == 0:
                return False
        return True

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

        self.block_manager.purge_expired(firewall_gateway=self.firewall_gateway)

        # Usar método público en vez de acceso directo a _blocks
        existing_block = self.block_manager.get_active_block(event.source_ip)
        if existing_block:
            return existing_block

        sync_with_firewall = self.block_manager.should_sync(event.source_ip)

        now = datetime.now(timezone.utc)
        last_hour = now - timedelta(hours=1)
        last_hour_count = self.offense_store.count_by_ip_since(event.source_ip, last_hour)
        total_count = self.offense_store.count_by_ip(event.source_ip)
        block_count = self.block_manager.count_for_ip(event.source_ip)

        for rule in self.rules:
            # Saltar reglas deshabilitadas
            if not rule.enabled:
                continue

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
                    delta = entry.expires_at - datetime.now(timezone.utc)
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

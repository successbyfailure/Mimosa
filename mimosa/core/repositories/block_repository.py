"""Repository para persistencia de bloqueos en SQLite."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from mimosa.core.domain import BlockEntry
from mimosa.core.storage import DEFAULT_DB_PATH, ensure_database


class BlockRepository:
    """Repositorio para operaciones CRUD de bloqueos."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def save(self, block: BlockEntry) -> BlockEntry:
        """Inserta un nuevo bloqueo en la base de datos."""
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO blocks (ip, reason, source, created_at, expires_at, active, sync_with_firewall)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    block.ip,
                    block.reason,
                    block.source,
                    block.created_at.isoformat(),
                    block.expires_at.isoformat() if block.expires_at else None,
                    int(block.active),
                    int(block.sync_with_firewall),
                ),
            )
            block.id = cursor.lastrowid
        return block

    def find_by_ip(self, ip: str) -> Optional[BlockEntry]:
        """Busca el bloqueo activo más reciente para una IP."""
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT id, ip, reason, source, created_at, expires_at, active,
                       synced_at, removed_at, sync_with_firewall
                FROM blocks
                WHERE ip = ? AND active = 1
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (ip,),
            ).fetchone()

        if not row:
            return None

        return self._row_to_block(row)

    def find_all_active(self) -> List[BlockEntry]:
        """Retorna todos los bloqueos activos."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, ip, reason, source, created_at, expires_at, active,
                       synced_at, removed_at, sync_with_firewall
                FROM blocks
                WHERE active = 1
                ORDER BY created_at DESC;
                """
            ).fetchall()

        return [self._row_to_block(row) for row in rows]

    def find_all(self) -> List[BlockEntry]:
        """Retorna todos los bloqueos (activos e inactivos)."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, ip, reason, source, created_at, expires_at, active,
                       synced_at, removed_at, sync_with_firewall
                FROM blocks
                ORDER BY created_at DESC;
                """
            ).fetchall()

        return [self._row_to_block(row) for row in rows]

    def find_by_ip_all(self, ip: str) -> List[BlockEntry]:
        """Retorna todos los bloqueos (activos e inactivos) para una IP específica."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, ip, reason, source, created_at, expires_at, active,
                       synced_at, removed_at, sync_with_firewall
                FROM blocks
                WHERE ip = ?
                ORDER BY created_at DESC;
                """,
                (ip,),
            ).fetchall()

        return [self._row_to_block(row) for row in rows]

    def mark_as_removed(self, ip: str, removed_at: datetime) -> None:
        """Marca un bloqueo como eliminado."""
        with self._connection() as conn:
            conn.execute(
                "UPDATE blocks SET active = 0, removed_at = ? WHERE ip = ? AND active = 1;",
                (removed_at.isoformat(), ip),
            )

    def update_synced_at(self, ip: str, synced_at: datetime) -> None:
        """Actualiza el timestamp de última sincronización."""
        with self._connection() as conn:
            conn.execute(
                "UPDATE blocks SET synced_at = ? WHERE ip = ? AND active = 1;",
                (synced_at.isoformat(), ip),
            )

    def delete_all(self) -> None:
        """Elimina todos los bloqueos (para testing o reset)."""
        with self._connection() as conn:
            conn.execute("DELETE FROM blocks;")

    def _row_to_block(self, row: tuple) -> BlockEntry:
        """Convierte una fila de la BD a un BlockEntry."""
        # Asegurar que todos los datetimes sean timezone-aware
        created_at = datetime.fromisoformat(row[4])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        expires_at = None
        if row[5]:
            expires_at = datetime.fromisoformat(row[5])
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

        synced_at = None
        if row[7]:
            synced_at = datetime.fromisoformat(row[7])
            if synced_at.tzinfo is None:
                synced_at = synced_at.replace(tzinfo=timezone.utc)

        removed_at = None
        if row[8]:
            removed_at = datetime.fromisoformat(row[8])
            if removed_at.tzinfo is None:
                removed_at = removed_at.replace(tzinfo=timezone.utc)

        return BlockEntry(
            id=row[0],
            ip=row[1],
            reason=row[2],
            source=row[3],
            created_at=created_at,
            expires_at=expires_at,
            active=bool(row[6]),
            synced_at=synced_at,
            removed_at=removed_at,
            sync_with_firewall=bool(row[9]) if len(row) > 9 else True,
        )


__all__ = ["BlockRepository"]

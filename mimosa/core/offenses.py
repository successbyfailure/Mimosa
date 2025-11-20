"""Persistencia local de ofensas en SQLite.

Este módulo proporciona una capa sencilla para almacenar ofensas
generadas por los distintos módulos de Mimosa en una base de datos
SQLite local. Facilita tanto el registro como la consulta reciente para
alimentar el dashboard y los mecanismos de correlación.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional


DEFAULT_DB_PATH = Path(os.getenv("MIMOSA_DB_PATH", "volumes/web/mimosa.db"))


@dataclass
class OffenseRecord:
    """Representa una ofensa registrada en el sistema."""

    id: int
    source_ip: str
    description: str
    severity: str
    created_at: datetime
    host: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    context: Optional[Dict[str, str]] = None


class OffenseStore:
    """Almacena y recupera ofensas desde SQLite."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT,
                    path TEXT,
                    user_agent TEXT,
                    context TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_offenses_created
                ON offenses(created_at);
                """
            )

    def record(
        self,
        *,
        source_ip: str,
        description: str,
        severity: str = "medio",
        host: Optional[str] = None,
        path: Optional[str] = None,
        user_agent: Optional[str] = None,
        context: Optional[Dict[str, str]] = None,
    ) -> OffenseRecord:
        """Inserta una ofensa y devuelve la fila creada."""

        created_at = datetime.utcnow()
        context_json = json.dumps(context) if context else None
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO offenses
                    (source_ip, description, severity, host, path, user_agent, context, created_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    source_ip,
                    description,
                    severity,
                    host,
                    path,
                    user_agent,
                    context_json,
                    created_at.isoformat(),
                ),
            )
            offense_id = cursor.lastrowid

        return OffenseRecord(
            id=offense_id,
            source_ip=source_ip,
            description=description,
            severity=severity,
            host=host,
            path=path,
            user_agent=user_agent,
            context=context,
            created_at=created_at,
        )

    def record_many(self, offenses: Iterable[Dict[str, str]]) -> None:
        """Inserta en bloque varias ofensas en una sola transacción."""

        with self._connection() as conn:
            rows = []
            for offense in offenses:
                created_at = offense.get("created_at") or datetime.utcnow().isoformat()
                rows.append(
                    (
                        offense.get("source_ip", "desconocido"),
                        offense.get("description", "Actividad sospechosa"),
                        offense.get("severity", "medio"),
                        offense.get("host"),
                        offense.get("path"),
                        offense.get("user_agent"),
                        json.dumps(offense.get("context")) if offense.get("context") else None,
                        created_at,
                    )
                )

            conn.executemany(
                """
                INSERT INTO offenses
                    (source_ip, description, severity, host, path, user_agent, context, created_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )

    def list_recent(self, limit: int = 50) -> List[OffenseRecord]:
        """Recupera las últimas ofensas registradas."""

        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, source_ip, description, severity, host, path, user_agent, context, created_at
                FROM offenses
                ORDER BY datetime(created_at) DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

        offenses: List[OffenseRecord] = []
        for row in rows:
            context = json.loads(row[7]) if row[7] else None
            offenses.append(
                OffenseRecord(
                    id=row[0],
                    source_ip=row[1],
                    description=row[2],
                    severity=row[3],
                    host=row[4],
                    path=row[5],
                    user_agent=row[6],
                    context=context,
                    created_at=datetime.fromisoformat(row[8]),
                )
            )

        return offenses


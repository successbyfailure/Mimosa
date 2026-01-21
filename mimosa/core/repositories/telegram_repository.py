"""Repository para persistencia de datos del bot de Telegram en SQLite."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from mimosa.core.domain.telegram import TelegramUser, TelegramInteraction
from mimosa.core.database import DEFAULT_DB_PATH, get_database, insert_returning_id
from mimosa.core.storage import ensure_database


class TelegramUserRepository:
    """Repositorio para operaciones CRUD de usuarios del bot de Telegram."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)
        self._db = get_database(db_path=self.db_path)

    def _connection(self):
        return self._db.connect()

    def save(self, user: TelegramUser) -> TelegramUser:
        """Inserta o actualiza un usuario en la base de datos."""
        with self._connection() as conn:
            new_id = insert_returning_id(
                conn,
                """
                INSERT INTO telegram_users
                (telegram_id, username, first_name, last_name, authorized,
                 authorized_at, authorized_by, first_seen, last_seen, interaction_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(telegram_id) DO UPDATE SET
                    username = excluded.username,
                    first_name = excluded.first_name,
                    last_name = excluded.last_name,
                    authorized = excluded.authorized,
                    authorized_at = excluded.authorized_at,
                    authorized_by = excluded.authorized_by,
                    last_seen = excluded.last_seen,
                    interaction_count = excluded.interaction_count;
                """,
                (
                    user.telegram_id,
                    user.username,
                    user.first_name,
                    user.last_name,
                    int(user.authorized),
                    user.authorized_at.isoformat() if user.authorized_at else None,
                    user.authorized_by,
                    user.first_seen.isoformat() if user.first_seen else None,
                    user.last_seen.isoformat() if user.last_seen else None,
                    user.interaction_count,
                ),
                self._db.backend,
            )
            if user.id == 0:
                if new_id:
                    user.id = new_id
                else:
                    row = conn.execute(
                        "SELECT id FROM telegram_users WHERE telegram_id = ? LIMIT 1;",
                        (user.telegram_id,),
                    ).fetchone()
                    if row:
                        user.id = int(row[0])
        return user

    def find_by_telegram_id(self, telegram_id: int) -> Optional[TelegramUser]:
        """Busca un usuario por su ID de Telegram."""
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT id, telegram_id, username, first_name, last_name,
                       authorized, authorized_at, authorized_by, first_seen,
                       last_seen, interaction_count
                FROM telegram_users
                WHERE telegram_id = ?;
                """,
                (telegram_id,),
            ).fetchone()

        if not row:
            return None

        return self._row_to_user(row)

    def find_all_authorized(self) -> List[TelegramUser]:
        """Retorna todos los usuarios autorizados."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, telegram_id, username, first_name, last_name,
                       authorized, authorized_at, authorized_by, first_seen,
                       last_seen, interaction_count
                FROM telegram_users
                WHERE authorized = 1
                ORDER BY authorized_at DESC;
                """
            ).fetchall()

        return [self._row_to_user(row) for row in rows]

    def find_all_unauthorized(self, limit: int = 50) -> List[TelegramUser]:
        """Retorna usuarios no autorizados que han interactuado con el bot."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, telegram_id, username, first_name, last_name,
                       authorized, authorized_at, authorized_by, first_seen,
                       last_seen, interaction_count
                FROM telegram_users
                WHERE authorized = 0 AND interaction_count > 0
                ORDER BY last_seen DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_user(row) for row in rows]

    def find_all(self) -> List[TelegramUser]:
        """Retorna todos los usuarios."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, telegram_id, username, first_name, last_name,
                       authorized, authorized_at, authorized_by, first_seen,
                       last_seen, interaction_count
                FROM telegram_users
                ORDER BY last_seen DESC;
                """
            ).fetchall()

        return [self._row_to_user(row) for row in rows]

    def authorize_user(
        self, telegram_id: int, authorized_by: str, authorized_at: datetime
    ) -> bool:
        """Autoriza a un usuario."""
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE telegram_users
                SET authorized = 1, authorized_at = ?, authorized_by = ?
                WHERE telegram_id = ?;
                """,
                (authorized_at.isoformat(), authorized_by, telegram_id),
            )
            return cursor.rowcount > 0

    def unauthorize_user(self, telegram_id: int) -> bool:
        """Desautoriza a un usuario."""
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE telegram_users
                SET authorized = 0, authorized_at = NULL, authorized_by = NULL
                WHERE telegram_id = ?;
                """,
                (telegram_id,),
            )
            return cursor.rowcount > 0

    def increment_interaction_count(self, telegram_id: int, last_seen: datetime) -> None:
        """Incrementa el contador de interacciones y actualiza last_seen."""
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE telegram_users
                SET interaction_count = interaction_count + 1, last_seen = ?
                WHERE telegram_id = ?;
                """,
                (last_seen.isoformat(), telegram_id),
            )

    def delete(self, telegram_id: int) -> bool:
        """Elimina un usuario."""
        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM telegram_users WHERE telegram_id = ?;",
                (telegram_id,),
            )
            return cursor.rowcount > 0

    def _row_to_user(self, row: tuple) -> TelegramUser:
        """Convierte una fila de la BD a un TelegramUser."""

        def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
            if not dt_str:
                return None
            dt = datetime.fromisoformat(dt_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt

        return TelegramUser(
            id=row[0],
            telegram_id=row[1],
            username=row[2],
            first_name=row[3],
            last_name=row[4],
            authorized=bool(row[5]),
            authorized_at=_parse_datetime(row[6]),
            authorized_by=row[7],
            first_seen=_parse_datetime(row[8]),
            last_seen=_parse_datetime(row[9]),
            interaction_count=row[10],
        )


class TelegramInteractionRepository:
    """Repositorio para operaciones CRUD de interacciones del bot de Telegram."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)
        self._db = get_database(db_path=self.db_path)

    def _connection(self):
        return self._db.connect()

    def save(self, interaction: TelegramInteraction) -> TelegramInteraction:
        """Inserta una nueva interacción en la base de datos."""
        with self._connection() as conn:
            interaction.id = insert_returning_id(
                conn,
                """
                INSERT INTO telegram_interactions
                (telegram_id, username, command, message, authorized, created_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    interaction.telegram_id,
                    interaction.username,
                    interaction.command,
                    interaction.message,
                    int(interaction.authorized),
                    interaction.created_at.isoformat()
                    if interaction.created_at
                    else datetime.now(timezone.utc).isoformat(),
                ),
                self._db.backend,
            )
        return interaction

    def find_recent(self, limit: int = 100) -> List[TelegramInteraction]:
        """Retorna las interacciones más recientes."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, telegram_id, username, command, message, authorized, created_at
                FROM telegram_interactions
                ORDER BY created_at DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_interaction(row) for row in rows]

    def find_by_telegram_id(
        self, telegram_id: int, limit: int = 50
    ) -> List[TelegramInteraction]:
        """Retorna las interacciones de un usuario específico."""
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, telegram_id, username, command, message, authorized, created_at
                FROM telegram_interactions
                WHERE telegram_id = ?
                ORDER BY created_at DESC
                LIMIT ?;
                """,
                (telegram_id, limit),
            ).fetchall()

        return [self._row_to_interaction(row) for row in rows]

    def count_total(self) -> int:
        """Retorna el total de interacciones registradas."""
        with self._connection() as conn:
            result = conn.execute(
                "SELECT COUNT(*) FROM telegram_interactions;"
            ).fetchone()
            return result[0] if result else 0

    def delete_old(self, days: int = 30) -> int:
        """Elimina interacciones más antiguas que X días."""
        cutoff = datetime.now(timezone.utc)
        cutoff = cutoff.replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timezone.timedelta(days=days)

        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM telegram_interactions WHERE created_at < ?;",
                (cutoff.isoformat(),),
            )
            return cursor.rowcount

    def _row_to_interaction(self, row: tuple) -> TelegramInteraction:
        """Convierte una fila de la BD a un TelegramInteraction."""
        created_at = None
        if row[6]:
            created_at = datetime.fromisoformat(row[6])
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)

        return TelegramInteraction(
            id=row[0],
            telegram_id=row[1],
            username=row[2],
            command=row[3],
            message=row[4],
            authorized=bool(row[5]),
            created_at=created_at,
        )


__all__ = ["TelegramUserRepository", "TelegramInteractionRepository"]

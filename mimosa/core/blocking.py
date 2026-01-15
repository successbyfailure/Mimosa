"""Gestión de bloqueos de IPs sospechosas con persistencia en SQLite.

ARQUITECTURA: Este módulo está en migración a Clean Architecture.
- Modelos de dominio → mimosa.core.domain.block
- Repository (en desarrollo) → mimosa.core.repositories.block_repository
- Service (futuro) → mimosa.core.services.blocking_service

Ver MIGRATION_PLAN.md para detalles completos.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional
import sqlite3
import ipaddress
import logging
import threading
from pathlib import Path

from mimosa.core.storage import DEFAULT_DB_PATH, ensure_database

# Importar modelo de dominio desde nueva ubicación
from mimosa.core.domain.block import BlockEntry  # noqa: F401

logger = logging.getLogger(__name__)

# Re-export para backward compatibility
# TODO: Remover en versión 2.0.0
__all__ = ["BlockEntry", "BlockManager"]


def _normalize_datetime(dt: datetime) -> datetime:
    """Normaliza datetime a timezone-aware UTC si es naive."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class BlockManager:
    """Registra y maneja bloqueos de direcciones IP.

    La información se persiste en SQLite y se mantiene sincronizada con el
    firewall remoto mediante ``sync_with_firewall``. No se asume la
    existencia de temporizadores en el firewall, por lo que las
    comprobaciones periódicas se realizan desde aquí.
    """

    def __init__(
        self,
        *,
        db_path: Path | str = DEFAULT_DB_PATH,
        default_duration_minutes: int = 60,
        sync_interval_seconds: int = 300,
        whitelist_checker: Callable[[str], bool] | None = None,
    ) -> None:
        self.db_path = ensure_database(db_path)
        self.default_duration_minutes = default_duration_minutes
        self.sync_interval_seconds = sync_interval_seconds
        self._blocks: Dict[str, BlockEntry] = {}
        self._history: List[BlockEntry] = []
        self._last_sync: Optional[datetime] = None
        self._should_sync = lambda ip: True
        self._lock = threading.Lock()  # Protección para acceso concurrente
        if whitelist_checker:
            self.set_whitelist_checker(whitelist_checker)
        self._load_state()
        self._load_settings()

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _deserialize_row(self, row: tuple) -> BlockEntry:
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

    # Persistencia y configuración -------------------------------------------------
    def _load_state(self) -> None:
        """Recupera el estado de bloqueos desde disco."""

        self._blocks.clear()
        self._history.clear()
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, ip, reason, source, created_at, expires_at, active, synced_at, removed_at, sync_with_firewall
                FROM blocks
                ORDER BY datetime(created_at) DESC;
                """
            ).fetchall()
        for row in rows:
            entry = self._deserialize_row(row)
            self._history.append(entry)
            if entry.active and (not entry.expires_at or entry.expires_at > datetime.now(timezone.utc)):
                self._blocks[entry.ip] = entry

    def _load_settings(self) -> None:
        with self._connection() as conn:
            rows = conn.execute("SELECT key, value FROM settings WHERE key LIKE 'block_%';").fetchall()
        settings = {row[0]: row[1] for row in rows}
        if "block_default_minutes" in settings:
            self.default_duration_minutes = int(settings["block_default_minutes"])
        if "block_sync_interval_seconds" in settings:
            self.sync_interval_seconds = int(settings["block_sync_interval_seconds"])
        # Persist defaults if table is empty
        if not settings:
            self._persist_settings()

    def _persist_settings(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO settings(key, value) VALUES('block_default_minutes', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value;
                """,
                (str(self.default_duration_minutes),),
            )
            conn.execute(
                """
                INSERT INTO settings(key, value) VALUES('block_sync_interval_seconds', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value;
                """,
                (str(self.sync_interval_seconds),),
            )

    # Operaciones principales ------------------------------------------------------
    def add(
        self,
        ip: str,
        reason: str,
        duration_minutes: Optional[int] = None,
        *,
        source: str = "manual",
        sync_with_firewall: bool = True,
    ) -> BlockEntry:
        """Añade un bloqueo en memoria y devuelve la entrada creada."""

        # Validar que sea una IP válida
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            logger.error(f"IP inválida rechazada: {ip} - {exc}")
            raise ValueError(f"IP inválida: {ip}") from exc

        now = datetime.now(timezone.utc)
        duration = duration_minutes if duration_minutes is not None else self.default_duration_minutes
        expires_at = (now + timedelta(minutes=duration)) if duration and duration > 0 else None

        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO blocks (ip, reason, source, created_at, expires_at, active, sync_with_firewall)
                VALUES (?, ?, ?, ?, ?, 1, ?);
                """,
                (
                    ip,
                    reason,
                    source,
                    now.isoformat(),
                    expires_at.isoformat() if expires_at else None,
                    int(sync_with_firewall),
                ),
            )
            entry_id = cursor.lastrowid

        entry = BlockEntry(
            id=entry_id,
            ip=ip,
            reason=reason,
            created_at=now,
            expires_at=expires_at,
            source=source,
            sync_with_firewall=sync_with_firewall,
        )

        with self._lock:
            self._blocks[ip] = entry
            self._history.append(entry)

        logger.info(f"IP bloqueada: {ip} (razón: {reason}, fuente: {source}, duración: {duration}min)")
        return entry

    def remove(self, ip: str) -> None:
        """Marca un bloqueo como inactivo y lo elimina de la caché."""

        now = datetime.now(timezone.utc)
        with self._connection() as conn:
            conn.execute(
                "UPDATE blocks SET active = 0, removed_at = ? WHERE ip = ?;",
                (now.isoformat(), ip),
            )

        with self._lock:
            removed = self._blocks.pop(ip, None)
            for entry in self._history:
                if entry.ip == ip and entry.removed_at is None:
                    entry.removed_at = now
                    break

        if removed:
            logger.info(f"IP desbloqueada: {ip}")
        else:
            logger.warning(f"Intento de desbloquear IP no encontrada: {ip}")

    def purge_expired(self, *, firewall_gateway: "FirewallGateway" | None = None) -> List[BlockEntry]:
        """Elimina de la lista activa cualquier bloqueo caducado."""

        now = datetime.now(timezone.utc)
        expired: List[BlockEntry] = []

        with self._lock:
            for ip, entry in list(self._blocks.items()):
                if entry.expires_at and entry.expires_at <= now:
                    expired.append(entry)

        # Remover fuera del lock para evitar deadlock
        for entry in expired:
            self.remove(entry.ip)
            if firewall_gateway:
                firewall_gateway.unblock_ip(entry.ip)

        if expired:
            logger.info(f"Purgados {len(expired)} bloqueos expirados")

        return expired

    def get_active_block(self, ip: str) -> Optional[BlockEntry]:
        """Obtiene el bloqueo activo para una IP (thread-safe)."""
        with self._lock:
            return self._blocks.get(ip)

    def list(self, *, include_expired: bool = False) -> List[BlockEntry]:
        """Devuelve la lista de IPs bloqueadas ordenada por fecha."""

        self.purge_expired()
        with self._lock:
            entries = list(self._blocks.values()) if not include_expired else list(self._history)
        return sorted(entries, key=lambda entry: entry.created_at, reverse=True)

    def history(self) -> List[BlockEntry]:
        """Devuelve el historial completo de bloqueos (incluidos expirados)."""

        return sorted(self._history, key=lambda entry: entry.created_at, reverse=True)

    def latest(self) -> Optional[BlockEntry]:
        """Devuelve el último bloqueo registrado."""

        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT id, ip, reason, source, created_at, expires_at, active, synced_at, removed_at, sync_with_firewall
                FROM blocks
                ORDER BY id DESC
                LIMIT 1;
                """
            ).fetchone()
        if not row:
            return None
        return self._deserialize_row(row)

    def history_for_ip(self, ip: str) -> List[BlockEntry]:
        return [entry for entry in self._history if entry.ip == ip]

    def count_for_ip(self, ip: str) -> int:
        """Número total de bloqueos registrados para una IP."""

        return len(self.history_for_ip(ip))

    def count_all(self) -> int:
        """Número total de bloqueos registrados."""

        return len(self._history)

    def count_since_id(self, last_id: int) -> int:
        """Cuenta bloqueos con id mayor al especificado."""

        if last_id <= 0:
            return self.count_all()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM blocks WHERE id > ?;",
                (last_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def count_since(self, since: datetime) -> int:
        """Cuenta bloqueos creados a partir de un instante dado."""

        since_normalized = _normalize_datetime(since)
        return len([
            entry for entry in self._history
            if _normalize_datetime(entry.created_at) >= since_normalized
        ])

    def recent_activity(self, limit: int = 20) -> List[Dict[str, object]]:
        """Historial combinado de altas y bajas de bloqueos."""

        events: List[Dict[str, object]] = []
        for entry in self._history:
            events.append(
                {
                    "ip": entry.ip,
                    "reason": entry.reason,
                    "source": entry.source,
                    "action": "añadido",
                    "at": entry.created_at,
                }
            )
            if entry.removed_at:
                events.append(
                    {
                        "ip": entry.ip,
                        "reason": entry.reason,
                        "source": entry.source,
                        "action": "eliminado",
                        "at": entry.removed_at,
                    }
                )

        events.sort(key=lambda item: item["at"], reverse=True)
        sliced = events[:limit]
        for item in sliced:
            item["at"] = item["at"].isoformat()
        return sliced

    def timeline(self, window: timedelta, *, bucket: str = "hour") -> List[Dict[str, str | int]]:
        """Devuelve recuentos de bloqueos agrupados por intervalo temporal."""

        cutoff = datetime.now(timezone.utc) - window
        format_map = {
            "day": "%Y-%m-%d",
            "hour": "%Y-%m-%d %H:00",
            "minute": "%Y-%m-%d %H:%M",
        }
        if bucket not in format_map:
            raise ValueError(f"Bucket desconocido: {bucket}")

        pattern = format_map[bucket]
        grouped: Dict[str, int] = {}
        for entry in self._history:
            created_at_normalized = _normalize_datetime(entry.created_at)
            if created_at_normalized < cutoff:
                continue
            grouped[created_at_normalized.strftime(pattern)] = grouped.get(created_at_normalized.strftime(pattern), 0) + 1

        return [
            {"bucket": bucket_label, "count": count}
            for bucket_label, count in sorted(grouped.items())
        ]

    def reset(self) -> None:
        """Elimina todos los bloqueos persistidos y reinicia la caché."""

        try:
            with self._connection() as conn:
                conn.execute("DELETE FROM blocks;")
        except sqlite3.DatabaseError:
            Path(self.db_path).unlink(missing_ok=True)
            ensure_database(self.db_path)
        self._last_sync = None
        self._load_state()

    # Sincronización con firewall --------------------------------------------------
    def sync_with_firewall(self, gateway: "FirewallGateway", *, force: bool = False) -> Dict[str, List[str]]:
        """Sincroniza la base de datos con las entradas reales del firewall."""

        now = datetime.now(timezone.utc)
        if not force and self._last_sync and (now - self._last_sync).total_seconds() < self.sync_interval_seconds:
            return {"added": [], "removed": []}

        expired = self.purge_expired()
        desired_ips = {
            ip for ip in self._blocks.keys() if self.should_sync(ip)
        }
        firewall_entries = set(gateway.list_blocks())

        added: List[str] = []
        removed: List[str] = []

        # Añadir los que faltan
        for ip in sorted(desired_ips - firewall_entries):
            entry = self._blocks.get(ip)
            remaining_minutes: Optional[int] = None
            if entry and entry.expires_at:
                delta = entry.expires_at - now
                remaining_minutes = max(int(delta.total_seconds() // 60), 1)
            gateway.block_ip(ip, entry.reason if entry else "", duration_minutes=remaining_minutes)
            added.append(ip)
            if entry:
                entry.synced_at = now

        # Eliminar caducados o huérfanos
        for ip in sorted(firewall_entries - desired_ips):
            gateway.unblock_ip(ip)
            removed.append(ip)

        # Eliminar del firewall los expirados que seguimos teniendo en caché
        for entry in expired:
            if entry.ip in firewall_entries and entry.ip not in removed:
                gateway.unblock_ip(entry.ip)
                removed.append(entry.ip)

        self._last_sync = now
        self._persist_settings()
        return {"added": added, "removed": removed}

    def settings(self) -> Dict[str, int]:
        return {
            "default_duration_minutes": self.default_duration_minutes,
            "sync_interval_seconds": self.sync_interval_seconds,
        }

    def set_whitelist_checker(self, checker: Callable[[str], bool]) -> None:
        self._should_sync = lambda ip: not checker(ip)

    def should_sync(self, ip: str) -> bool:
        with self._lock:
            entry = self._blocks.get(ip)
            if entry and not entry.sync_with_firewall:
                return False

        try:
            return bool(self._should_sync(ip))
        except Exception as exc:
            # Fail-safe: si la whitelist falla, NO sincronizar por seguridad
            logger.error(f"Error verificando whitelist para {ip}: {exc}")
            return False

    def update_settings(self, *, default_duration_minutes: Optional[int] = None, sync_interval_seconds: Optional[int] = None) -> None:
        if default_duration_minutes is not None:
            self.default_duration_minutes = default_duration_minutes
        if sync_interval_seconds is not None:
            self.sync_interval_seconds = sync_interval_seconds
        self._persist_settings()


__all__ = ["BlockManager", "BlockEntry"]

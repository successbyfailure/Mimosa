"""Gestión de bloqueos de IPs sospechosas con persistencia en SQLite."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional
import sqlite3
from pathlib import Path

from mimosa.core.storage import DEFAULT_DB_PATH, ensure_database


@dataclass
class BlockEntry:
    """Entrada de bloqueo registrada localmente."""

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

    def to_dict(self) -> Dict[str, object]:
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
        return payload


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
        if whitelist_checker:
            self.set_whitelist_checker(whitelist_checker)
        self._load_state()
        self._load_settings()

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

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
            entry = BlockEntry(
                id=row[0],
                ip=row[1],
                reason=row[2],
                source=row[3],
                created_at=datetime.fromisoformat(row[4]),
                expires_at=datetime.fromisoformat(row[5]) if row[5] else None,
                active=bool(row[6]),
                synced_at=datetime.fromisoformat(row[7]) if row[7] else None,
                removed_at=datetime.fromisoformat(row[8]) if row[8] else None,
                sync_with_firewall=bool(row[9]) if len(row) > 9 else True,
            )
            self._history.append(entry)
            if entry.active and (not entry.expires_at or entry.expires_at > datetime.utcnow()):
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

        now = datetime.utcnow()
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
        self._blocks[ip] = entry
        self._history.append(entry)
        return entry

    def remove(self, ip: str) -> None:
        """Marca un bloqueo como inactivo y lo elimina de la caché."""

        now = datetime.utcnow()
        with self._connection() as conn:
            conn.execute(
                "UPDATE blocks SET active = 0, removed_at = ? WHERE ip = ?;",
                (now.isoformat(), ip),
            )
        self._blocks.pop(ip, None)
        for entry in self._history:
            if entry.ip == ip and entry.removed_at is None:
                entry.removed_at = now
                break

    def purge_expired(self, *, firewall_gateway: "FirewallGateway" | None = None) -> List[BlockEntry]:
        """Elimina de la lista activa cualquier bloqueo caducado."""

        now = datetime.utcnow()
        expired: List[BlockEntry] = []
        for ip, entry in list(self._blocks.items()):
            if entry.expires_at and entry.expires_at <= now:
                expired.append(entry)
                self.remove(ip)
                if firewall_gateway:
                    firewall_gateway.unblock_ip(ip)
        return expired

    def list(self, *, include_expired: bool = False) -> List[BlockEntry]:
        """Devuelve la lista de IPs bloqueadas ordenada por fecha."""

        self.purge_expired()
        entries = list(self._blocks.values()) if not include_expired else list(self._history)
        return sorted(entries, key=lambda entry: entry.created_at, reverse=True)

    def history(self) -> List[BlockEntry]:
        """Devuelve el historial completo de bloqueos (incluidos expirados)."""

        return sorted(self._history, key=lambda entry: entry.created_at, reverse=True)

    def history_for_ip(self, ip: str) -> List[BlockEntry]:
        return [entry for entry in self._history if entry.ip == ip]

    def count_for_ip(self, ip: str) -> int:
        """Número total de bloqueos registrados para una IP."""

        return len(self.history_for_ip(ip))

    def count_all(self) -> int:
        """Número total de bloqueos registrados."""

        return len(self._history)

    def count_since(self, since: datetime) -> int:
        """Cuenta bloqueos creados a partir de un instante dado."""

        return len([entry for entry in self._history if entry.created_at >= since])

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

        cutoff = datetime.utcnow() - window
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
            if entry.created_at < cutoff:
                continue
            grouped[entry.created_at.strftime(pattern)] = grouped.get(entry.created_at.strftime(pattern), 0) + 1

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

        now = datetime.utcnow()
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
        entry = self._blocks.get(ip)
        if entry and not entry.sync_with_firewall:
            return False
        try:
            return bool(self._should_sync(ip))
        except Exception:
            return True

    def update_settings(self, *, default_duration_minutes: Optional[int] = None, sync_interval_seconds: Optional[int] = None) -> None:
        if default_duration_minutes is not None:
            self.default_duration_minutes = default_duration_minutes
        if sync_interval_seconds is not None:
            self.sync_interval_seconds = sync_interval_seconds
        self._persist_settings()


__all__ = ["BlockManager", "BlockEntry"]

"""Persistencia local de ofensas y metadatos de IPs en SQLite.

Este módulo proporciona una capa sencilla para almacenar ofensas
generadas por los distintos módulos de Mimosa en una base de datos
SQLite local. Amplía la funcionalidad previa incorporando un catálogo de
IPs enriquecidas, listas blancas y utilidades para correlacionar
bloqueos.

ARQUITECTURA: Este módulo está en migración a Clean Architecture.
- Modelos de dominio → mimosa.core.domain.offense
- Repository (en desarrollo) → mimosa.core.repositories.offense_repository
- Service (futuro) → mimosa.core.services.offense_service

Ver MIGRATION_PLAN.md para detalles completos.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import httpx
from urllib.parse import urlparse, urlunparse
from mimosa.core.database import (
    DEFAULT_DB_PATH,
    DatabaseError,
    get_database,
    insert_returning_id,
)
from mimosa.core.storage import ensure_database

# Importar modelos de dominio desde nueva ubicación
from mimosa.core.domain.offense import (  # noqa: F401
    OffenseRecord,
    IpProfile,
    WhitelistEntry,
)

# Importar clasificador de IPs
from mimosa.core.ip_classification import IpClassifier

# Re-export para backward compatibility (TODO: Remover en 2.0.0)
__all__ = ["OffenseRecord", "IpProfile", "WhitelistEntry", "OffenseStore"]


class OffenseStore:
    """Almacena y recupera ofensas desde SQLite."""

    _OFFENSE_FIELDS = (
        "id, source_ip, description, severity, host, path, user_agent, context, "
        "plugin, event_id, event_type, method, status_code, protocol, src_port, "
        "dst_ip, dst_port, firewall_id, rule_id, tags, ingested_at, created_at, "
        "created_at_epoch"
    )
    _IP_PROFILE_FIELDS = (
        "ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at, "
        "offenses_count, blocks_count, ip_type, ip_type_confidence, ip_type_source, "
        "ip_type_provider, isp, org, asn, is_proxy, is_mobile, is_hosting, "
        "last_offense_at, last_block_at, country_code, risk_score, labels, "
        "enriched_source"
    )

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)
        self._db = get_database(db_path=self.db_path)
        self._ip_classifier = IpClassifier()

    def _connection(self):
        return self._db.connect()

    def _parse_iso_datetime(self, value: object | None) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None

    def _serialize_tags(self, value: object | None) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value)
        except (TypeError, ValueError):
            return None

    def _normalize_offense_fields(
        self,
        *,
        context: Optional[Dict[str, object]],
        plugin: Optional[str],
        event_id: Optional[str],
        event_type: Optional[str],
        method: Optional[str],
        status_code: Optional[str | int],
        protocol: Optional[str],
        src_port: Optional[int],
        dst_ip: Optional[str],
        dst_port: Optional[int],
        firewall_id: Optional[str],
        rule_id: Optional[str],
        tags: Optional[object],
    ) -> Dict[str, object]:
        context = context or {}
        plugin = plugin or context.get("plugin")
        event_id = event_id or context.get("event_id") or context.get("eventId")
        event_type = event_type or context.get("event_type") or context.get("alert_type")
        method = method or context.get("method")
        status_value = status_code if status_code is not None else context.get("status_code")
        if status_value is not None:
            status_value = str(status_value)
        protocol = protocol or context.get("protocol")
        src_port = src_port if src_port is not None else context.get("src_port")
        dst_ip = dst_ip or context.get("dst_ip")
        dst_port = dst_port if dst_port is not None else context.get("dst_port")
        if dst_port is None:
            dst_port = context.get("port")
        firewall_id = firewall_id or context.get("firewall_id")
        rule_id = rule_id or context.get("rule_id")
        tags = tags if tags is not None else context.get("tags") or context.get("alert_tags")

        return {
            "plugin": plugin,
            "event_id": event_id,
            "event_type": event_type,
            "method": method,
            "status_code": status_value,
            "protocol": protocol,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "firewall_id": firewall_id,
            "rule_id": rule_id,
            "tags": self._serialize_tags(tags),
        }

    def _touch_ip_profile(
        self,
        conn,
        ip: str,
        *,
        seen_at: datetime,
        increment_offenses: int = 0,
    ) -> None:
        row = conn.execute(
            "SELECT last_offense_at FROM ip_profiles WHERE ip = ? LIMIT 1;",
            (ip,),
        ).fetchone()
        if row:
            if increment_offenses > 0:
                conn.execute(
                    """
                    UPDATE ip_profiles
                    SET last_seen = ?,
                        last_offense_at = CASE
                            WHEN last_offense_at IS NULL OR last_offense_at < ? THEN ?
                            ELSE last_offense_at
                        END,
                        offenses_count = COALESCE(offenses_count, 0) + ?
                    WHERE ip = ?;
                    """,
                    (
                        seen_at.isoformat(),
                        seen_at.isoformat(),
                        seen_at.isoformat(),
                        increment_offenses,
                        ip,
                    ),
                )
            else:
                conn.execute(
                    "UPDATE ip_profiles SET last_seen = ? WHERE ip = ?;",
                    (seen_at.isoformat(), ip),
                )
            return

        metadata = self._enrich_ip(ip)
        conn.execute(
            """
            INSERT INTO ip_profiles (
                ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at,
                ip_type, ip_type_confidence, ip_type_source, ip_type_provider,
                isp, org, asn, is_proxy, is_mobile, is_hosting, offenses_count,
                blocks_count, last_offense_at, last_block_at, country_code,
                risk_score, labels, enriched_source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                ip,
                metadata.get("geo"),
                metadata.get("whois"),
                metadata.get("reverse_dns"),
                seen_at.isoformat(),
                seen_at.isoformat(),
                seen_at.isoformat(),
                metadata.get("ip_type"),
                metadata.get("ip_type_confidence"),
                metadata.get("ip_type_source"),
                metadata.get("ip_type_provider"),
                metadata.get("isp"),
                metadata.get("org"),
                metadata.get("asn"),
                1 if metadata.get("is_proxy") else 0,
                1 if metadata.get("is_mobile") else 0,
                1 if metadata.get("is_hosting") else 0,
                increment_offenses,
                0,
                seen_at.isoformat() if increment_offenses > 0 else None,
                None,
                metadata.get("country_code"),
                metadata.get("risk_score"),
                metadata.get("labels"),
                metadata.get("enriched_source"),
            ),
        )

    def _row_to_offense(self, row: tuple) -> OffenseRecord:
        context = json.loads(row[7]) if row[7] else None
        ingested_at = self._parse_iso_datetime(row[20])
        created_at = self._parse_iso_datetime(row[21]) or datetime.now(timezone.utc)
        return OffenseRecord(
            id=row[0],
            source_ip=row[1],
            description=row[2],
            severity=row[3],
            host=row[4],
            path=row[5],
            user_agent=row[6],
            context=context,
            plugin=row[8],
            event_id=row[9],
            event_type=row[10],
            method=row[11],
            status_code=row[12],
            protocol=row[13],
            src_port=row[14] if row[14] is not None else None,
            dst_ip=row[15],
            dst_port=row[16] if row[16] is not None else None,
            firewall_id=row[17],
            rule_id=row[18],
            tags=row[19],
            ingested_at=ingested_at,
            created_at=created_at,
            created_at_epoch=row[22] if row[22] is not None else None,
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
        context: Optional[Dict[str, object]] = None,
        plugin: Optional[str] = None,
        event_id: Optional[str] = None,
        event_type: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[str | int] = None,
        protocol: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        firewall_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        tags: Optional[object] = None,
        ingested_at: Optional[datetime] = None,
    ) -> OffenseRecord:
        """Inserta una ofensa y devuelve la fila creada."""

        created_at = datetime.now(timezone.utc)
        ingested_at = ingested_at or created_at
        if ingested_at.tzinfo is None:
            ingested_at = ingested_at.replace(tzinfo=timezone.utc)
        fields = self._normalize_offense_fields(
            context=context,
            plugin=plugin,
            event_id=event_id,
            event_type=event_type,
            method=method,
            status_code=status_code,
            protocol=protocol,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            firewall_id=firewall_id,
            rule_id=rule_id,
            tags=tags,
        )
        context_json = json.dumps(context) if context else None
        with self._connection() as conn:
            self._touch_ip_profile(
                conn,
                source_ip,
                seen_at=created_at,
                increment_offenses=1,
            )
            offense_id = insert_returning_id(
                conn,
                """
                INSERT INTO offenses
                    (
                        source_ip, description, severity, host, path, user_agent, context,
                        plugin, event_id, event_type, method, status_code, protocol,
                        src_port, dst_ip, dst_port, firewall_id, rule_id, tags,
                        ingested_at, created_at, created_at_epoch
                    )
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    source_ip,
                    description,
                    severity,
                    host,
                    path,
                    user_agent,
                    context_json,
                    fields.get("plugin"),
                    fields.get("event_id"),
                    fields.get("event_type"),
                    fields.get("method"),
                    fields.get("status_code"),
                    fields.get("protocol"),
                    fields.get("src_port"),
                    fields.get("dst_ip"),
                    fields.get("dst_port"),
                    fields.get("firewall_id"),
                    fields.get("rule_id"),
                    fields.get("tags"),
                    ingested_at.isoformat(),
                    created_at.isoformat(),
                    int(created_at.timestamp()),
                ),
                self._db.backend,
            )

        return OffenseRecord(
            id=offense_id,
            source_ip=source_ip,
            description=description,
            severity=severity,
            host=host,
            path=path,
            user_agent=user_agent,
            context=context,
            plugin=fields.get("plugin"),
            event_id=fields.get("event_id"),
            event_type=fields.get("event_type"),
            method=fields.get("method"),
            status_code=fields.get("status_code"),
            protocol=fields.get("protocol"),
            src_port=fields.get("src_port"),
            dst_ip=fields.get("dst_ip"),
            dst_port=fields.get("dst_port"),
            firewall_id=fields.get("firewall_id"),
            rule_id=fields.get("rule_id"),
            tags=fields.get("tags"),
            ingested_at=ingested_at,
            created_at=created_at,
            created_at_epoch=int(created_at.timestamp()),
        )

    def record_many(self, offenses: Iterable[Dict[str, object]]) -> None:
        """Inserta en bloque varias ofensas en una sola transacción."""

        with self._connection() as conn:
            rows = []
            for offense in offenses:
                created_at_raw = offense.get("created_at")
                parsed_created = self._parse_iso_datetime(created_at_raw)
                created_at = parsed_created or datetime.now(timezone.utc)
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                ingested_at_raw = offense.get("ingested_at")
                ingested_at = (
                    self._parse_iso_datetime(ingested_at_raw) or datetime.now(timezone.utc)
                )
                if ingested_at.tzinfo is None:
                    ingested_at = ingested_at.replace(tzinfo=timezone.utc)
                context = offense.get("context") or {}
                fields = self._normalize_offense_fields(
                    context=context if isinstance(context, dict) else {},
                    plugin=offense.get("plugin"),
                    event_id=offense.get("event_id"),
                    event_type=offense.get("event_type"),
                    method=offense.get("method"),
                    status_code=offense.get("status_code"),
                    protocol=offense.get("protocol"),
                    src_port=offense.get("src_port"),
                    dst_ip=offense.get("dst_ip"),
                    dst_port=offense.get("dst_port"),
                    firewall_id=offense.get("firewall_id"),
                    rule_id=offense.get("rule_id"),
                    tags=offense.get("tags"),
                )
                source_ip = offense.get("source_ip", "desconocido")
                self._touch_ip_profile(
                    conn,
                    source_ip,
                    seen_at=created_at,
                    increment_offenses=1,
                )
                rows.append(
                    (
                        source_ip,
                        offense.get("description", "Actividad sospechosa"),
                        offense.get("severity", "medio"),
                        offense.get("host"),
                        offense.get("path"),
                        offense.get("user_agent"),
                        json.dumps(context) if context else None,
                        fields.get("plugin"),
                        fields.get("event_id"),
                        fields.get("event_type"),
                        fields.get("method"),
                        fields.get("status_code"),
                        fields.get("protocol"),
                        fields.get("src_port"),
                        fields.get("dst_ip"),
                        fields.get("dst_port"),
                        fields.get("firewall_id"),
                        fields.get("rule_id"),
                        fields.get("tags"),
                        ingested_at.isoformat(),
                        created_at.isoformat(),
                        int(created_at.timestamp()),
                    )
                )

            conn.executemany(
                """
                INSERT INTO offenses
                    (
                        source_ip, description, severity, host, path, user_agent, context,
                        plugin, event_id, event_type, method, status_code, protocol,
                        src_port, dst_ip, dst_port, firewall_id, rule_id, tags,
                        ingested_at, created_at, created_at_epoch
                    )
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )

    def list_recent(self, limit: int = 50) -> List[OffenseRecord]:
        """Recupera las últimas ofensas registradas."""

        with self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT {self._OFFENSE_FIELDS}
                FROM offenses
                ORDER BY created_at DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_offense(row) for row in rows]

    def latest(self) -> Optional[OffenseRecord]:
        """Devuelve la última ofensa registrada."""

        with self._connection() as conn:
            row = conn.execute(
                f"""
                SELECT {self._OFFENSE_FIELDS}
                FROM offenses
                ORDER BY id DESC
                LIMIT 1;
                """
            ).fetchone()
        if not row:
            return None
        return self._row_to_offense(row)

    def list_recent_by_description_prefix(
        self, prefix: str, limit: int = 50
    ) -> List[OffenseRecord]:
        """Recupera ofensas recientes filtradas por prefijo de descripción."""

        pattern = f"{prefix}%"
        with self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT {self._OFFENSE_FIELDS}
                FROM offenses
                WHERE description LIKE ?
                ORDER BY created_at DESC
                LIMIT ?;
                """,
                (pattern, limit),
            ).fetchall()

        return [self._row_to_offense(row) for row in rows]

    def count_by_description_prefix_since(self, prefix: str, since: datetime) -> int:
        """Cuenta ofensas con prefijo en la descripción desde una fecha."""

        pattern = f"{prefix}%"
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*)
                FROM offenses
                WHERE description LIKE ? AND created_at >= ?;
                """,
                (pattern, since.isoformat()),
            ).fetchone()
        return int(row[0]) if row else 0

    def last_seen_by_description_prefix(self, prefix: str) -> Optional[datetime]:
        """Devuelve la fecha más reciente para un prefijo de descripción."""

        pattern = f"{prefix}%"
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT MAX(created_at)
                FROM offenses
                WHERE description LIKE ?;
                """,
                (pattern,),
            ).fetchone()
        if not row or not row[0]:
            return None
        return self._parse_iso_datetime(row[0])

    def list_by_ip(self, ip: str, limit: int = 50) -> List[OffenseRecord]:
        """Devuelve ofensas asociadas a una IP concreta."""

        with self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT {self._OFFENSE_FIELDS}
                FROM offenses
                WHERE source_ip = ?
                ORDER BY created_at DESC
                LIMIT ?;
                """,
                (ip, limit),
            ).fetchall()

        return [self._row_to_offense(row) for row in rows]

    def count_all(self) -> int:
        """Devuelve el número total de ofensas almacenadas."""

        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM offenses;").fetchone()
        return int(row[0]) if row else 0

    def count_since_id(self, last_id: int) -> int:
        """Cuenta ofensas con id mayor al especificado."""

        if last_id <= 0:
            return self.count_all()
        with self._connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM offenses WHERE id > ?;",
                (last_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def count_by_ip(self, ip: str) -> int:
        """Cuenta ofensas totales asociadas a una IP."""

        with self._connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM offenses WHERE source_ip = ?;", (ip,)
            ).fetchone()
        return int(row[0]) if row else 0

    def count_since(self, since: datetime) -> int:
        """Cuenta ofensas registradas desde un momento concreto."""

        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*)
                FROM offenses
                WHERE created_at >= ?;
                """,
                (since.isoformat(),),
            ).fetchone()

        return int(row[0]) if row else 0

    def count_by_ip_since(self, ip: str, since: datetime) -> int:
        """Cuenta ofensas de una IP desde un momento concreto."""

        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*)
                FROM offenses
                WHERE source_ip = ? AND created_at >= ?;
                """,
                (ip, since.isoformat()),
            ).fetchone()

        return int(row[0]) if row else 0

    def offense_counts_by_ip(self, since: Optional[datetime] = None) -> Dict[str, int]:
        """Devuelve recuentos de ofensas agregados por IP."""

        query = "SELECT source_ip, COUNT(*) FROM offenses"
        params: tuple = ()
        if since is not None:
            query += " WHERE created_at >= ?"
            params = (since.isoformat(),)
        query += " GROUP BY source_ip;"
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return {row[0]: int(row[1]) for row in rows if row and row[0]}

    def offense_counts_by_ip_freshness(self, since: datetime) -> Dict[str, int]:
        """Devuelve recuentos de ofensas por IPs nuevas vs conocidas."""

        since_value = since.isoformat()
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN p.first_seen IS NULL OR p.first_seen >= ? THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN p.first_seen IS NOT NULL AND p.first_seen < ? THEN 1 ELSE 0 END), 0)
                FROM offenses o
                LEFT JOIN ip_profiles p ON p.ip = o.source_ip
                WHERE o.created_at >= ?;
                """,
                (since_value, since_value, since_value),
            ).fetchone()
        if not row:
            return {"new": 0, "known": 0}
        return {"new": int(row[0] or 0), "known": int(row[1] or 0)}

    def timeline(self, window: timedelta, *, bucket: str = "hour") -> List[Dict[str, str | int]]:
        """Devuelve recuentos agregados por intervalo para un periodo."""

        cutoff = datetime.now(timezone.utc) - window
        with self._connection() as conn:
            if self._db.backend == "postgres":
                format_map = {
                    "day": "YYYY-MM-DD",
                    "hour": "YYYY-MM-DD HH24:00",
                    "minute": "YYYY-MM-DD HH24:MI",
                }
                if bucket not in format_map:
                    raise ValueError(f"Bucket desconocido: {bucket}")
                bucket_sql = {
                    "day": "to_char(date_trunc('day', created_at::timestamptz), 'YYYY-MM-DD')",
                    "hour": "to_char(date_trunc('hour', created_at::timestamptz), 'YYYY-MM-DD HH24:00')",
                    "minute": "to_char(date_trunc('minute', created_at::timestamptz), 'YYYY-MM-DD HH24:MI')",
                }[bucket]
                rows = conn.execute(
                    f"""
                    SELECT {bucket_sql} AS bucket, COUNT(*)
                    FROM offenses
                    WHERE created_at >= ?
                    GROUP BY 1
                    ORDER BY 1 ASC;
                    """,
                    (cutoff.isoformat(),),
                ).fetchall()
            else:
                format_map = {
                    "day": "%Y-%m-%d",
                    "hour": "%Y-%m-%d %H:00",
                    "minute": "%Y-%m-%d %H:%M",
                }
                if bucket not in format_map:
                    raise ValueError(f"Bucket desconocido: {bucket}")
                strftime_pattern = format_map[bucket]
                rows = conn.execute(
                    """
                    SELECT strftime(?, created_at) AS bucket, COUNT(*)
                    FROM offenses
                    WHERE created_at >= ?
                    GROUP BY bucket
                    ORDER BY bucket ASC;
                    """,
                    (strftime_pattern, cutoff.isoformat()),
                ).fetchall()

        return [{"bucket": row[0], "count": int(row[1])} for row in rows]

    def count_by_ip_type(self) -> Dict[str, int]:
        """Devuelve recuentos de IPs agregados por tipo."""

        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT COALESCE(ip_type, 'unknown') as ip_type, COUNT(*) as count
                FROM ip_profiles
                GROUP BY ip_type
                ORDER BY count DESC;
                """
            ).fetchall()
        return {row[0]: int(row[1]) for row in rows if row}

    def refresh_cloud_ranges(self) -> Dict[str, int]:
        """Actualiza los rangos de cloud providers."""
        return self._ip_classifier.refresh_cloud_ranges()

    def get_cloud_stats(self) -> Dict[str, int]:
        """Devuelve estadísticas de los rangos de cloud cargados."""
        return self._ip_classifier.get_cloud_stats()

    def get_reaction_time_stats(
        self, window: Optional[str] = None
    ) -> Dict[str, object]:
        """Calcula estadísticas de tiempo de reacción entre ofensa y bloqueo.

        Args:
            window: Ventana temporal: '24h', '7d' o None para todo el historial.

        Returns:
            Diccionario con estadísticas: min, max, avg, median, p90, p99,
            total de bloqueos analizados, y distribución por rangos.
        """
        # Calcular cutoff según ventana
        cutoff = None
        if window == "24h":
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        elif window == "7d":
            cutoff = datetime.now(timezone.utc) - timedelta(days=7)

        with self._connection() as conn:
            # Obtener bloqueos automáticos con su ofensa más reciente
            if cutoff:
                rows = conn.execute(
                    """
                    SELECT
                        b.id as block_id,
                        b.ip,
                        b.created_at as block_created,
                        (
                            SELECT o.created_at
                            FROM offenses o
                            WHERE o.source_ip = b.ip
                              AND o.created_at <= b.created_at
                            ORDER BY o.created_at DESC
                            LIMIT 1
                        ) as offense_created
                    FROM blocks b
                    WHERE b.source != 'manual'
                      AND b.created_at >= ?
                    ORDER BY b.created_at DESC
                    """,
                    (cutoff.isoformat(),),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT
                        b.id as block_id,
                        b.ip,
                        b.created_at as block_created,
                        (
                            SELECT o.created_at
                            FROM offenses o
                            WHERE o.source_ip = b.ip
                              AND o.created_at <= b.created_at
                            ORDER BY o.created_at DESC
                            LIMIT 1
                        ) as offense_created
                    FROM blocks b
                    WHERE b.source != 'manual'
                    ORDER BY b.created_at DESC
                    """
                ).fetchall()

        reaction_times: List[float] = []
        for row in rows:
            block_created = row[2]
            offense_created = row[3]
            if not offense_created or not block_created:
                continue
            try:
                offense_dt = datetime.fromisoformat(
                    offense_created.replace("Z", "+00:00")
                )
                block_dt = datetime.fromisoformat(
                    block_created.replace("Z", "+00:00")
                )
                # Normalizar ambos a UTC naive para comparación
                if offense_dt.tzinfo is not None:
                    offense_dt = offense_dt.replace(tzinfo=None)
                if block_dt.tzinfo is not None:
                    block_dt = block_dt.replace(tzinfo=None)
                diff_seconds = (block_dt - offense_dt).total_seconds()
                if diff_seconds >= 0:
                    reaction_times.append(diff_seconds)
            except (ValueError, AttributeError, TypeError):
                continue

        if not reaction_times:
            return {
                "total_blocks": 0,
                "blocks_with_offense": 0,
                "min_seconds": None,
                "max_seconds": None,
                "avg_seconds": None,
                "median_seconds": None,
                "p90_seconds": None,
                "p99_seconds": None,
                "distribution": {},
            }

        reaction_times.sort()
        total = len(reaction_times)

        # Distribución por rangos
        distribution = {
            "sub_1s": len([t for t in reaction_times if t < 1]),
            "1s_to_5s": len([t for t in reaction_times if 1 <= t < 5]),
            "5s_to_10s": len([t for t in reaction_times if 5 <= t < 10]),
            "over_10s": len([t for t in reaction_times if t >= 10]),
        }

        return {
            "total_blocks": len(rows),
            "blocks_with_offense": total,
            "min_seconds": round(min(reaction_times), 3),
            "max_seconds": round(max(reaction_times), 3),
            "avg_seconds": round(sum(reaction_times) / total, 3),
            "median_seconds": round(reaction_times[total // 2], 3),
            "p90_seconds": round(reaction_times[int(total * 0.9)], 3),
            "p99_seconds": round(reaction_times[int(total * 0.99)], 3),
            "distribution": distribution,
        }

    def list_ip_profiles(self, limit: int = 100) -> List[IpProfile]:
        """Devuelve la lista de IPs conocidas con contadores básicos."""

        with self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT {self._IP_PROFILE_FIELDS}
                FROM ip_profiles
                ORDER BY last_seen DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_profile(row) for row in rows]

    def count_ip_profiles(self) -> int:
        """Devuelve el total de IPs registradas en el perfil."""

        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM ip_profiles;").fetchone()
        return int(row[0]) if row else 0

    def offense_window_by_ip(self, ip: str) -> tuple[Optional[datetime], Optional[datetime]]:
        """Devuelve la primera y última ofensa registradas para una IP."""

        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT MIN(created_at), MAX(created_at)
                FROM offenses
                WHERE source_ip = ?;
                """,
                (ip,),
            ).fetchone()
        if not row:
            return None, None
        return self._parse_iso_datetime(row[0]), self._parse_iso_datetime(row[1])

    def get_ip_profile(self, ip: str) -> Optional[IpProfile]:
        """Recupera los metadatos de una IP concreta."""

        with self._connection() as conn:
            row = conn.execute(
                f"""
                SELECT {self._IP_PROFILE_FIELDS}
                FROM ip_profiles
                WHERE ip = ?
                LIMIT 1;
                """,
                (ip,),
            ).fetchone()

        if not row:
            return None
        return self._row_to_profile(row)

    def get_ip_profiles_by_ips(self, ips: Iterable[str]) -> Dict[str, IpProfile]:
        items = [ip for ip in ips if ip]
        if not items:
            return {}
        profiles: Dict[str, IpProfile] = {}
        chunk_size = 200
        with self._connection() as conn:
            for start in range(0, len(items), chunk_size):
                chunk = items[start : start + chunk_size]
                placeholders = ", ".join(["?"] * len(chunk))
                rows = conn.execute(
                    f"""
                    SELECT {self._IP_PROFILE_FIELDS}
                    FROM ip_profiles
                    WHERE ip IN ({placeholders});
                    """,
                    chunk,
                ).fetchall()
                for row in rows:
                    profile = self._row_to_profile(row)
                    profiles[profile.ip] = profile
        return profiles

    def offense_counts_total_by_ip(self) -> Dict[str, int]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT ip, offenses_count
                FROM ip_profiles
                WHERE COALESCE(offenses_count, 0) > 0;
                """
            ).fetchall()
        return {row[0]: int(row[1]) for row in rows if row and row[0]}

    def block_counts_total_by_ip(self) -> Dict[str, int]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT ip, blocks_count
                FROM ip_profiles
                WHERE COALESCE(blocks_count, 0) > 0;
                """
            ).fetchall()
        return {row[0]: int(row[1]) for row in rows if row and row[0]}

    def refresh_ip_profile(self, ip: str) -> Optional[IpProfile]:
        """Recalcula los datos enriquecidos de una IP."""

        metadata = self._enrich_ip(ip)
        now = datetime.now(timezone.utc)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO ip_profiles (
                    ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at,
                    ip_type, ip_type_confidence, ip_type_source, ip_type_provider,
                    isp, org, asn, is_proxy, is_mobile, is_hosting,
                    country_code, risk_score, labels, enriched_source
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    geo=excluded.geo,
                    whois=excluded.whois,
                    reverse_dns=excluded.reverse_dns,
                    last_seen=excluded.last_seen,
                    enriched_at=excluded.enriched_at,
                    ip_type=excluded.ip_type,
                    ip_type_confidence=excluded.ip_type_confidence,
                    ip_type_source=excluded.ip_type_source,
                    ip_type_provider=excluded.ip_type_provider,
                    isp=excluded.isp,
                    org=excluded.org,
                    asn=excluded.asn,
                    is_proxy=excluded.is_proxy,
                    is_mobile=excluded.is_mobile,
                    is_hosting=excluded.is_hosting,
                    country_code=excluded.country_code,
                    risk_score=excluded.risk_score,
                    labels=excluded.labels,
                    enriched_source=excluded.enriched_source
                ;
                """,
                (
                    ip,
                    metadata.get("geo"),
                    metadata.get("whois"),
                    metadata.get("reverse_dns"),
                    now.isoformat(),
                    now.isoformat(),
                    now.isoformat(),
                    metadata.get("ip_type"),
                    metadata.get("ip_type_confidence"),
                    metadata.get("ip_type_source"),
                    metadata.get("ip_type_provider"),
                    metadata.get("isp"),
                    metadata.get("org"),
                    metadata.get("asn"),
                    1 if metadata.get("is_proxy") else 0,
                    1 if metadata.get("is_mobile") else 0,
                    1 if metadata.get("is_hosting") else 0,
                    metadata.get("country_code"),
                    metadata.get("risk_score"),
                    metadata.get("labels"),
                    metadata.get("enriched_source"),
                ),
            )
        return self.get_ip_profile(ip)

    def add_whitelist(self, cidr: str, note: Optional[str] = None) -> WhitelistEntry:
        """Inserta una entrada en la lista blanca local."""

        created_at = datetime.now(timezone.utc)
        with self._connection() as conn:
            entry_id = insert_returning_id(
                conn,
                """
                INSERT INTO whitelist (cidr, note, created_at)
                VALUES (?, ?, ?);
                """,
                (cidr, note, created_at.isoformat()),
                self._db.backend,
            )
        return WhitelistEntry(id=entry_id, cidr=cidr, note=note, created_at=created_at)

    def list_whitelist(self) -> List[WhitelistEntry]:
        """Devuelve todas las entradas de whitelist."""

        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, cidr, note, created_at
                FROM whitelist
                ORDER BY created_at DESC;
                """
            ).fetchall()

        return [
            WhitelistEntry(
                id=row[0], cidr=row[1], note=row[2], created_at=datetime.fromisoformat(row[3])
            )
            for row in rows
        ]

    def delete_whitelist(self, entry_id: int) -> None:
        with self._connection() as conn:
            conn.execute("DELETE FROM whitelist WHERE id = ?;", (entry_id,))

    def is_whitelisted(self, ip: str) -> bool:
        """Comprueba si una IP pertenece a alguna entrada de whitelist."""

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for entry in self.list_whitelist():
            try:
                network = ipaddress.ip_network(entry.cidr, strict=False)
            except ValueError:
                continue
            if address in network:
                return True
        return False

    def _ensure_ip_profile(self, ip: str, *, seen_at: Optional[datetime] = None) -> None:
        """Garantiza que existe una entrada de IP y actualiza last_seen."""

        seen = seen_at or datetime.now(timezone.utc)
        with self._connection() as conn:
            self._touch_ip_profile(conn, ip, seen_at=seen, increment_offenses=0)

    def _row_to_profile(self, row: tuple) -> IpProfile:
        return IpProfile(
            ip=row[0],
            geo=row[1],
            whois=row[2],
            reverse_dns=row[3],
            first_seen=datetime.fromisoformat(row[4]),
            last_seen=datetime.fromisoformat(row[5]),
            enriched_at=datetime.fromisoformat(row[6]) if row[6] else None,
            offenses=int(row[7]) if row[7] is not None else 0,
            blocks=int(row[8]) if row[8] is not None else 0,
            # Campos de clasificación
            ip_type=row[9] if len(row) > 9 else None,
            ip_type_confidence=float(row[10]) if len(row) > 10 and row[10] is not None else None,
            ip_type_source=row[11] if len(row) > 11 else None,
            ip_type_provider=row[12] if len(row) > 12 else None,
            isp=row[13] if len(row) > 13 else None,
            org=row[14] if len(row) > 14 else None,
            asn=row[15] if len(row) > 15 else None,
            is_proxy=bool(row[16]) if len(row) > 16 and row[16] is not None else False,
            is_mobile=bool(row[17]) if len(row) > 17 and row[17] is not None else False,
            is_hosting=bool(row[18]) if len(row) > 18 and row[18] is not None else False,
            last_offense_at=self._parse_iso_datetime(row[19]) if len(row) > 19 else None,
            last_block_at=self._parse_iso_datetime(row[20]) if len(row) > 20 else None,
            country_code=row[21] if len(row) > 21 else None,
            risk_score=float(row[22]) if len(row) > 22 and row[22] is not None else None,
            labels=row[23] if len(row) > 23 else None,
            enriched_source=row[24] if len(row) > 24 else None,
        )

    def _enrich_ip(self, ip: str) -> Dict[str, object]:
        """Obtiene información enriquecida de la IP incluyendo clasificación.

        Reverse DNS se obtiene con la librería estándar. La geolocalización
        y datos de clasificación se consultan desde ip-api.com si se habilita
        con ``MIMOSA_GEOIP_ENABLED=true``.
        """

        reverse_dns: Optional[str] = None
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except (socket.gaierror, socket.herror, OSError):  # Errores de resolución DNS
            reverse_dns = None

        geo, api_data = self._lookup_geo(ip)
        country_code = None
        enriched_source = None
        if geo:
            try:
                payload = json.loads(geo)
                if isinstance(payload, dict):
                    country_code = payload.get("country_code") or payload.get("countryCode")
                    enriched_source = payload.get("provider")
            except json.JSONDecodeError:
                country_code = None
                enriched_source = None

        # Clasificar la IP usando el clasificador
        classification = self._ip_classifier.classify(
            ip=ip,
            rdns=reverse_dns,
            api_data=api_data,
        )

        return {
            "geo": geo,
            "whois": None,
            "reverse_dns": reverse_dns,
            "ip_type": classification.ip_type.value,
            "ip_type_confidence": classification.confidence,
            "ip_type_source": classification.source,
            "ip_type_provider": classification.provider,
            "isp": classification.isp,
            "org": classification.org,
            "asn": classification.asn,
            "is_proxy": classification.is_proxy,
            "is_mobile": classification.is_mobile,
            "is_hosting": classification.is_hosting,
            "country_code": country_code,
            "risk_score": None,
            "labels": None,
            "enriched_source": enriched_source,
        }

    def _lookup_geo(self, ip: str) -> tuple[Optional[str], Optional[Dict[str, object]]]:
        """Obtiene geolocalización y datos de clasificación de ip-api.com.

        Returns:
            Tupla (geo_json, api_data) donde:
            - geo_json: JSON string con lat, lon, country, etc.
            - api_data: Dict con hosting, proxy, mobile, isp, org, as
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None, None
        if not ip_obj.is_global:
            return None, None
        enabled = os.getenv("MIMOSA_GEOIP_ENABLED", "false").lower() == "true"
        if not enabled:
            return None, None
        provider = os.getenv("MIMOSA_GEOIP_PROVIDER", "ip-api").lower()
        if provider != "ip-api":
            return None, None
        base_url = os.getenv("MIMOSA_GEOIP_ENDPOINT", "http://ip-api.com/json")
        # Campos extendidos para clasificación de IP
        fields = "status,message,lat,lon,country,countryCode,regionName,city,timezone,isp,org,as,asname,hosting,proxy,mobile"
        url = f"{base_url.rstrip('/')}/{ip}"
        data = self._fetch_geo_payload(url, fields)
        if not data and base_url.startswith("https://ip-api.com"):
            parsed = urlparse(url)
            fallback = parsed._replace(scheme="http")
            data = self._fetch_geo_payload(urlunparse(fallback), fields)
        if not data:
            return None, None
        geo_payload = {
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "city": data.get("city"),
            "region": data.get("regionName"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "timezone": data.get("timezone"),
            "provider": "ip-api",
        }
        geo_json = None
        if geo_payload.get("lat") is not None and geo_payload.get("lon") is not None:
            geo_json = json.dumps(geo_payload)
        # Datos adicionales para clasificación
        api_data = {
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "asname": data.get("asname"),
            "hosting": data.get("hosting", False),
            "proxy": data.get("proxy", False),
            "mobile": data.get("mobile", False),
        }
        return geo_json, api_data

    def _fetch_geo_payload(self, url: str, fields: str) -> Optional[Dict[str, object]]:
        try:
            response = httpx.get(
                url,
                params={"fields": fields},
                timeout=3.0,
            )
            data = response.json()
        except httpx.HTTPError:
            return None
        except json.JSONDecodeError:
            return None
        if data.get("status") != "success":
            return None
        return data

    def reset(self) -> None:
        """Limpia ofensas y perfiles almacenados.

        Si la base de datos estuviera corrupta, se elimina el fichero y se
        vuelve a crear con el esquema esperado.
        """

        db_path = Path(self.db_path)
        try:
            with self._connection() as conn:
                conn.execute("DELETE FROM offenses;")
                conn.execute("DELETE FROM ip_profiles;")
        except DatabaseError:
            if self._db.backend == "sqlite":
                db_path.unlink(missing_ok=True)
                ensure_database(db_path)
                return
            raise
        ensure_database(db_path)

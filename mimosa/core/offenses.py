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
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import httpx
from urllib.parse import urlparse, urlunparse
from mimosa.core.storage import DEFAULT_DB_PATH, ensure_database

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

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)
        self._ip_classifier = IpClassifier()

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

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

        created_at = datetime.now(timezone.utc)
        self._ensure_ip_profile(source_ip, seen_at=created_at)
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
                created_at = offense.get("created_at") or datetime.now(timezone.utc).isoformat()
                self._ensure_ip_profile(offense.get("source_ip", "desconocido"))
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

    def latest(self) -> Optional[OffenseRecord]:
        """Devuelve la última ofensa registrada."""

        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT id, source_ip, description, severity, host, path, user_agent, context, created_at
                FROM offenses
                ORDER BY id DESC
                LIMIT 1;
                """
            ).fetchone()
        if not row:
            return None
        context = json.loads(row[7]) if row[7] else None
        return OffenseRecord(
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

    def list_recent_by_description_prefix(
        self, prefix: str, limit: int = 50
    ) -> List[OffenseRecord]:
        """Recupera ofensas recientes filtradas por prefijo de descripción."""

        pattern = f"{prefix}%"
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, source_ip, description, severity, host, path, user_agent, context, created_at
                FROM offenses
                WHERE description LIKE ?
                ORDER BY datetime(created_at) DESC
                LIMIT ?;
                """,
                (pattern, limit),
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

    def count_by_description_prefix_since(self, prefix: str, since: datetime) -> int:
        """Cuenta ofensas con prefijo en la descripción desde una fecha."""

        pattern = f"{prefix}%"
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*)
                FROM offenses
                WHERE description LIKE ? AND datetime(created_at) >= datetime(?);
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
                SELECT MAX(datetime(created_at))
                FROM offenses
                WHERE description LIKE ?;
                """,
                (pattern,),
            ).fetchone()
        if not row or not row[0]:
            return None
        return datetime.fromisoformat(row[0])

    def list_by_ip(self, ip: str, limit: int = 50) -> List[OffenseRecord]:
        """Devuelve ofensas asociadas a una IP concreta."""

        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, source_ip, description, severity, host, path, user_agent, context, created_at
                FROM offenses
                WHERE source_ip = ?
                ORDER BY datetime(created_at) DESC
                LIMIT ?;
                """,
                (ip, limit),
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
                WHERE datetime(created_at) >= datetime(?);
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
                WHERE source_ip = ? AND datetime(created_at) >= datetime(?);
                """,
                (ip, since.isoformat()),
            ).fetchone()

        return int(row[0]) if row else 0

    def offense_counts_by_ip(self, since: Optional[datetime] = None) -> Dict[str, int]:
        """Devuelve recuentos de ofensas agregados por IP."""

        query = "SELECT source_ip, COUNT(*) FROM offenses"
        params: tuple = ()
        if since is not None:
            query += " WHERE datetime(created_at) >= datetime(?)"
            params = (since.isoformat(),)
        query += " GROUP BY source_ip;"
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return {row[0]: int(row[1]) for row in rows if row and row[0]}

    def timeline(self, window: timedelta, *, bucket: str = "hour") -> List[Dict[str, str | int]]:
        """Devuelve recuentos agregados por intervalo para un periodo."""

        cutoff = datetime.now(timezone.utc) - window
        format_map = {
            "day": "%Y-%m-%d",
            "hour": "%Y-%m-%d %H:00",
            "minute": "%Y-%m-%d %H:%M",
        }
        if bucket not in format_map:
            raise ValueError(f"Bucket desconocido: {bucket}")

        strftime_pattern = format_map[bucket]
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT strftime(?, created_at) AS bucket, COUNT(*)
                FROM offenses
                WHERE datetime(created_at) >= datetime(?)
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
                """
                SELECT ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at,
                       (SELECT COUNT(*) FROM offenses o WHERE o.source_ip = ip_profiles.ip) AS offenses,
                       (SELECT COUNT(*) FROM blocks b WHERE b.ip = ip_profiles.ip) AS blocks,
                       ip_type, ip_type_confidence, ip_type_source, ip_type_provider,
                       isp, org, asn, is_proxy, is_mobile, is_hosting
                FROM ip_profiles
                ORDER BY datetime(last_seen) DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_profile(row) for row in rows]

    def get_ip_profile(self, ip: str) -> Optional[IpProfile]:
        """Recupera los metadatos de una IP concreta."""

        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at,
                       (SELECT COUNT(*) FROM offenses o WHERE o.source_ip = ip_profiles.ip) AS offenses,
                       (SELECT COUNT(*) FROM blocks b WHERE b.ip = ip_profiles.ip) AS blocks,
                       ip_type, ip_type_confidence, ip_type_source, ip_type_provider,
                       isp, org, asn, is_proxy, is_mobile, is_hosting
                FROM ip_profiles
                WHERE ip = ?
                LIMIT 1;
                """,
                (ip,),
            ).fetchone()

        if not row:
            return None
        return self._row_to_profile(row)

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
                    isp, org, asn, is_proxy, is_mobile, is_hosting
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    is_hosting=excluded.is_hosting
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
                ),
            )
        return self.get_ip_profile(ip)

    def add_whitelist(self, cidr: str, note: Optional[str] = None) -> WhitelistEntry:
        """Inserta una entrada en la lista blanca local."""

        created_at = datetime.now(timezone.utc)
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO whitelist (cidr, note, created_at)
                VALUES (?, ?, ?);
                """,
                (cidr, note, created_at.isoformat()),
            )
            entry_id = cursor.lastrowid
        return WhitelistEntry(id=entry_id, cidr=cidr, note=note, created_at=created_at)

    def list_whitelist(self) -> List[WhitelistEntry]:
        """Devuelve todas las entradas de whitelist."""

        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, cidr, note, created_at
                FROM whitelist
                ORDER BY datetime(created_at) DESC;
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
            row = conn.execute(
                "SELECT ip FROM ip_profiles WHERE ip = ? LIMIT 1;", (ip,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE ip_profiles SET last_seen = ? WHERE ip = ?;",
                    (seen.isoformat(), ip),
                )
                return

            metadata = self._enrich_ip(ip)
            conn.execute(
                """
                INSERT INTO ip_profiles (
                    ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at,
                    ip_type, ip_type_confidence, ip_type_source, ip_type_provider,
                    isp, org, asn, is_proxy, is_mobile, is_hosting
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    ip,
                    metadata.get("geo"),
                    metadata.get("whois"),
                    metadata.get("reverse_dns"),
                    seen.isoformat(),
                    seen.isoformat(),
                    seen.isoformat(),
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
                ),
            )

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
        }

    def _lookup_geo(self, ip: str) -> tuple[Optional[str], Optional[Dict[str, object]]]:
        """Obtiene geolocalización y datos de clasificación de ip-api.com.

        Returns:
            Tupla (geo_json, api_data) donde:
            - geo_json: JSON string con lat, lon, country, etc.
            - api_data: Dict con hosting, proxy, mobile, isp, org, as
        """
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
        except sqlite3.DatabaseError:
            db_path.unlink(missing_ok=True)
        ensure_database(db_path)

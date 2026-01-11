"""Persistencia local de ofensas y metadatos de IPs en SQLite.

Este módulo proporciona una capa sencilla para almacenar ofensas
generadas por los distintos módulos de Mimosa en una base de datos
SQLite local. Amplía la funcionalidad previa incorporando un catálogo de
IPs enriquecidas, listas blancas y utilidades para correlacionar
bloqueos.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import httpx
from urllib.parse import urlparse, urlunparse
from mimosa.core.storage import DEFAULT_DB_PATH, ensure_database


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


@dataclass
class IpProfile:
    """Información enriquecida de una IP conocida."""

    ip: str
    geo: Optional[str]
    whois: Optional[str]
    reverse_dns: Optional[str]
    first_seen: datetime
    last_seen: datetime
    enriched_at: Optional[datetime] = None
    offenses: int = 0
    blocks: int = 0


@dataclass
class WhitelistEntry:
    """Entrada en la lista blanca local."""

    id: int
    cidr: str
    note: Optional[str]
    created_at: datetime


class OffenseStore:
    """Almacena y recupera ofensas desde SQLite."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)

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

        created_at = datetime.utcnow()
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
                created_at = offense.get("created_at") or datetime.utcnow().isoformat()
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

    def timeline(self, window: timedelta, *, bucket: str = "hour") -> List[Dict[str, str | int]]:
        """Devuelve recuentos agregados por intervalo para un periodo."""

        cutoff = datetime.utcnow() - window
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

    def list_ip_profiles(self, limit: int = 100) -> List[IpProfile]:
        """Devuelve la lista de IPs conocidas con contadores básicos."""

        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at,
                       (SELECT COUNT(*) FROM offenses o WHERE o.source_ip = ip_profiles.ip) AS offenses,
                       (SELECT COUNT(*) FROM blocks b WHERE b.ip = ip_profiles.ip AND b.active = 1) AS blocks
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
                       (SELECT COUNT(*) FROM blocks b WHERE b.ip = ip_profiles.ip AND b.active = 1) AS blocks
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
        now = datetime.utcnow()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO ip_profiles (ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    geo=excluded.geo,
                    whois=excluded.whois,
                    reverse_dns=excluded.reverse_dns,
                    last_seen=excluded.last_seen,
                    enriched_at=excluded.enriched_at
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
                ),
            )
        return self.get_ip_profile(ip)

    def add_whitelist(self, cidr: str, note: Optional[str] = None) -> WhitelistEntry:
        """Inserta una entrada en la lista blanca local."""

        created_at = datetime.utcnow()
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

        seen = seen_at or datetime.utcnow()
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
                INSERT INTO ip_profiles (ip, geo, whois, reverse_dns, first_seen, last_seen, enriched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    ip,
                    metadata.get("geo"),
                    metadata.get("whois"),
                    metadata.get("reverse_dns"),
                    seen.isoformat(),
                    seen.isoformat(),
                    seen.isoformat(),
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
        )

    def _enrich_ip(self, ip: str) -> Dict[str, Optional[str]]:
        """Obtiene información básica de la IP.

        Reverse DNS se obtiene con la librería estándar. La geolocalización
        se consulta solo si se habilita explícitamente con
        ``MIMOSA_GEOIP_ENABLED=true``.
        """

        reverse_dns: Optional[str] = None
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except Exception:  # pragma: no cover - dependiente de red/resolución
            reverse_dns = None

        geo = self._lookup_geo(ip)
        return {"geo": geo, "whois": None, "reverse_dns": reverse_dns}

    def _lookup_geo(self, ip: str) -> Optional[str]:
        enabled = os.getenv("MIMOSA_GEOIP_ENABLED", "false").lower() == "true"
        if not enabled:
            return None
        provider = os.getenv("MIMOSA_GEOIP_PROVIDER", "ip-api").lower()
        if provider != "ip-api":
            return None
        base_url = os.getenv("MIMOSA_GEOIP_ENDPOINT", "http://ip-api.com/json")
        fields = "status,message,lat,lon,country,countryCode,regionName,city,timezone"
        url = f"{base_url.rstrip('/')}/{ip}"
        data = self._fetch_geo_payload(url, fields)
        if not data and base_url.startswith("https://ip-api.com"):
            parsed = urlparse(url)
            fallback = parsed._replace(scheme="http")
            data = self._fetch_geo_payload(urlunparse(fallback), fields)
        if not data:
            return None
        payload = {
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "city": data.get("city"),
            "region": data.get("regionName"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "timezone": data.get("timezone"),
            "provider": "ip-api",
        }
        if payload.get("lat") is None or payload.get("lon") is None:
            return None
        return json.dumps(payload)

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

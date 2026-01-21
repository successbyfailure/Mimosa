"""Configuracion y acceso unificado a base de datos (SQLite o Postgres)."""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

try:
    import psycopg
except ImportError:  # pragma: no cover - depende del entorno
    psycopg = None

DEFAULT_DB_PATH = Path(os.getenv("MIMOSA_DB_PATH", "data/mimosa.db"))
DEFAULT_DB_CONFIG_PATH = Path(os.getenv("MIMOSA_DB_CONFIG_PATH", "data/database.json"))


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


@dataclass
class DatabaseConfig:
    backend: str = "sqlite"
    sqlite_path: str = str(DEFAULT_DB_PATH)
    postgres_url: Optional[str] = None
    postgres_ssl_required: bool = True
    postgres_allow_self_signed: bool = True


@dataclass
class ResolvedDatabaseConfig:
    backend: str
    sqlite_path: Path
    postgres_url: Optional[str]
    postgres_ssl_required: bool
    postgres_allow_self_signed: bool


class DatabaseConfigStore:
    """Almacena la configuracion de la base de datos en un fichero local."""

    def __init__(self, path: Path | str = DEFAULT_DB_CONFIG_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> DatabaseConfig:
        if not self.path.exists():
            return DatabaseConfig()
        with self.path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            return DatabaseConfig()
        ssl_raw = raw.get("postgres_ssl_required", True)
        if isinstance(ssl_raw, bool):
            ssl_required = ssl_raw
        else:
            ssl_required = _as_bool(str(ssl_raw), True)
        allow_raw = raw.get("postgres_allow_self_signed", True)
        if isinstance(allow_raw, bool):
            allow_self_signed = allow_raw
        else:
            allow_self_signed = _as_bool(str(allow_raw), True)
        data = {
            "backend": raw.get("backend", "sqlite"),
            "sqlite_path": raw.get("sqlite_path", str(DEFAULT_DB_PATH)),
            "postgres_url": raw.get("postgres_url"),
            "postgres_ssl_required": ssl_required,
            "postgres_allow_self_signed": allow_self_signed,
        }
        return DatabaseConfig(**data)

    def save(self, config: DatabaseConfig) -> None:
        payload = asdict(config)
        with self.path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


def _apply_ssl_mode(url: str, ssl_required: bool, allow_self_signed: bool) -> str:
    if not url:
        return url
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    if not ssl_required:
        query.pop("sslmode", None)
    else:
        query["sslmode"] = "require" if allow_self_signed else "verify-full"
    return urlunparse(parsed._replace(query=urlencode(query)))


def resolve_database_config(db_path: Path | str | None = None) -> ResolvedDatabaseConfig:
    config = DatabaseConfigStore().load()

    backend_env = os.getenv("MIMOSA_DB_BACKEND")
    postgres_url_env = os.getenv("MIMOSA_DATABASE_URL")
    ssl_env = os.getenv("MIMOSA_DB_SSL_REQUIRED")
    allow_env = os.getenv("MIMOSA_DB_ALLOW_SELF_SIGNED")
    sqlite_path_env = os.getenv("MIMOSA_DB_PATH")

    backend = (backend_env or config.backend or "sqlite").strip().lower()
    if backend not in {"sqlite", "postgres"}:
        backend = "sqlite"

    sqlite_path = Path(sqlite_path_env or config.sqlite_path or DEFAULT_DB_PATH)
    postgres_url = postgres_url_env or config.postgres_url
    postgres_ssl_required = _as_bool(ssl_env, config.postgres_ssl_required)
    postgres_allow_self_signed = _as_bool(
        allow_env, config.postgres_allow_self_signed
    )

    if db_path is not None:
        resolved_path = Path(db_path)
        if resolved_path != sqlite_path:
            return ResolvedDatabaseConfig(
                backend="sqlite",
                sqlite_path=resolved_path,
                postgres_url=None,
                postgres_ssl_required=postgres_ssl_required,
                postgres_allow_self_signed=postgres_allow_self_signed,
            )

    if backend == "postgres" and postgres_url:
        return ResolvedDatabaseConfig(
            backend="postgres",
            sqlite_path=sqlite_path,
            postgres_url=_apply_ssl_mode(
                postgres_url, postgres_ssl_required, postgres_allow_self_signed
            ),
            postgres_ssl_required=postgres_ssl_required,
            postgres_allow_self_signed=postgres_allow_self_signed,
        )

    return ResolvedDatabaseConfig(
        backend="sqlite",
        sqlite_path=sqlite_path,
        postgres_url=None,
        postgres_ssl_required=postgres_ssl_required,
        postgres_allow_self_signed=postgres_allow_self_signed,
    )


class CursorWrapper:
    def __init__(self, cursor) -> None:
        self._cursor = cursor

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchone(self):
        return self._cursor.fetchone()

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def lastrowid(self) -> Optional[int]:
        return getattr(self._cursor, "lastrowid", None)


class DatabaseConnection:
    def __init__(self, raw, backend: str) -> None:
        self._raw = raw
        self._backend = backend

    def execute(self, sql: str, params: Iterable[object] | None = None) -> CursorWrapper:
        query = _normalize_query(sql, self._backend)
        cursor = self._raw.cursor()
        cursor.execute(query, tuple(params or ()))
        return CursorWrapper(cursor)

    def executemany(self, sql: str, seq: Iterable[Iterable[object]]) -> CursorWrapper:
        query = _normalize_query(sql, self._backend)
        cursor = self._raw.cursor()
        cursor.executemany(query, list(seq))
        return CursorWrapper(cursor)

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()

    def __enter__(self) -> "DatabaseConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()
        self.close()


def _normalize_query(sql: str, backend: str) -> str:
    if backend == "postgres":
        return sql.replace("?", "%s")
    return sql


class Database:
    def __init__(self, config: ResolvedDatabaseConfig) -> None:
        self.backend = config.backend
        self.sqlite_path = config.sqlite_path
        self.postgres_url = config.postgres_url
        self.postgres_ssl_required = config.postgres_ssl_required
        self.postgres_allow_self_signed = config.postgres_allow_self_signed

    def connect(self) -> DatabaseConnection:
        if self.backend == "postgres":
            if psycopg is None:  # pragma: no cover - depende del entorno
                raise RuntimeError("psycopg no esta instalado")
            if not self.postgres_url:
                raise RuntimeError("postgres_url no configurada")
            raw = psycopg.connect(self.postgres_url)
            return DatabaseConnection(raw, self.backend)
        raw = sqlite3.connect(self.sqlite_path)
        return DatabaseConnection(raw, self.backend)


def get_database(db_path: Path | str | None = None) -> Database:
    config = resolve_database_config(db_path=db_path)
    return Database(config)


def get_postgres_database(
    url: str,
    *,
    ssl_required: bool = True,
    allow_self_signed: bool = True,
) -> Database:
    config = ResolvedDatabaseConfig(
        backend="postgres",
        sqlite_path=DEFAULT_DB_PATH,
        postgres_url=_apply_ssl_mode(url, ssl_required, allow_self_signed),
        postgres_ssl_required=ssl_required,
        postgres_allow_self_signed=allow_self_signed,
    )
    return Database(config)


DatabaseError = (sqlite3.DatabaseError,) + (() if psycopg is None else (psycopg.Error,))


def insert_returning_id(conn: DatabaseConnection, sql: str, params: Iterable[object], backend: str) -> Optional[int]:
    if backend == "postgres":
        query = sql.rstrip().rstrip(";") + " RETURNING id;"
        cursor = conn.execute(query, params)
        row = cursor.fetchone()
        return int(row[0]) if row else None
    cursor = conn.execute(sql, params)
    return cursor.lastrowid


__all__ = [
    "Database",
    "DatabaseConfig",
    "DatabaseConfigStore",
    "DatabaseConnection",
    "DatabaseError",
    "DEFAULT_DB_PATH",
    "DEFAULT_DB_CONFIG_PATH",
    "get_database",
    "get_postgres_database",
    "insert_returning_id",
    "resolve_database_config",
]

"""Utilidades compartidas para persistencia en SQLite.

Centraliza la ruta por defecto y la creación de tablas utilizadas
por los distintos componentes de Mimosa.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(os.getenv("MIMOSA_DB_PATH", "data/mimosa.db"))


def ensure_database(path: Path | str = DEFAULT_DB_PATH) -> Path:
    """Crea las tablas necesarias si no existen y devuelve la ruta.

    Mantiene todas las tablas relacionadas con ofensas, perfiles de IP,
    bloqueos y listas blancas dentro del mismo fichero para facilitar
    correlaciones entre módulos.
    """

    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
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
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_offenses_source_ip
            ON offenses(source_ip);
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_profiles (
                ip TEXT PRIMARY KEY,
                geo TEXT,
                whois TEXT,
                reverse_dns TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                enriched_at TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_last_seen
            ON ip_profiles(last_seen);
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                reason TEXT NOT NULL,
                source TEXT DEFAULT 'manual',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                synced_at TEXT,
                removed_at TEXT,
                FOREIGN KEY(ip) REFERENCES ip_profiles(ip)
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocks_active
            ON blocks(active);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocks_ip
            ON blocks(ip);
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offense_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin TEXT NOT NULL,
                event_id TEXT NOT NULL DEFAULT '*',
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                min_last_hour INTEGER NOT NULL DEFAULT 1,
                min_total INTEGER NOT NULL DEFAULT 1,
                min_blocks_total INTEGER NOT NULL DEFAULT 0,
                block_minutes INTEGER
            );
            """
        )
    return db_path

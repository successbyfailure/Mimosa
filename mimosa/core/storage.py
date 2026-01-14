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
                sync_with_firewall INTEGER NOT NULL DEFAULT 1,
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
        columns = {row[1] for row in conn.execute("PRAGMA table_info(blocks);")}
        if "sync_with_firewall" not in columns:
            conn.execute(
                "ALTER TABLE blocks ADD COLUMN sync_with_firewall INTEGER NOT NULL DEFAULT 1;"
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
                min_last_hour INTEGER NOT NULL DEFAULT 0,
                min_total INTEGER NOT NULL DEFAULT 0,
                min_blocks_total INTEGER NOT NULL DEFAULT 0,
                block_minutes INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        # Migración: añadir columna enabled si no existe
        rule_columns = {row[1] for row in conn.execute("PRAGMA table_info(offense_rules);")}
        if "enabled" not in rule_columns:
            conn.execute(
                "ALTER TABLE offense_rules ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;"
            )
        # Tablas para el bot de Telegram
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telegram_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE NOT NULL,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                authorized INTEGER NOT NULL DEFAULT 0,
                authorized_at TEXT,
                authorized_by TEXT,
                first_seen TEXT,
                last_seen TEXT,
                interaction_count INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_telegram_users_telegram_id
            ON telegram_users(telegram_id);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_telegram_users_authorized
            ON telegram_users(authorized);
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telegram_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL,
                username TEXT,
                command TEXT,
                message TEXT,
                authorized INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(telegram_id) REFERENCES telegram_users(telegram_id)
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_telegram_interactions_created
            ON telegram_interactions(created_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_telegram_interactions_telegram_id
            ON telegram_interactions(telegram_id);
            """
        )
    return db_path

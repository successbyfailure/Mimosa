"""Utilidades compartidas para persistencia en SQLite o Postgres.

Centraliza la ruta por defecto y la creación de tablas utilizadas
por los distintos componentes de Mimosa.
"""
from __future__ import annotations

from pathlib import Path

from mimosa.core.database import DEFAULT_DB_PATH, get_database, get_postgres_database


def ensure_database(path: Path | str = DEFAULT_DB_PATH) -> Path:
    """Crea las tablas necesarias si no existen y devuelve la ruta.

    Mantiene todas las tablas relacionadas con ofensas, perfiles de IP,
    bloqueos y listas blancas dentro del mismo fichero para facilitar
    correlaciones entre módulos.
    """

    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = get_database(db_path=db_path)
    if db.backend == "postgres":
        _ensure_postgres(db)
        return db_path
    with db.connect() as conn:
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
                plugin TEXT,
                event_id TEXT,
                event_type TEXT,
                method TEXT,
                status_code TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                firewall_id TEXT,
                rule_id TEXT,
                tags TEXT,
                ingested_at TEXT,
                created_at TEXT NOT NULL,
                created_at_epoch INTEGER
            );
            """
        )
        offense_columns = {row[1] for row in conn.execute("PRAGMA table_info(offenses);").fetchall()}
        if "plugin" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN plugin TEXT;")
        if "event_id" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN event_id TEXT;")
        if "event_type" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN event_type TEXT;")
        if "method" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN method TEXT;")
        if "status_code" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN status_code TEXT;")
        if "protocol" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN protocol TEXT;")
        if "src_port" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN src_port INTEGER;")
        if "dst_ip" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN dst_ip TEXT;")
        if "dst_port" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN dst_port INTEGER;")
        if "firewall_id" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN firewall_id TEXT;")
        if "rule_id" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN rule_id TEXT;")
        if "tags" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN tags TEXT;")
        if "ingested_at" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN ingested_at TEXT;")
        if "created_at_epoch" not in offense_columns:
            conn.execute("ALTER TABLE offenses ADD COLUMN created_at_epoch INTEGER;")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_offenses_created
            ON offenses(created_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_offenses_source_created
            ON offenses(source_ip, created_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_offenses_plugin_created
            ON offenses(plugin, created_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_offenses_created_epoch
            ON offenses(created_at_epoch);
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
        # Migración: añadir columnas de clasificación de IP y metadata adicional
        ip_columns = {row[1] for row in conn.execute("PRAGMA table_info(ip_profiles);").fetchall()}
        backfill_offense_counts = False
        backfill_block_counts = False
        if "ip_type" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type TEXT;")
        if "ip_type_confidence" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type_confidence REAL;")
        if "ip_type_source" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type_source TEXT;")
        if "ip_type_provider" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type_provider TEXT;")
        if "isp" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN isp TEXT;")
        if "org" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN org TEXT;")
        if "asn" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN asn TEXT;")
        if "is_proxy" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN is_proxy INTEGER DEFAULT 0;")
        if "is_mobile" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN is_mobile INTEGER DEFAULT 0;")
        if "is_hosting" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN is_hosting INTEGER DEFAULT 0;")
        if "offenses_count" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN offenses_count INTEGER DEFAULT 0;")
            backfill_offense_counts = True
        if "blocks_count" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN blocks_count INTEGER DEFAULT 0;")
            backfill_block_counts = True
        if "last_offense_at" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN last_offense_at TEXT;")
            backfill_offense_counts = True
        if "last_block_at" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN last_block_at TEXT;")
            backfill_block_counts = True
        if "country_code" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN country_code TEXT;")
        if "risk_score" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN risk_score REAL;")
        if "labels" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN labels TEXT;")
        if "enriched_source" not in ip_columns:
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN enriched_source TEXT;")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_ip_type
            ON ip_profiles(ip_type);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_last_offense
            ON ip_profiles(last_offense_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_last_block
            ON ip_profiles(last_block_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_country
            ON ip_profiles(country_code);
            """
        )
        if backfill_offense_counts:
            conn.execute(
                """
                UPDATE ip_profiles
                SET offenses_count = (
                    SELECT COUNT(*)
                    FROM offenses o
                    WHERE o.source_ip = ip_profiles.ip
                ),
                last_offense_at = (
                    SELECT MAX(o.created_at)
                    FROM offenses o
                    WHERE o.source_ip = ip_profiles.ip
                );
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
                trigger_offense_id INTEGER,
                rule_id TEXT,
                firewall_id TEXT,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                reason_code TEXT,
                expires_at_epoch INTEGER,
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
            CREATE INDEX IF NOT EXISTS idx_blocks_created
            ON blocks(created_at);
            """
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(blocks);").fetchall()}
        if "sync_with_firewall" not in columns:
            conn.execute(
                "ALTER TABLE blocks ADD COLUMN sync_with_firewall INTEGER NOT NULL DEFAULT 1;"
            )
        if "trigger_offense_id" not in columns:
            conn.execute("ALTER TABLE blocks ADD COLUMN trigger_offense_id INTEGER;")
        if "rule_id" not in columns:
            conn.execute("ALTER TABLE blocks ADD COLUMN rule_id TEXT;")
        if "firewall_id" not in columns:
            conn.execute("ALTER TABLE blocks ADD COLUMN firewall_id TEXT;")
        if "acknowledged_by" not in columns:
            conn.execute("ALTER TABLE blocks ADD COLUMN acknowledged_by TEXT;")
        if "acknowledged_at" not in columns:
            conn.execute("ALTER TABLE blocks ADD COLUMN acknowledged_at TEXT;")
        if "reason_code" not in columns:
            conn.execute("ALTER TABLE blocks ADD COLUMN reason_code TEXT;")
        if "expires_at_epoch" not in columns:
            conn.execute("ALTER TABLE blocks ADD COLUMN expires_at_epoch INTEGER;")
        if backfill_block_counts:
            conn.execute(
                """
                UPDATE ip_profiles
                SET blocks_count = (
                    SELECT COUNT(*)
                    FROM blocks b
                    WHERE b.ip = ip_profiles.ip
                ),
                last_block_at = (
                    SELECT MAX(b.created_at)
                    FROM blocks b
                    WHERE b.ip = ip_profiles.ip
                );
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
                name TEXT,
                plugin TEXT NOT NULL,
                event_id TEXT NOT NULL DEFAULT '*',
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                min_last_hour INTEGER NOT NULL DEFAULT 0,
                min_total INTEGER NOT NULL DEFAULT 0,
                min_blocks_total INTEGER NOT NULL DEFAULT 0,
                block_minutes INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        # Migración: añadir columna enabled si no existe
        rule_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(offense_rules);").fetchall()
        }
        if "name" not in rule_columns:
            conn.execute("ALTER TABLE offense_rules ADD COLUMN name TEXT;")
        if "enabled" not in rule_columns:
            conn.execute(
                "ALTER TABLE offense_rules ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;"
            )
        if "priority" not in rule_columns:
            conn.execute(
                "ALTER TABLE offense_rules ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;"
            )
            conn.execute(
                "UPDATE offense_rules SET priority = id WHERE COALESCE(priority, 0) = 0;"
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS firewalls (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                base_url TEXT,
                api_key TEXT,
                api_secret TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                verify_ssl INTEGER NOT NULL DEFAULT 1,
                timeout REAL NOT NULL DEFAULT 5.0,
                apply_changes INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plugin_configs (
                name TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            """
        )
    return db_path


def ensure_postgres_database(
    url: str,
    *,
    ssl_required: bool = True,
    allow_self_signed: bool = True,
) -> None:
    db = get_postgres_database(
        url, ssl_required=ssl_required, allow_self_signed=allow_self_signed
    )
    _ensure_postgres(db)


def _postgres_column_exists(conn, table: str, column: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = ?
          AND column_name = ?
        LIMIT 1;
        """,
        (table, column),
    ).fetchone()
    return bool(row)


def _ensure_postgres(db) -> None:
    with db.connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offenses (
                id SERIAL PRIMARY KEY,
                source_ip TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                host TEXT,
                path TEXT,
                user_agent TEXT,
                context TEXT,
                plugin TEXT,
                event_id TEXT,
                event_type TEXT,
                method TEXT,
                status_code TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                firewall_id TEXT,
                rule_id TEXT,
                tags TEXT,
                ingested_at TEXT,
                created_at TEXT NOT NULL,
                created_at_epoch INTEGER
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
            CREATE INDEX IF NOT EXISTS idx_offenses_source_created
            ON offenses(source_ip, created_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_offenses_plugin_created
            ON offenses(plugin, created_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_offenses_created_epoch
            ON offenses(created_at_epoch);
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
        backfill_offense_counts = False
        backfill_block_counts = False
        if not _postgres_column_exists(conn, "ip_profiles", "ip_type"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "ip_type_confidence"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type_confidence REAL;")
        if not _postgres_column_exists(conn, "ip_profiles", "ip_type_source"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type_source TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "ip_type_provider"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN ip_type_provider TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "isp"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN isp TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "org"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN org TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "asn"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN asn TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "is_proxy"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN is_proxy INTEGER DEFAULT 0;")
        if not _postgres_column_exists(conn, "ip_profiles", "is_mobile"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN is_mobile INTEGER DEFAULT 0;")
        if not _postgres_column_exists(conn, "ip_profiles", "is_hosting"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN is_hosting INTEGER DEFAULT 0;")
        if not _postgres_column_exists(conn, "ip_profiles", "offenses_count"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN offenses_count INTEGER DEFAULT 0;")
            backfill_offense_counts = True
        if not _postgres_column_exists(conn, "ip_profiles", "blocks_count"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN blocks_count INTEGER DEFAULT 0;")
            backfill_block_counts = True
        if not _postgres_column_exists(conn, "ip_profiles", "last_offense_at"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN last_offense_at TEXT;")
            backfill_offense_counts = True
        if not _postgres_column_exists(conn, "ip_profiles", "last_block_at"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN last_block_at TEXT;")
            backfill_block_counts = True
        if not _postgres_column_exists(conn, "ip_profiles", "country_code"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN country_code TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "risk_score"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN risk_score REAL;")
        if not _postgres_column_exists(conn, "ip_profiles", "labels"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN labels TEXT;")
        if not _postgres_column_exists(conn, "ip_profiles", "enriched_source"):
            conn.execute("ALTER TABLE ip_profiles ADD COLUMN enriched_source TEXT;")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_ip_type
            ON ip_profiles(ip_type);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_last_offense
            ON ip_profiles(last_offense_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_last_block
            ON ip_profiles(last_block_at);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ip_profiles_country
            ON ip_profiles(country_code);
            """
        )
        if backfill_offense_counts:
            conn.execute(
                """
                UPDATE ip_profiles
                SET offenses_count = (
                    SELECT COUNT(*)
                    FROM offenses o
                    WHERE o.source_ip = ip_profiles.ip
                ),
                last_offense_at = (
                    SELECT MAX(o.created_at)
                    FROM offenses o
                    WHERE o.source_ip = ip_profiles.ip
                );
                """
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                reason TEXT NOT NULL,
                source TEXT DEFAULT 'manual',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                synced_at TEXT,
                removed_at TEXT,
                sync_with_firewall INTEGER NOT NULL DEFAULT 1,
                trigger_offense_id INTEGER,
                rule_id TEXT,
                firewall_id TEXT,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                reason_code TEXT,
                expires_at_epoch INTEGER
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
            CREATE INDEX IF NOT EXISTS idx_blocks_created
            ON blocks(created_at);
            """
        )
        if not _postgres_column_exists(conn, "blocks", "sync_with_firewall"):
            conn.execute(
                "ALTER TABLE blocks ADD COLUMN sync_with_firewall INTEGER NOT NULL DEFAULT 1;"
            )
        if not _postgres_column_exists(conn, "blocks", "trigger_offense_id"):
            conn.execute("ALTER TABLE blocks ADD COLUMN trigger_offense_id INTEGER;")
        if not _postgres_column_exists(conn, "blocks", "rule_id"):
            conn.execute("ALTER TABLE blocks ADD COLUMN rule_id TEXT;")
        if not _postgres_column_exists(conn, "blocks", "firewall_id"):
            conn.execute("ALTER TABLE blocks ADD COLUMN firewall_id TEXT;")
        if not _postgres_column_exists(conn, "blocks", "acknowledged_by"):
            conn.execute("ALTER TABLE blocks ADD COLUMN acknowledged_by TEXT;")
        if not _postgres_column_exists(conn, "blocks", "acknowledged_at"):
            conn.execute("ALTER TABLE blocks ADD COLUMN acknowledged_at TEXT;")
        if not _postgres_column_exists(conn, "blocks", "reason_code"):
            conn.execute("ALTER TABLE blocks ADD COLUMN reason_code TEXT;")
        if not _postgres_column_exists(conn, "blocks", "expires_at_epoch"):
            conn.execute("ALTER TABLE blocks ADD COLUMN expires_at_epoch INTEGER;")
        if backfill_block_counts:
            conn.execute(
                """
                UPDATE ip_profiles
                SET blocks_count = (
                    SELECT COUNT(*)
                    FROM blocks b
                    WHERE b.ip = ip_profiles.ip
                ),
                last_block_at = (
                    SELECT MAX(b.created_at)
                    FROM blocks b
                    WHERE b.ip = ip_profiles.ip
                );
                """
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS whitelist (
                id SERIAL PRIMARY KEY,
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
                id SERIAL PRIMARY KEY,
                name TEXT,
                plugin TEXT NOT NULL,
                event_id TEXT NOT NULL DEFAULT '*',
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                min_last_hour INTEGER NOT NULL DEFAULT 0,
                min_total INTEGER NOT NULL DEFAULT 0,
                min_blocks_total INTEGER NOT NULL DEFAULT 0,
                block_minutes INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        if not _postgres_column_exists(conn, "offense_rules", "name"):
            conn.execute("ALTER TABLE offense_rules ADD COLUMN name TEXT;")
        if not _postgres_column_exists(conn, "offense_rules", "enabled"):
            conn.execute(
                "ALTER TABLE offense_rules ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;"
            )
        if not _postgres_column_exists(conn, "offense_rules", "priority"):
            conn.execute(
                "ALTER TABLE offense_rules ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;"
            )
            conn.execute(
                "UPDATE offense_rules SET priority = id WHERE COALESCE(priority, 0) = 0;"
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telegram_users (
                id SERIAL PRIMARY KEY,
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
                id SERIAL PRIMARY KEY,
                telegram_id INTEGER NOT NULL,
                username TEXT,
                command TEXT,
                message TEXT,
                authorized INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS firewalls (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                base_url TEXT,
                api_key TEXT,
                api_secret TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                verify_ssl INTEGER NOT NULL DEFAULT 1,
                timeout REAL NOT NULL DEFAULT 5.0,
                apply_changes INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plugin_configs (
                name TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            """
        )

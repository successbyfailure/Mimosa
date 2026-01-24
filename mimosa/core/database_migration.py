"""Migracion de datos desde SQLite a Postgres."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable, List, Sequence

from mimosa.core.database import get_postgres_database
from mimosa.core.storage import ensure_postgres_database


def _sqlite_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1;",
        (table,),
    ).fetchone()
    return bool(row)


def _sqlite_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
    return {row[1] for row in rows}


def _select_expr(column: str, available: set[str]) -> str:
    if column in available:
        return column
    if column == "created_at_epoch" and "created_at" in available:
        return "CAST(strftime('%s', created_at) AS INTEGER) AS created_at_epoch"
    if column == "expires_at_epoch" and "expires_at" in available:
        return "CAST(strftime('%s', expires_at) AS INTEGER) AS expires_at_epoch"
    return f"NULL AS {column}"


def _iter_rows(
    conn: sqlite3.Connection, query: str, chunk_size: int = 500
) -> Iterable[Sequence[object]]:
    cursor = conn.execute(query)
    while True:
        rows = cursor.fetchmany(chunk_size)
        if not rows:
            break
        for row in rows:
            yield row


def _migrate_table(
    sqlite_conn: sqlite3.Connection,
    pg_conn,
    *,
    table: str,
    columns: List[str],
    conflict_target: List[str],
    update_on_conflict: bool = False,
    chunk_size: int = 500,
) -> int:
    if not _sqlite_table_exists(sqlite_conn, table):
        return 0
    available = _sqlite_columns(sqlite_conn, table)
    select_exprs = [_select_expr(col, available) for col in columns]
    query = f"SELECT {', '.join(select_exprs)} FROM {table};"
    placeholders = ", ".join(["?"] * len(columns))
    target_list = ", ".join(columns)
    conflict_list = ", ".join(conflict_target)
    if update_on_conflict:
        updates = ", ".join(
            f"{col} = excluded.{col}"
            for col in columns
            if col not in conflict_target
        )
        conflict_sql = f"ON CONFLICT({conflict_list}) DO UPDATE SET {updates}"
    else:
        conflict_sql = f"ON CONFLICT({conflict_list}) DO NOTHING"
    insert_sql = (
        f"INSERT INTO {table} ({target_list}) VALUES ({placeholders}) {conflict_sql};"
    )

    total = 0
    batch: List[Sequence[object]] = []
    for row in _iter_rows(sqlite_conn, query, chunk_size=chunk_size):
        batch.append(row)
        if len(batch) >= chunk_size:
            pg_conn.executemany(insert_sql, batch)
            total += len(batch)
            batch = []
    if batch:
        pg_conn.executemany(insert_sql, batch)
        total += len(batch)
    return total


def _load_legacy_plugins(path: Path) -> List[tuple[str, str]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    rows = []
    for name, payload in data.items():
        if name == "dummy":
            continue
        rows.append((name, json.dumps(payload)))
    return rows


def _load_legacy_firewalls(path: Path) -> List[tuple]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rows.append(
            (
                item.get("id"),
                item.get("name"),
                item.get("type"),
                item.get("base_url"),
                item.get("api_key"),
                item.get("api_secret"),
                int(item.get("enabled", True)),
                int(item.get("verify_ssl", True)),
                float(item.get("timeout", 5.0) or 5.0),
                int(item.get("apply_changes", True)),
            )
        )
    return rows


def _set_sequence(pg_conn, table: str) -> None:
    pg_conn.execute(
        f"""
        SELECT setval(
            pg_get_serial_sequence('{table}', 'id'),
            COALESCE((SELECT MAX(id) FROM {table}), 1),
            true
        );
        """
    )


def migrate_sqlite_to_postgres(
    *,
    sqlite_path: Path | str,
    postgres_url: str,
    ssl_required: bool = True,
    allow_self_signed: bool = True,
    legacy_plugins_path: Path | str = Path("data/plugins.json"),
    legacy_firewalls_path: Path | str = Path("data/firewalls.json"),
) -> dict:
    sqlite_path = Path(sqlite_path)
    if not sqlite_path.exists():
        raise FileNotFoundError(f"No existe la base de datos SQLite: {sqlite_path}")

    ensure_postgres_database(
        postgres_url, ssl_required=ssl_required, allow_self_signed=allow_self_signed
    )
    pg_db = get_postgres_database(
        postgres_url, ssl_required=ssl_required, allow_self_signed=allow_self_signed
    )

    counts: dict[str, int] = {}
    with sqlite3.connect(sqlite_path) as sqlite_conn, pg_db.connect() as pg_conn:
        counts["offenses"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="offenses",
            columns=[
                "id",
                "source_ip",
                "description",
                "severity",
                "host",
                "path",
                "user_agent",
                "context",
                "plugin",
                "event_id",
                "event_type",
                "method",
                "status_code",
                "protocol",
                "src_port",
                "dst_ip",
                "dst_port",
                "firewall_id",
                "rule_id",
                "tags",
                "ingested_at",
                "created_at",
                "created_at_epoch",
            ],
            conflict_target=["id"],
            update_on_conflict=False,
        )
        counts["ip_profiles"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="ip_profiles",
            columns=[
                "ip",
                "geo",
                "whois",
                "reverse_dns",
                "first_seen",
                "last_seen",
                "enriched_at",
                "offenses_count",
                "blocks_count",
                "ip_type",
                "ip_type_confidence",
                "ip_type_source",
                "ip_type_provider",
                "isp",
                "org",
                "asn",
                "is_proxy",
                "is_mobile",
                "is_hosting",
                "last_offense_at",
                "last_block_at",
                "country_code",
                "risk_score",
                "labels",
                "enriched_source",
            ],
            conflict_target=["ip"],
            update_on_conflict=True,
        )
        counts["blocks"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="blocks",
            columns=[
                "id",
                "ip",
                "reason",
                "source",
                "created_at",
                "expires_at",
                "active",
                "synced_at",
                "removed_at",
                "sync_with_firewall",
                "trigger_offense_id",
                "rule_id",
                "firewall_id",
                "acknowledged_by",
                "acknowledged_at",
                "reason_code",
                "expires_at_epoch",
            ],
            conflict_target=["id"],
            update_on_conflict=False,
        )
        counts["whitelist"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="whitelist",
            columns=["id", "cidr", "note", "created_at"],
            conflict_target=["id"],
            update_on_conflict=False,
        )
        counts["settings"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="settings",
            columns=["key", "value"],
            conflict_target=["key"],
            update_on_conflict=True,
        )
        counts["offense_rules"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="offense_rules",
            columns=[
                "id",
                "name",
                "plugin",
                "event_id",
                "severity",
                "description",
                "min_last_hour",
                "min_total",
                "min_blocks_total",
                "block_minutes",
                "enabled",
            ],
            conflict_target=["id"],
            update_on_conflict=True,
        )
        counts["telegram_users"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="telegram_users",
            columns=[
                "id",
                "telegram_id",
                "username",
                "first_name",
                "last_name",
                "authorized",
                "authorized_at",
                "authorized_by",
                "first_seen",
                "last_seen",
                "interaction_count",
            ],
            conflict_target=["id"],
            update_on_conflict=False,
        )
        counts["telegram_interactions"] = _migrate_table(
            sqlite_conn,
            pg_conn,
            table="telegram_interactions",
            columns=[
                "id",
                "telegram_id",
                "username",
                "command",
                "message",
                "authorized",
                "created_at",
            ],
            conflict_target=["id"],
            update_on_conflict=False,
        )

        if _sqlite_table_exists(sqlite_conn, "firewalls"):
            counts["firewalls"] = _migrate_table(
                sqlite_conn,
                pg_conn,
                table="firewalls",
                columns=[
                    "id",
                    "name",
                    "type",
                    "base_url",
                    "api_key",
                    "api_secret",
                    "enabled",
                    "verify_ssl",
                    "timeout",
                    "apply_changes",
                ],
                conflict_target=["id"],
                update_on_conflict=True,
            )
        else:
            legacy_rows = _load_legacy_firewalls(Path(legacy_firewalls_path))
            if legacy_rows:
                pg_conn.executemany(
                    """
                    INSERT INTO firewalls (
                        id, name, type, base_url, api_key, api_secret,
                        enabled, verify_ssl, timeout, apply_changes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        type = excluded.type,
                        base_url = excluded.base_url,
                        api_key = excluded.api_key,
                        api_secret = excluded.api_secret,
                        enabled = excluded.enabled,
                        verify_ssl = excluded.verify_ssl,
                        timeout = excluded.timeout,
                        apply_changes = excluded.apply_changes;
                    """,
                    legacy_rows,
                )
            counts["firewalls"] = len(legacy_rows)

        if _sqlite_table_exists(sqlite_conn, "plugin_configs"):
            counts["plugin_configs"] = _migrate_table(
                sqlite_conn,
                pg_conn,
                table="plugin_configs",
                columns=["name", "payload"],
                conflict_target=["name"],
                update_on_conflict=True,
            )
        else:
            legacy_plugins = _load_legacy_plugins(Path(legacy_plugins_path))
            if legacy_plugins:
                pg_conn.executemany(
                    """
                    INSERT INTO plugin_configs (name, payload)
                    VALUES (?, ?)
                    ON CONFLICT(name) DO UPDATE SET payload = excluded.payload;
                    """,
                    legacy_plugins,
                )
            counts["plugin_configs"] = len(legacy_plugins)

        pg_conn.execute(
            """
            UPDATE offenses
            SET created_at_epoch = EXTRACT(EPOCH FROM created_at::timestamptz)::INT
            WHERE created_at_epoch IS NULL AND created_at IS NOT NULL;
            """
        )
        pg_conn.execute(
            """
            UPDATE blocks
            SET expires_at_epoch = EXTRACT(EPOCH FROM expires_at::timestamptz)::INT
            WHERE expires_at_epoch IS NULL AND expires_at IS NOT NULL;
            """
        )
        pg_conn.execute(
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
        pg_conn.execute(
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
        for table in [
            "offenses",
            "blocks",
            "whitelist",
            "offense_rules",
            "telegram_users",
            "telegram_interactions",
        ]:
            _set_sequence(pg_conn, table)

    return counts

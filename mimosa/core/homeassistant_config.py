"""Gestion de configuracion para integracion con Home Assistant."""
from __future__ import annotations

import os
import re
import secrets
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Dict, Optional

from mimosa.core.database import DEFAULT_DB_PATH, get_database
from mimosa.core.storage import ensure_database


def _generate_token() -> str:
    return secrets.token_hex(24)


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


@dataclass
class HomeAssistantConfig:
    """Configuracion persistente de la integracion con Home Assistant."""

    enabled: bool = False
    api_token: Optional[str] = None
    expose_stats: bool = True
    expose_signals: bool = True
    expose_heatmap: bool = False
    heatmap_source: str = "offenses"
    heatmap_window: str = "24h"
    heatmap_limit: int = 300
    expose_rules: bool = True
    expose_firewall_rules: bool = False
    stats_include_timeline: bool = False

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class HomeAssistantConfigStore:
    """Almacena configuracion y estado de Home Assistant en SQLite."""

    SETTINGS_PREFIX = "homeassistant_"
    CLIENT_PREFIX = "homeassistant_client_"
    BOOL_KEYS = {
        "enabled",
        "expose_stats",
        "expose_signals",
        "expose_heatmap",
        "expose_rules",
        "expose_firewall_rules",
        "stats_include_timeline",
    }
    INT_KEYS = {"heatmap_limit"}
    _CLIENT_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)
        self._db = get_database(db_path=self.db_path)
        self._maybe_seed_from_env()

    def _connection(self):
        return self._db.connect()

    def _has_config(self) -> bool:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM settings WHERE key LIKE ? LIMIT 1;",
                (f"{self.SETTINGS_PREFIX}%",),
            ).fetchone()
        return bool(row)

    def _normalize_client_id(self, client_id: str) -> str:
        normalized = self._CLIENT_ID_RE.sub("_", (client_id or "").strip())
        if not normalized:
            normalized = "default"
        return normalized[:64]

    def _client_key(self, client_id: str, suffix: str) -> str:
        normalized = self._normalize_client_id(client_id)
        return f"{self.CLIENT_PREFIX}{normalized}_{suffix}"

    def get_config(self) -> HomeAssistantConfig:
        """Obtiene la configuracion actual."""
        config_fields = {field.name for field in fields(HomeAssistantConfig)}
        config_dict: Dict[str, object] = {}

        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT key, value FROM settings
                WHERE key LIKE ?;
                """,
                (f"{self.SETTINGS_PREFIX}%",),
            ).fetchall()

        for key, value in rows:
            clean_key = key.replace(self.SETTINGS_PREFIX, "")
            if clean_key not in config_fields:
                continue
            if value == "":
                config_dict[clean_key] = None
                continue
            if clean_key in self.BOOL_KEYS:
                config_dict[clean_key] = value.lower() == "true"
                continue
            if clean_key in self.INT_KEYS:
                try:
                    config_dict[clean_key] = int(value)
                except (TypeError, ValueError):
                    continue
                continue
            config_dict[clean_key] = value

        config = HomeAssistantConfig(**config_dict)
        if not config.api_token:
            config.api_token = _generate_token()
            self.save_config(config)
        return config

    def save_config(self, config: HomeAssistantConfig) -> None:
        """Guarda la configuracion."""
        config_dict = config.to_dict()
        with self._connection() as conn:
            for key, value in config_dict.items():
                if isinstance(value, bool):
                    str_value = "true" if value else "false"
                elif value is None:
                    str_value = ""
                else:
                    str_value = str(value)
                conn.execute(
                    """
                    INSERT INTO settings (key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                    """,
                    (f"{self.SETTINGS_PREFIX}{key}", str_value),
                )

    def update_setting(self, key: str, value: str | bool | int | None) -> None:
        """Actualiza un setting especifico."""
        if isinstance(value, bool):
            str_value = "true" if value else "false"
        elif value is None:
            str_value = ""
        else:
            str_value = str(value)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                """,
                (f"{self.SETTINGS_PREFIX}{key}", str_value),
            )

    def rotate_token(self) -> str:
        """Genera y guarda un nuevo token de API."""
        token = _generate_token()
        self.update_setting("api_token", token)
        return token

    def get_client_state(self, client_id: str) -> Dict[str, Optional[int]]:
        """Obtiene el estado del cliente (offsets para senales)."""
        keys = {
            "last_offense_id": self._client_key(client_id, "last_offense_id"),
            "last_block_id": self._client_key(client_id, "last_block_id"),
        }
        state: Dict[str, Optional[int]] = {"last_offense_id": None, "last_block_id": None}
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT key, value FROM settings
                WHERE key IN (?, ?);
                """,
                (keys["last_offense_id"], keys["last_block_id"]),
            ).fetchall()
        for key, value in rows:
            parsed: Optional[int] = None
            if value != "":
                try:
                    parsed = int(value)
                except (TypeError, ValueError):
                    parsed = None
            if key == keys["last_offense_id"]:
                state["last_offense_id"] = parsed
            elif key == keys["last_block_id"]:
                state["last_block_id"] = parsed
        return state

    def update_client_state(
        self,
        client_id: str,
        *,
        last_offense_id: Optional[int] = None,
        last_block_id: Optional[int] = None,
    ) -> None:
        """Actualiza offsets de senales para un cliente."""
        updates = {}
        if last_offense_id is not None:
            updates[self._client_key(client_id, "last_offense_id")] = last_offense_id
        if last_block_id is not None:
            updates[self._client_key(client_id, "last_block_id")] = last_block_id
        if not updates:
            return
        with self._connection() as conn:
            for key, value in updates.items():
                conn.execute(
                    """
                    INSERT INTO settings (key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                    """,
                    (key, str(value)),
                )

    def _maybe_seed_from_env(self) -> None:
        if self._has_config():
            return
        env_token = os.environ.get("HOMEASSISTANT_TOKEN")
        env_enabled = os.environ.get("HOMEASSISTANT_ENABLED")
        if env_token is None and env_enabled is None:
            return
        config = HomeAssistantConfig(
            enabled=_as_bool(env_enabled, False),
            api_token=env_token.strip() if env_token else None,
        )
        self.save_config(config)


__all__ = ["HomeAssistantConfig", "HomeAssistantConfigStore"]

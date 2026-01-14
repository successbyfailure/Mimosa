"""Gestión de configuración del bot de Telegram."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from mimosa.core.domain.telegram import TelegramBotConfig
from mimosa.core.storage import DEFAULT_DB_PATH, ensure_database


class TelegramConfigStore:
    """Almacena y recupera la configuración del bot de Telegram en la base de datos."""

    SETTINGS_PREFIX = "telegram_bot_"

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = ensure_database(db_path)

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def get_config(self) -> TelegramBotConfig:
        """Obtiene la configuración actual del bot."""
        with self._connection() as conn:
            # Obtener todos los settings relacionados con el bot
            rows = conn.execute(
                """
                SELECT key, value FROM settings
                WHERE key LIKE ?;
                """,
                (f"{self.SETTINGS_PREFIX}%",),
            ).fetchall()

        # Convertir a diccionario
        config_dict = {}
        for key, value in rows:
            # Remover el prefijo
            clean_key = key.replace(self.SETTINGS_PREFIX, "")
            # Parsear valores booleanos y JSON
            if value.lower() in ("true", "false"):
                config_dict[clean_key] = value.lower() == "true"
            else:
                try:
                    config_dict[clean_key] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    config_dict[clean_key] = value

        # Retornar configuración con valores por defecto si no existen
        return TelegramBotConfig(
            enabled=config_dict.get("enabled", False),
            bot_token=config_dict.get("bot_token"),
            welcome_message=config_dict.get(
                "welcome_message", "Bienvenido al bot de Mimosa"
            ),
            unauthorized_message=config_dict.get(
                "unauthorized_message", "No estás autorizado para usar este bot"
            ),
        )

    def save_config(self, config: TelegramBotConfig) -> None:
        """Guarda la configuración del bot."""
        config_dict = config.to_dict()

        with self._connection() as conn:
            for key, value in config_dict.items():
                # Convertir valores a string
                if isinstance(value, bool):
                    str_value = "true" if value else "false"
                elif value is None:
                    str_value = ""
                else:
                    str_value = str(value)

                # Usar INSERT ... ON CONFLICT para actualizar o insertar
                conn.execute(
                    """
                    INSERT INTO settings (key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                    """,
                    (f"{self.SETTINGS_PREFIX}{key}", str_value),
                )

    def update_setting(self, key: str, value: str | bool | None) -> None:
        """Actualiza un setting específico del bot."""
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

    def get_bot_token(self) -> Optional[str]:
        """Obtiene el token del bot."""
        config = self.get_config()
        return config.bot_token

    def is_enabled(self) -> bool:
        """Verifica si el bot está habilitado."""
        config = self.get_config()
        return config.enabled

    def enable_bot(self) -> None:
        """Habilita el bot."""
        self.update_setting("enabled", True)

    def disable_bot(self) -> None:
        """Deshabilita el bot."""
        self.update_setting("enabled", False)


__all__ = ["TelegramConfigStore"]

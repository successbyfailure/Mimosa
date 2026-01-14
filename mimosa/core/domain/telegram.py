"""Modelos de dominio para el bot de Telegram."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Optional


@dataclass
class TelegramUser:
    """Usuario autorizado para usar el bot de Telegram.

    Representa un usuario de Telegram que ha sido autorizado
    para interactuar con el bot de Mimosa.
    """

    id: int
    telegram_id: int  # ID único del usuario en Telegram
    username: Optional[str] = None  # @username en Telegram
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    authorized: bool = True
    authorized_at: Optional[datetime] = None
    authorized_by: Optional[str] = None  # Usuario de Mimosa que lo autorizó
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    interaction_count: int = 0

    def to_dict(self) -> Dict[str, object]:
        """Serializa el usuario a diccionario con fechas en formato ISO."""
        payload = asdict(self)

        def _iso(dt: Optional[datetime]) -> Optional[str]:
            if not dt:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat()

        payload["authorized_at"] = _iso(self.authorized_at)
        payload["first_seen"] = _iso(self.first_seen)
        payload["last_seen"] = _iso(self.last_seen)
        return payload


@dataclass
class TelegramInteraction:
    """Registro de una interacción con el bot de Telegram.

    Representa un comando o mensaje enviado al bot.
    """

    id: int
    telegram_id: int  # ID del usuario que interactuó
    username: Optional[str] = None
    command: Optional[str] = None  # Comando ejecutado (ej: /start, /stats)
    message: Optional[str] = None  # Mensaje completo
    authorized: bool = False  # Si el usuario estaba autorizado en ese momento
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, object]:
        """Serializa la interacción a diccionario con fechas en formato ISO."""
        payload = asdict(self)

        def _iso(dt: Optional[datetime]) -> Optional[str]:
            if not dt:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat()

        payload["created_at"] = _iso(self.created_at)
        return payload


@dataclass
class TelegramBotConfig:
    """Configuración del bot de Telegram."""

    enabled: bool = False
    bot_token: Optional[str] = None
    welcome_message: str = "Bienvenido al bot de Mimosa"
    unauthorized_message: str = "No estás autorizado para usar este bot"

    def to_dict(self) -> Dict[str, object]:
        """Serializa la configuración a diccionario."""
        return asdict(self)


__all__ = ["TelegramUser", "TelegramInteraction", "TelegramBotConfig"]

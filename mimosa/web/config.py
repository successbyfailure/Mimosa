"""Gestión de configuración y conexiones de firewalls para la UI web."""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

from mimosa.core.api import FirewallGateway
from mimosa.core.sense import BLACKLIST_ALIAS_NAME, PORT_ALIAS_NAMES, TEMPORAL_ALIAS_NAME
from mimosa.core.sense import OPNsenseClient


@dataclass
class FirewallConfig:
    """Configuración persistida para conectarse a un firewall remoto."""

    id: str
    name: str
    type: str
    base_url: str | None
    api_key: str | None
    api_secret: str | None
    verify_ssl: bool = True
    timeout: float = 5.0
    apply_changes: bool = True

    @classmethod
    def new(
        cls,
        *,
        name: str,
        type: str,
        base_url: str | None,
        api_key: str | None,
        api_secret: str | None,
        verify_ssl: bool = True,
        timeout: float = 5.0,
        apply_changes: bool = True,
    ) -> "FirewallConfig":
        return cls(
            id=uuid.uuid4().hex,
            name=name,
            type=type,
            base_url=base_url,
            api_key=api_key,
            api_secret=api_secret,
            verify_ssl=verify_ssl,
            timeout=timeout,
            apply_changes=apply_changes,
        )


class FirewallConfigStore:
    """Almacena y recupera configuraciones de firewall en disco."""

    def __init__(self, path: Path | str = Path("data/firewalls.json")) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._configs: Dict[str, FirewallConfig] = {}
        self._load()

        # Opcionalmente crea una configuración inicial a partir de variables de entorno
        # (útil para despliegues automatizados). Solo se ejecuta cuando el almacén
        # está vacío para evitar duplicados en arranques sucesivos.
        if not self._configs:
            self._maybe_seed_from_env()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data:
            sanitized = {
                key: value
                for key, value in item.items()
                if key
                in {
                    "id",
                    "name",
                    "type",
                    "base_url",
                    "api_key",
                    "api_secret",
                    "verify_ssl",
                    "timeout",
                    "apply_changes",
                }
            }
            config = FirewallConfig(**sanitized)
            self._configs[config.id] = config

    def _save(self) -> None:
        payload = [asdict(config) for config in self._configs.values()]
        with self.path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    def list(self) -> List[FirewallConfig]:
        return sorted(self._configs.values(), key=lambda cfg: cfg.name)

    def add(self, config: FirewallConfig) -> FirewallConfig:
        self._configs[config.id] = config
        self._save()
        return config

    def get(self, config_id: str) -> Optional[FirewallConfig]:
        return self._configs.get(config_id)

    def delete(self, config_id: str) -> None:
        if config_id in self._configs:
            self._configs.pop(config_id)
            self._save()

    def update(self, config_id: str, payload: FirewallConfig) -> FirewallConfig:
        if config_id not in self._configs:
            raise KeyError(config_id)
        payload.id = config_id
        self._configs[config_id] = payload
        self._save()
        return payload

    def _maybe_seed_from_env(self) -> Optional[FirewallConfig]:
        if self._configs:
            return None

        env = os.environ
        name = env.get("INITIAL_FIREWALL_NAME")
        if not name:
            return None

        firewall_type = env.get("INITIAL_FIREWALL_TYPE", "opnsense").lower()
        if firewall_type not in {"opnsense"}:
            raise ValueError("INITIAL_FIREWALL_TYPE debe ser opnsense")

        def _as_bool(value: str | None, default: bool) -> bool:
            if value is None:
                return default
            return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}

        config = FirewallConfig.new(
            name=name,
            type=firewall_type,
            base_url=env.get("INITIAL_FIREWALL_BASE_URL"),
            api_key=env.get("INITIAL_FIREWALL_API_KEY"),
            api_secret=env.get("INITIAL_FIREWALL_API_SECRET"),
            verify_ssl=_as_bool(env.get("INITIAL_FIREWALL_VERIFY_SSL"), True),
            timeout=float(env.get("INITIAL_FIREWALL_TIMEOUT") or 15),
            apply_changes=_as_bool(
                env.get("INITIAL_FIREWALL_APPLY_CHANGES"), True
            ),
        )

        return self.add(config)


def build_firewall_gateway(config: FirewallConfig) -> FirewallGateway:
    """Construye el cliente correcto según el tipo configurado."""

    if config.type == "opnsense":
        return OPNsenseClient(
            base_url=config.base_url or "",
            api_key=config.api_key or "",
            api_secret=config.api_secret or "",
            verify_ssl=config.verify_ssl,
            timeout=config.timeout,
            apply_changes=config.apply_changes,
        )
    raise ValueError(f"Tipo de firewall no soportado: {config.type}")


def check_firewall_status(config: FirewallConfig) -> Dict[str, str | bool]:
    """Comprueba conectividad con el firewall configurado."""

    gateway = build_firewall_gateway(config)
    status: Dict[str, str | bool] = {
        "id": config.id,
        "name": config.name,
        "type": config.type,
        "online": False,
        "message": "",
        "alias_ready": False,
        "alias_created": False,
        "applied_changes": False,
    }
    try:
        info = gateway.get_status()
        status["online"] = bool(info.get("available"))
        status["alias_ready"] = bool(info.get("alias_ready"))
        status["alias_created"] = bool(info.get("alias_created"))
        status["alias_details"] = info.get("alias_details")
        status["ports_alias_status"] = info.get("ports_alias_status")
        status["applied_changes"] = bool(info.get("applied_changes"))
        status["message"] = "Conexión OK" if status["online"] else "No disponible"
    except Exception as exc:  # pragma: no cover - logging superficial
        status["online"] = False
        status["message"] = str(exc)
    return status

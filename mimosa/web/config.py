"""Gestión de configuración y conexiones de firewalls para la UI web."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

from mimosa.core.firewall import DummyFirewall
from mimosa.core.pfsense import OPNsenseClient, PFSenseClient
from mimosa.core.api import FirewallGateway


@dataclass
class FirewallConfig:
    """Configuración persistida para conectarse a un firewall remoto."""

    id: str
    name: str
    type: str
    base_url: str | None
    api_key: str | None
    api_secret: str | None
    alias_name: str = "mimosa_blocklist"
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
        alias_name: str = "mimosa_blocklist",
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
            alias_name=alias_name,
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

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data:
            config = FirewallConfig(**item)
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


def build_firewall_gateway(config: FirewallConfig) -> FirewallGateway:
    """Construye el cliente correcto según el tipo configurado."""

    if config.type == "dummy":
        return DummyFirewall()
    if config.type == "opnsense":
        return OPNsenseClient(
            base_url=config.base_url or "",
            api_key=config.api_key or "",
            api_secret=config.api_secret or "",
            alias_name=config.alias_name,
            verify_ssl=config.verify_ssl,
            timeout=config.timeout,
            apply_changes=config.apply_changes,
        )
    if config.type == "pfsense":
        return PFSenseClient(
            base_url=config.base_url or "",
            api_key=config.api_key or "",
            api_secret=config.api_secret or "",
            alias_name=config.alias_name,
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
    }
    try:
        gateway.check_connection()
        status["online"] = True
        status["message"] = "Conexión OK"
    except Exception as exc:  # pragma: no cover - logging superficial
        status["online"] = False
        status["message"] = str(exc)
    return status

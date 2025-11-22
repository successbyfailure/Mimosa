"""Gestión de plugins y configuración persistente.

Incluye utilidades mínimas para almacenar la configuración de plugins
en disco y exponer defaults sensatos tanto para el plugin "dummy"
como para el nuevo plugin "proxytrap".
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List


DEFAULT_PROXYTRAP_POLICIES = [
    {"pattern": "phpmyadmin.*", "severity": "alto"},
    {"pattern": "admin.*", "severity": "alto"},
    {"pattern": "*.admin", "severity": "alto"},
    {"pattern": "cpanel.*", "severity": "alto"},
]


@dataclass
class DummyPluginConfig:
    """Configuración del plugin manual de ofensas."""

    name: str = "dummy"
    enabled: bool = True


@dataclass
class ProxyTrapConfig:
    """Opciones del plugin ProxyTrap."""

    name: str = "proxytrap"
    enabled: bool = False
    port: int = 8081
    default_severity: str = "alto"
    response_type: str = "404"
    custom_html: str | None = None
    domain_policies: List[Dict[str, str]] = field(
        default_factory=lambda: list(DEFAULT_PROXYTRAP_POLICIES)
    )
    wildcard_severity: str | None = None


class PluginConfigStore:
    """Almacena configuraciones de plugins en un fichero JSON."""

    def __init__(self, path: Path | str = Path("data/plugins.json")) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._plugins: Dict[str, Dict[str, object]] = {}
        self._load()
        if not self._plugins:
            self._bootstrap_defaults()

    def _bootstrap_defaults(self) -> None:
        dummy = asdict(DummyPluginConfig())
        proxytrap = asdict(ProxyTrapConfig())
        self._plugins = {dummy["name"]: dummy, proxytrap["name"]: proxytrap}
        self._save()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            self._plugins = json.load(fh)

    def _save(self) -> None:
        with self.path.open("w", encoding="utf-8") as fh:
            json.dump(self._plugins, fh, indent=2)

    def list(self) -> List[Dict[str, object]]:
        """Devuelve todas las configuraciones conocidas."""

        return list(self._plugins.values())

    def get_proxytrap(self) -> ProxyTrapConfig:
        config = self._plugins.get("proxytrap")
        if not config:
            proxytrap = ProxyTrapConfig()
            self._plugins[proxytrap.name] = asdict(proxytrap)
            self._save()
            return proxytrap
        return ProxyTrapConfig(**config)

    def update_proxytrap(self, payload: ProxyTrapConfig) -> ProxyTrapConfig:
        self._plugins[payload.name] = asdict(payload)
        self._save()
        return payload


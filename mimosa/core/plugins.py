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

COMMON_SERVICE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 5432, 6379, 8080]


@dataclass
class PortDetectorRule:
    """Regla de escucha asociada a un puerto o rango."""

    protocol: str = "tcp"
    severity: str = "medio"
    port: int | None = None
    ports: List[int] = field(default_factory=list)
    start: int | None = None
    end: int | None = None


def _default_port_rules() -> List[PortDetectorRule]:
    return [
        PortDetectorRule(protocol="tcp", severity="alto", ports=list(COMMON_SERVICE_PORTS)),
        PortDetectorRule(protocol="tcp", severity="medio", start=5900, end=5903),
        PortDetectorRule(protocol="udp", severity="medio", ports=[53, 123]),
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


@dataclass
class PortDetectorConfig:
    """Opciones del plugin Port Detector."""

    name: str = "portdetector"
    enabled: bool = False
    default_severity: str = "medio"
    rules: List[PortDetectorRule] = field(default_factory=_default_port_rules)


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
        portdetector = asdict(PortDetectorConfig())
        self._plugins = {
            dummy["name"]: dummy,
            proxytrap["name"]: proxytrap,
            portdetector["name"]: portdetector,
        }
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
        config = dict(config)
        config.pop("wildcard_severity", None)
        return ProxyTrapConfig(**config)

    def update_proxytrap(self, payload: ProxyTrapConfig) -> ProxyTrapConfig:
        self._plugins[payload.name] = asdict(payload)
        self._save()
        return payload

    def get_port_detector(self) -> PortDetectorConfig:
        config = self._plugins.get("portdetector")
        if not config:
            instance = PortDetectorConfig()
            self._plugins[instance.name] = asdict(instance)
            self._save()
            return instance
        loaded_rules = []
        for entry in config.get("rules", []):
            loaded_rules.append(PortDetectorRule(**entry))
        return PortDetectorConfig(
            enabled=bool(config.get("enabled", False)),
            default_severity=config.get("default_severity", "medio"),
            rules=loaded_rules or _default_port_rules(),
        )

    def update_port_detector(self, payload: PortDetectorConfig) -> PortDetectorConfig:
        sanitized = asdict(payload)
        self._plugins[payload.name] = sanitized
        self._save()
        return payload


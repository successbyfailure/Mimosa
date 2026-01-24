"""Gestión de plugins y configuración persistente."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, asdict, field
import os
from pathlib import Path
from typing import Dict, List

from mimosa.core.database import DEFAULT_DB_PATH, get_database
from mimosa.core.storage import ensure_database


DEFAULT_PROXYTRAP_POLICIES = [
    {"pattern": "phpmyadmin.*", "severity": "alto"},
    {"pattern": "admin.*", "severity": "alto"},
    {"pattern": "*.admin", "severity": "alto"},
    {"pattern": "cpanel.*", "severity": "alto"},
]

COMMON_SERVICE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 5432, 6379, 8080]


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass
class PortDetectorRule:
    """Regla de escucha asociada a un puerto o rango."""

    protocol: str = "tcp"
    severity: str = "medio"
    description: str | None = None
    port: int | None = None
    ports: List[int] = field(default_factory=list)
    start: int | None = None
    end: int | None = None


def _default_port_rules() -> List[PortDetectorRule]:
    return [
        PortDetectorRule(
            protocol="tcp",
            severity="alto",
            description="RemoteAccess",
            ports=[2200, 2222, 3389, 5900, 5901, 5902, 5903, 5938, 6080, 7070, 8200, 12975],
        ),
        PortDetectorRule(
            protocol="udp",
            severity="medio",
            description="-",
            ports=[53, 123],
        ),
        PortDetectorRule(
            protocol="tcp",
            severity="alto",
            description="databases",
            ports=[1521, 1433, 3306, 5432, 27017, 6379, 9200, 9042],
        ),
        PortDetectorRule(
            protocol="tcp",
            severity="alto",
            description="Infra",
            ports=[21, 23, 389, 445, 636, 631],
        ),
        PortDetectorRule(
            protocol="tcp",
            severity="alto",
            description="HTTP-dev",
            ports=[8000, 8001, 8080, 8443, 5000, 3000],
        ),
        PortDetectorRule(
            protocol="tcp",
            severity="alto",
            description="email",
            ports=[25, 110, 143, 465, 587, 993, 995],
        ),
    ]


@dataclass
class ProxyTrapConfig:
    """Opciones del plugin ProxyTrap."""

    name: str = "proxytrap"
    enabled: bool = False
    port: int = field(default_factory=lambda: _env_int("MIMOSA_PROXYTRAP_PORT", 8081))
    default_severity: str = "alto"
    response_type: str = "404"
    custom_html: str | None = None
    trap_hosts: List[str] = field(default_factory=list)
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


def _generate_secret() -> str:
    return secrets.token_hex(24)


@dataclass
class MimosaNpmConfig:
    """Ajustes para el agente externo de Nginx Proxy Manager."""

    name: str = "mimosanpm"
    enabled: bool = False
    default_severity: str = "alto"
    fallback_severity: str | None = None
    rules: List["MimosaNpmRule"] = field(default_factory=list)
    ignore_list: List["MimosaNpmIgnoreRule"] = field(default_factory=list)
    shared_secret: str = field(default_factory=_generate_secret)
    alert_fallback: bool = True
    alert_unregistered_domain: bool = True
    alert_suspicious_path: bool = True


@dataclass
class MimosaNpmRule:
    """Regla de severidad para alertas de MimosaNPM."""

    host: str = "*"
    path: str = "*"
    status: str = "*"
    severity: str = "medio"


@dataclass
class MimosaNpmIgnoreRule:
    """Regla para ignorar alertas de MimosaNPM."""

    host: str = "*"
    path: str = "*"
    status: str = "*"


class PluginConfigStore:
    """Almacena configuraciones de plugins en la base de datos."""

    def __init__(
        self,
        db_path: Path | str = DEFAULT_DB_PATH,
        legacy_path: Path | str | None = None,
    ) -> None:
        self.db_path = ensure_database(db_path)
        self._db = get_database(db_path=self.db_path)
        self._legacy_path = Path(legacy_path or "data/plugins.json")
        self._legacy_path.parent.mkdir(parents=True, exist_ok=True)
        self._plugins: Dict[str, Dict[str, object]] = {}
        self._load()
        if not self._plugins:
            self._bootstrap_defaults()

    def _bootstrap_defaults(self) -> None:
        proxytrap = asdict(ProxyTrapConfig())
        portdetector = asdict(PortDetectorConfig())
        mimosanpm = asdict(MimosaNpmConfig())
        self._plugins = {
            proxytrap["name"]: proxytrap,
            portdetector["name"]: portdetector,
            mimosanpm["name"]: mimosanpm,
        }
        self._save()

    def _load(self) -> None:
        self._plugins = {}
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT name, payload FROM plugin_configs;"
            ).fetchall()
        if not rows and self._legacy_path.exists():
            try:
                with self._legacy_path.open("r", encoding="utf-8") as fh:
                    self._plugins = json.load(fh)
            except (json.JSONDecodeError, OSError):
                self._plugins = {}
            if "dummy" in self._plugins:
                self._plugins.pop("dummy", None)
            if self._plugins:
                self._save()
            with self._db.connect() as conn:
                rows = conn.execute(
                    "SELECT name, payload FROM plugin_configs;"
                ).fetchall()
        for row in rows:
            name = row[0]
            payload = row[1]
            try:
                data = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                data = {}
            if isinstance(data, dict):
                self._plugins[name] = data

    def _save(self) -> None:
        with self._db.connect() as conn:
            conn.execute("DELETE FROM plugin_configs;")
            rows = [
                (name, json.dumps(payload))
                for name, payload in self._plugins.items()
            ]
            if rows:
                conn.executemany(
                    "INSERT INTO plugin_configs (name, payload) VALUES (?, ?);",
                    rows,
                )

    def list(self) -> List[Dict[str, object]]:
        """Devuelve todas las configuraciones conocidas."""

        return [
            plugin for name, plugin in self._plugins.items() if name != "dummy"
        ]

    def get_proxytrap(self) -> ProxyTrapConfig:
        config = self._plugins.get("proxytrap")
        if not config:
            proxytrap = ProxyTrapConfig()
            self._plugins[proxytrap.name] = asdict(proxytrap)
            self._save()
            return proxytrap
        config = dict(config)
        config.pop("wildcard_severity", None)
        config.pop("reverse_proxy", None)
        trap_hosts = config.get("trap_hosts") or []
        if "trap_hosts" not in config:
            config["trap_hosts"] = list(trap_hosts)
            self._plugins["proxytrap"] = config
            self._save()
        if "domain_policies" not in config:
            config["domain_policies"] = list(DEFAULT_PROXYTRAP_POLICIES)
            self._plugins["proxytrap"] = config
            self._save()
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

    def generate_secret(self) -> str:
        """Genera un secreto aleatorio reutilizando el helper interno."""

        return _generate_secret()

    def get_mimosanpm(self) -> MimosaNpmConfig:
        config = self._plugins.get("mimosanpm")
        if not config:
            instance = MimosaNpmConfig()
            self._plugins[instance.name] = asdict(instance)
            self._save()
            return instance

        shared_secret = config.get("shared_secret") or _generate_secret()
        rules = []
        for entry in config.get("rules", []) or []:
            rules.append(MimosaNpmRule(**entry))
        ignore_list = []
        for entry in config.get("ignore_list", []) or []:
            ignore_list.append(MimosaNpmIgnoreRule(**entry))
        fallback_severity = config.get("fallback_severity") or None
        loaded = MimosaNpmConfig(
            enabled=bool(config.get("enabled", False)),
            default_severity=config.get("default_severity", "alto"),
            fallback_severity=fallback_severity,
            rules=rules,
            ignore_list=ignore_list,
            shared_secret=str(shared_secret),
            alert_fallback=bool(config.get("alert_fallback", True)),
            alert_unregistered_domain=bool(
                config.get("alert_unregistered_domain", True)
            ),
            alert_suspicious_path=bool(config.get("alert_suspicious_path", True)),
        )
        # Normaliza y persiste secretos faltantes.
        self._plugins[loaded.name] = asdict(loaded)
        self._save()
        return loaded

    def update_mimosanpm(self, payload: MimosaNpmConfig) -> MimosaNpmConfig:
        sanitized = asdict(payload)
        if not sanitized.get("shared_secret"):
            sanitized["shared_secret"] = _generate_secret()
        self._plugins[payload.name] = sanitized
        self._save()
        return payload

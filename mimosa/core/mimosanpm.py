"""Ingestión de alertas provenientes de Nginx Proxy Manager.

El agente externo (MimosaNPM) lee los logs de NPM y publica eventos a Mimosa
para que se registren ofensas y se apliquen reglas de bloqueo.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Callable, Iterable

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.core.plugins import MimosaNpmConfig, MimosaNpmIgnoreRule, MimosaNpmRule
from mimosa.core.rules import OffenseEvent, OffenseRule, OffenseRuleStore, RuleManager


@dataclass
class MimosaNpmAlert:
    """Alerta mínima emitida por el agente de NPM."""

    source_ip: str
    requested_host: str
    path: str | None = None
    user_agent: str | None = None
    severity: str | None = None
    status_code: int | None = None
    alert_type: str | None = None
    alert_tags: list[str] | None = None
    log_source: str | None = None


class MimosaNpmService:
    """Procesa alertas del agente externo y ejecuta reglas locales."""

    def __init__(
        self,
        offense_store: OffenseStore,
        block_manager: BlockManager,
        rule_store: OffenseRuleStore,
        gateway_factory: Callable[[], object],
    ) -> None:
        self.offense_store = offense_store
        self.block_manager = block_manager
        self.rule_store = rule_store
        self._gateway_factory = gateway_factory
        self.config = MimosaNpmConfig()

    def apply_config(self, config: MimosaNpmConfig) -> None:
        """Actualiza la configuración activa."""

        self.config = config

    def ingest(self, alerts: Iterable[MimosaNpmAlert]) -> int:
        """Registra ofensas y evalúa reglas para cada alerta recibida."""

        processed = 0
        for alert in alerts:
            self._handle_alert(alert)
            processed += 1
        return processed

    def _handle_alert(self, alert: MimosaNpmAlert) -> None:
        if not self._is_alert_enabled(alert):
            return
        host = (alert.requested_host or "desconocido").strip()
        path = (alert.path or "/").strip() or "/"
        status_code = alert.status_code if alert.status_code is not None else "n/a"
        if self._is_ignored(host, path, status_code):
            return
        severity = (
            self._severity_from_rules(host, path, status_code)
            or alert.severity
            or self.config.default_severity
        )
        alert_type = alert.alert_type or "unknown"
        description = (
            f"mimosanpm:{alert_type} host={host} path={path} status={status_code}"
        )
        context = {
            "plugin": "mimosanpm",
            "status_code": alert.status_code,
            "alert_type": alert.alert_type,
            "alert_tags": alert.alert_tags,
            "log_source": alert.log_source,
        }
        sanitized_context = {k: v for k, v in context.items() if v is not None}

        self.offense_store.record(
            source_ip=alert.source_ip or "desconocido",
            description=description,
            severity=severity,
            host=host,
            path=path,
            user_agent=alert.user_agent,
            plugin="mimosanpm",
            event_id=alert_type,
            event_type=alert.alert_type,
            status_code=alert.status_code,
            tags=alert.alert_tags,
            context=sanitized_context,
        )
        self._process_rules(alert_type, alert.source_ip, severity, description)

    def _process_rules(
        self, event_id: str, source_ip: str | None, severity: str, description: str
    ) -> None:
        manager = RuleManager(
            self.offense_store,
            self.block_manager,
            self._gateway_factory(),
            rules=self.rule_store.list() or [OffenseRule()],
        )
        manager.process_offense(
            OffenseEvent(
                source_ip=source_ip or "desconocido",
                plugin="mimosanpm",
                event_id=event_id,
                severity=severity,
                description=description,
            )
        )

    def _is_alert_enabled(self, alert: MimosaNpmAlert) -> bool:
        alert_type = (alert.alert_type or "").lower()
        if alert_type == "fallback":
            return self.config.alert_fallback
        if alert_type == "unregistered_domain":
            return self.config.alert_unregistered_domain
        if alert_type == "suspicious_path":
            return self.config.alert_suspicious_path
        return True

    def _is_ignored(self, host: str, path: str, status_code: int | str) -> bool:
        status_value = str(status_code)
        for rule in self.config.ignore_list or []:
            if self._matches_rule(rule, host, path, status_value):
                return True
        return False

    def _severity_from_rules(
        self, host: str, path: str, status_code: int | str
    ) -> str | None:
        status_value = str(status_code)
        for rule in self.config.rules or []:
            if self._matches_rule(rule, host, path, status_value):
                return rule.severity
        return None

    def _matches_rule(
        self,
        rule: MimosaNpmRule | MimosaNpmIgnoreRule,
        host: str,
        path: str,
        status_code: str,
    ) -> bool:
        host_value = host.lower()
        host_pattern = (rule.host or "*").lower()
        path_value = path or "/"
        path_pattern = rule.path or "*"
        status_pattern = rule.status or "*"
        return (
            fnmatchcase(host_value, host_pattern)
            and fnmatchcase(path_value, path_pattern)
            and fnmatchcase(status_code, status_pattern)
        )

"""Ingestión de alertas provenientes de Nginx Proxy Manager.

El agente externo (MimosaNPM) lee los logs de NPM y publica eventos a Mimosa
para que se registren ofensas y se apliquen reglas de bloqueo.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.core.plugins import MimosaNpmConfig
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
        severity = alert.severity or self.config.default_severity
        host = alert.requested_host or "desconocido"
        path = alert.path or "/"
        alert_type = alert.alert_type or "unknown"
        description = f"mimosanpm:{alert_type}"
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

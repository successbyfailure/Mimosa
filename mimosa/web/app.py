"""Aplicación FastAPI que sirve el dashboard y el panel de control."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Literal, Optional

from fastapi import FastAPI, HTTPException, Request, Response
import httpx
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from mimosa.core.api import FirewallGateway
from mimosa.core.blocking import BlockEntry, BlockManager
from mimosa.core.offenses import OffenseRecord, OffenseStore
from mimosa.core.plugins import (
    MimosaNpmConfig,
    PluginConfigStore,
    PortDetectorConfig,
    PortDetectorRule,
    ProxyTrapConfig,
)
from mimosa.core.sense import (
    BLACKLIST_ALIAS_NAME,
    PORT_ALIAS_NAMES,
    TEMPORAL_ALIAS_NAME,
    WHITELIST_ALIAS_NAME,
)
from mimosa.core.portdetector import (
    PortBindingError,
    PortDetectorService,
    collect_ports_by_protocol,
)
from mimosa.core.mimosanpm import MimosaNpmAlert, MimosaNpmService
from mimosa.core.proxytrap import ProxyTrapService
from mimosa.core.rules import OffenseEvent, OffenseRule, OffenseRuleStore, RuleManager
from mimosa.web.config import (
    FirewallConfig,
    FirewallConfigStore,
    build_firewall_gateway,
    check_firewall_status,
)


def _load_app_version() -> str:
    """Lee el número de versión desde el archivo compartido de versionado."""

    version_path = Path(__file__).resolve().parents[2] / "version.json"
    try:
        data = json.loads(version_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "0.0.0"

    return str(data.get("version", "0.0.0"))


class FirewallInput(BaseModel):
    """Payload para crear y probar conexiones con firewalls."""

    name: str
    type: Literal["opnsense", "pfsense"]
    base_url: str | None = None
    api_key: str | None = None
    api_secret: str | None = None
    verify_ssl: bool = True
    timeout: float = 5.0
    apply_changes: bool = True


class BlockInput(BaseModel):
    """Payload para crear o eliminar entradas de bloqueo manual."""

    ip: str
    reason: str | None = None
    duration_minutes: int | None = None
    sync_with_firewall: bool = True


class BlacklistInput(BaseModel):
    """Entrada para gestionar la lista negra permanente."""

    ip: str
    reason: str | None = None


class BlockingSettingsInput(BaseModel):
    """Configuración del gestor de bloqueos."""

    default_duration_minutes: int = 60
    sync_interval_seconds: int = 300


class ProxyTrapDomainInput(BaseModel):
    """Dominio/host específico con severidad personalizada."""

    pattern: str
    severity: str = "alto"


class ProxyTrapInput(BaseModel):
    """Configuración expuesta para el plugin ProxyTrap."""

    enabled: bool = False
    port: int = 8081
    default_severity: str = "alto"
    response_type: Literal["silence", "404", "custom"] = "404"
    custom_html: str | None = None
    trap_hosts: List[str] = Field(default_factory=list)
    domain_policies: List[ProxyTrapDomainInput] = Field(default_factory=list)


class PortDetectorRuleInput(BaseModel):
    """Regla de configuración para Port Detector."""

    protocol: Literal["tcp", "udp"] = "tcp"
    severity: str = "medio"
    port: int | None = None
    ports: List[int] | None = None
    start: int | None = None
    end: int | None = None


class PortDetectorInput(BaseModel):
    """Configuración expuesta para el plugin Port Detector."""

    enabled: bool = False
    default_severity: str = "medio"
    rules: List[PortDetectorRuleInput] = Field(default_factory=list)


class MimosaNpmConfigInput(BaseModel):
    """Config pública del agente MimosaNPM."""

    enabled: bool = False
    default_severity: str = "alto"
    shared_secret: str | None = None
    rotate_secret: bool = False
    alert_fallback: bool = True
    alert_unregistered_domain: bool = True
    alert_suspicious_path: bool = True


class MimosaNpmAlertInput(BaseModel):
    """Evento emitido por el agente desplegado junto a NPM."""

    source_ip: str
    host: str
    path: Optional[str] = None
    user_agent: Optional[str] = None
    severity: Optional[str] = None
    status_code: Optional[int] = None
    alert_type: Optional[str] = None
    alert_tags: Optional[List[str]] = None
    log_source: Optional[str] = None


class MimosaNpmBatchInput(BaseModel):
    """Permite enviar eventos en lote."""

    alerts: List[MimosaNpmAlertInput] = Field(default_factory=list)


class OffenseInput(BaseModel):
    """Payload para crear ofensas manuales desde la UI."""

    source_ip: str
    plugin: str = "manual"
    event_id: str = "manual"
    description: str
    severity: str = "medio"
    host: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    context: Optional[Dict[str, str]] = None


class RuleInput(BaseModel):
    """Definición de regla configurable desde la UI."""

    plugin: str = "*"
    event_id: str = "*"
    severity: str = "*"
    description: str = "*"
    min_last_hour: int = 0
    min_total: int = 0
    min_blocks_total: int = 0
    block_minutes: int | None = None


class WhitelistInput(BaseModel):
    """Entrada para la lista blanca."""

    cidr: str
    note: str | None = None


def create_app(
    *,
    offense_store: OffenseStore | None = None,
    block_manager: BlockManager | None = None,
    config_store: FirewallConfigStore | None = None,
    rule_store: OffenseRuleStore | None = None,
    proxytrap_stats_path: Path | str | None = None,
    portdetector_stats_path: Path | str | None = None,
) -> FastAPI:
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

    app_version = _load_app_version()
    app = FastAPI(title="Mimosa UI", version=app_version)
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    )

    templates.env.globals["mimosa_version"] = app_version

    offense_store = offense_store or OffenseStore()
    block_manager = block_manager or BlockManager(
        db_path=offense_store.db_path, whitelist_checker=offense_store.is_whitelisted
    )
    block_manager.set_whitelist_checker(offense_store.is_whitelisted)
    config_store = config_store or FirewallConfigStore()
    rule_store = rule_store or OffenseRuleStore(db_path=offense_store.db_path)
    plugin_store = PluginConfigStore()
    gateway_cache: Dict[str, FirewallGateway] = {}
    proxytrap_stats_path = proxytrap_stats_path or Path("data/proxytrap_stats.json")
    portdetector_stats_path = portdetector_stats_path or Path(
        "data/portdetector_stats.json"
    )
    proxytrap_service = ProxyTrapService(
        offense_store,
        block_manager,
        rule_store,
        gateway_factory=lambda: _select_gateway(),
        stats_path=proxytrap_stats_path,
    )
    portdetector_service = PortDetectorService(
        offense_store,
        block_manager,
        rule_store,
        gateway_factory=lambda: _select_gateway(),
        stats_path=portdetector_stats_path,
    )
    mimosanpm_service = MimosaNpmService(
        offense_store,
        block_manager,
        rule_store,
        gateway_factory=lambda: _select_gateway(),
    )

    def _select_gateway() -> FirewallGateway:
        configs = config_store.list()
        if not configs:
            raise RuntimeError("Configura un firewall OPNsense antes de continuar")

        primary = configs[0]
        cached = gateway_cache.get(primary.id)
        if cached:
            return cached

        gateway = build_firewall_gateway(primary)
        gateway_cache[primary.id] = gateway
        return gateway

    def _primary_gateway_or_error() -> FirewallGateway:
        try:
            return _select_gateway()
        except RuntimeError as exc:
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            )

    def _cleanup_expired_blocks() -> None:
        gateway: FirewallGateway | None = None
        try:
            gateway = _select_gateway()
        except RuntimeError:
            gateway = None
        block_manager.purge_expired(firewall_gateway=gateway)

    def _rule_manager() -> RuleManager:
        return RuleManager(
            offense_store,
            block_manager,
            _primary_gateway_or_error(),
            rules=rule_store.list() or [OffenseRule()],
        )

    def _get_firewall(config_id: str) -> tuple[FirewallConfig, FirewallGateway]:
        config = config_store.get(config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Firewall no encontrado")
        gateway = gateway_cache.get(config.id)
        if not gateway:
            gateway = build_firewall_gateway(config)
            gateway_cache[config.id] = gateway
        return config, gateway

    def _sync_whitelist_entry(cidr: str, *, remove: bool = False) -> None:
        for config in config_store.list():
            gateway = gateway_cache.get(config.id)
            if not gateway:
                gateway = build_firewall_gateway(config)
                gateway_cache[config.id] = gateway
            try:
                gateway.ensure_ready()
                if remove:
                    gateway.remove_from_whitelist(cidr)
                    continue
                try:
                    current = set(gateway.list_whitelist())
                except NotImplementedError:
                    continue
                if cidr in current:
                    continue
                gateway.add_to_whitelist(cidr)
            except NotImplementedError:
                continue
            except httpx.HTTPStatusError:
                continue

    def _sync_whitelist_full(gateway: FirewallGateway, desired: List[str]) -> List[str]:
        try:
            current = gateway.list_whitelist()
        except NotImplementedError:
            return []
        desired_set = set(entry for entry in desired if entry)
        current_set = set(entry for entry in current if entry)

        missing = []
        for entry in desired_set:
            if entry in current_set or f"{entry}/32" in current_set:
                continue
            missing.append(entry)

        to_remove = []
        for entry in current_set:
            if entry in desired_set:
                continue
            if entry.endswith("/32") and entry[:-3] in desired_set:
                continue
            to_remove.append(entry)

        for entry in missing:
            gateway.add_to_whitelist(entry)
        for entry in to_remove:
            gateway.remove_from_whitelist(entry)

        try:
            return gateway.list_whitelist()
        except NotImplementedError:
            return []

    def _serialize_block(entry: BlockEntry) -> Dict[str, object]:
        return entry.to_dict()

    def _serialize_offense(offense: OffenseRecord) -> Dict[str, object]:
        created_at = offense.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        else:
            created_at = created_at.astimezone(timezone.utc)
        description = offense.description or ""
        plugin = None
        if offense.context and isinstance(offense.context, dict):
            plugin = offense.context.get("plugin")

        description_clean = description
        if plugin and description.startswith(f"{plugin}:"):
            description_clean = description[len(plugin) + 1 :].lstrip()
        elif not plugin and ":" in description:
            prefix, rest = description.split(":", 1)
            prefix = prefix.strip()
            if prefix and all(ch.isalnum() or ch in "-_." for ch in prefix):
                plugin = prefix
                description_clean = rest.lstrip()

        return {
            "id": offense.id,
            "source_ip": offense.source_ip,
            "description": offense.description,
            "description_clean": description_clean,
            "plugin": plugin,
            "severity": offense.severity,
            "created_at": created_at.isoformat(),
            "host": offense.host,
            "path": offense.path,
            "user_agent": offense.user_agent,
            "context": offense.context,
        }

    def _serialize_rule(rule: OffenseRule) -> Dict[str, object]:
        return {
            "id": rule.id,
            "plugin": rule.plugin,
            "event_id": rule.event_id,
            "severity": rule.severity,
            "description": rule.description,
            "min_last_hour": rule.min_last_hour,
            "min_total": rule.min_total,
            "min_blocks_total": rule.min_blocks_total,
            "block_minutes": rule.block_minutes,
        }

    def _parse_geo_point(raw: object) -> Optional[Dict[str, float]]:
        if raw is None:
            return None
        if isinstance(raw, dict):
            lat = raw.get("lat") or raw.get("latitude")
            lon = raw.get("lon") or raw.get("lng") or raw.get("longitude")
            if lat is None or lon is None:
                return None
            return {"lat": float(lat), "lon": float(lon)}
        if isinstance(raw, str):
            text = raw.strip()
            if not text:
                return None
            try:
                payload = json.loads(text)
                return _parse_geo_point(payload)
            except json.JSONDecodeError:
                pass
            if "," in text:
                parts = [part.strip() for part in text.split(",")]
                if len(parts) >= 2:
                    try:
                        lat = float(parts[0])
                        lon = float(parts[1])
                        return {"lat": lat, "lon": lon}
                    except ValueError:
                        return None
        return None

    def _parse_geo_country(raw: object) -> Optional[Dict[str, Optional[str]]]:
        if raw is None:
            return None
        if isinstance(raw, dict):
            return {
                "country": raw.get("country"),
                "country_code": raw.get("country_code") or raw.get("countryCode"),
            }
        if isinstance(raw, str):
            text = raw.strip()
            if not text:
                return None
            try:
                payload = json.loads(text)
                return _parse_geo_country(payload)
            except json.JSONDecodeError:
                return None
        return None

    def _serialize_plugins() -> List[Dict[str, object]]:
        proxytrap_config = plugin_store.get_proxytrap()
        portdetector_config = plugin_store.get_port_detector()
        mimosanpm_config = plugin_store.get_mimosanpm()
        return [
            {
                "name": "proxytrap",
                "enabled": proxytrap_config.enabled,
                "config": proxytrap_config.__dict__,
            },
            {
                "name": "portdetector",
                "enabled": portdetector_config.enabled,
                "config": asdict(portdetector_config),
            },
            {
                "name": "mimosanpm",
                "enabled": mimosanpm_config.enabled,
                "config": asdict(mimosanpm_config),
            },
        ]

    proxytrap_service.apply_config(plugin_store.get_proxytrap())
    portdetector_service.apply_config(plugin_store.get_port_detector())
    mimosanpm_service.apply_config(plugin_store.get_mimosanpm())

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        return templates.TemplateResponse("dashboard.html", {"request": request})

    @app.get("/admin", response_class=HTMLResponse)
    def admin(request: Request):
        return templates.TemplateResponse("admin.html", {"request": request})

    def _stats_payload() -> Dict[str, Dict[str, object]]:
        now = datetime.utcnow()
        seven_days = timedelta(days=7)
        day = timedelta(hours=24)
        hour = timedelta(hours=1)

        def _bucket_format(bucket: str) -> str:
            return {
                "day": "%Y-%m-%d",
                "hour": "%Y-%m-%d %H:00",
                "minute": "%Y-%m-%d %H:%M",
            }[bucket]

        def _bucket_step(bucket: str) -> timedelta:
            return {
                "day": timedelta(days=1),
                "hour": timedelta(hours=1),
                "minute": timedelta(minutes=1),
            }[bucket]

        def _floor_time(value: datetime, bucket: str) -> datetime:
            if bucket == "day":
                return value.replace(hour=0, minute=0, second=0, microsecond=0)
            if bucket == "hour":
                return value.replace(minute=0, second=0, microsecond=0)
            if bucket == "minute":
                return value.replace(second=0, microsecond=0)
            raise ValueError(f"Bucket desconocido: {bucket}")

        def _complete_timeline(
            timeline: List[Dict[str, str | int]],
            window: timedelta,
            bucket: str,
        ) -> List[Dict[str, str | int]]:
            step = _bucket_step(bucket)
            count = max(1, int(window.total_seconds() // step.total_seconds()))
            end = _floor_time(now, bucket)
            start = end - step * (count - 1)
            label_format = _bucket_format(bucket)

            existing = {entry["bucket"]: int(entry["count"]) for entry in timeline}
            filled: List[Dict[str, str | int]] = []
            current = start
            for _ in range(count):
                label = current.strftime(label_format)
                filled.append({"bucket": label, "count": existing.get(label, 0)})
                current += step
            return filled

        return {
            "offenses": {
                "total": offense_store.count_all(),
                "last_7d": offense_store.count_since(now - seven_days),
                "last_24h": offense_store.count_since(now - day),
                "last_1h": offense_store.count_since(now - hour),
                "timeline": {
                    "7d": _complete_timeline(
                        offense_store.timeline(seven_days, bucket="day"),
                        seven_days,
                        "day",
                    ),
                    "24h": _complete_timeline(
                        offense_store.timeline(day, bucket="hour"),
                        day,
                        "hour",
                    ),
                    "1h": _complete_timeline(
                        offense_store.timeline(hour, bucket="minute"),
                        hour,
                        "minute",
                    ),
                },
            },
            "blocks": {
                "current": len(block_manager.list()),
                "total": block_manager.count_all(),
                "last_7d": block_manager.count_since(now - seven_days),
                "last_24h": block_manager.count_since(now - day),
                "last_1h": block_manager.count_since(now - hour),
                "timeline": {
                    "7d": _complete_timeline(
                        block_manager.timeline(seven_days, bucket="day"),
                        seven_days,
                        "day",
                    ),
                    "24h": _complete_timeline(
                        block_manager.timeline(day, bucket="hour"),
                        day,
                        "hour",
                    ),
                    "1h": _complete_timeline(
                        block_manager.timeline(hour, bucket="minute"),
                        hour,
                        "minute",
                    ),
                },
            },
        }

    @app.get("/api/stats")
    def stats() -> Dict[str, Dict[str, object]]:
        try:
            return _stats_payload()
        except sqlite3.DatabaseError:
            offense_store.reset()
            block_manager.reset()
            proxytrap_service.reset_stats()
            return _stats_payload()

    @app.post("/api/stats/reset")
    def reset_stats() -> Dict[str, Dict[str, object]]:
        offense_store.reset()
        block_manager.reset()
        proxytrap_service.reset_stats()
        return _stats_payload()

    @app.get("/api/plugins")
    def plugins() -> List[Dict[str, object]]:
        return _serialize_plugins()

    @app.get("/api/plugins/proxytrap/stats")
    def proxytrap_stats() -> Dict[str, object]:
        return proxytrap_service.stats()

    @app.get("/api/plugins/portdetector/stats")
    def portdetector_stats(limit: int = 50) -> Dict[str, object]:
        return portdetector_service.stats(limit=limit)

    @app.get("/api/plugins/portdetector/aliases")
    def list_portdetector_aliases() -> Dict[str, object]:
        gateway = _primary_gateway_or_error()
        try:
            gateway.ensure_ready()
            port_entries = gateway.get_ports()
            alias_names = getattr(gateway, "ports_alias_names", PORT_ALIAS_NAMES)
        except (NotImplementedError, AttributeError):
            raise HTTPException(
                status_code=501,
                detail="El firewall no expone alias de puertos",
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

        return {"ports_aliases": alias_names, "port_entries": port_entries}

    @app.post("/api/plugins/portdetector/aliases/sync")
    def sync_portdetector_aliases() -> Dict[str, object]:
        gateway = _primary_gateway_or_error()
        config = plugin_store.get_port_detector()
        desired_ports = collect_ports_by_protocol(config.rules or [])
        try:
            gateway.ensure_ready()
            for protocol, ports in desired_ports.items():
                gateway.set_ports_alias(protocol, ports)
            port_entries = gateway.get_ports()
            alias_names = getattr(gateway, "ports_alias_names", PORT_ALIAS_NAMES)
        except (NotImplementedError, AttributeError):
            raise HTTPException(
                status_code=501,
                detail="El firewall no expone alias de puertos",
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

        return {
            "ports_aliases": alias_names,
            "port_entries": port_entries,
            "synced": desired_ports,
        }

    @app.put("/api/plugins/proxytrap")
    def update_proxytrap_settings(payload: ProxyTrapInput) -> Dict[str, object]:
        config = ProxyTrapConfig(
            enabled=payload.enabled,
            port=payload.port,
            default_severity=payload.default_severity,
            response_type=payload.response_type,
            custom_html=payload.custom_html,
            trap_hosts=payload.trap_hosts,
            domain_policies=[
                policy.model_dump() for policy in payload.domain_policies
            ],
        )
        try:
            proxytrap_service.apply_config(config)
        except OSError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        plugin_store.update_proxytrap(config)
        return config.__dict__

    @app.put("/api/plugins/portdetector")
    def update_port_detector_settings(payload: PortDetectorInput) -> Dict[str, object]:
        rules = [PortDetectorRule(**rule.model_dump()) for rule in payload.rules]
        config = PortDetectorConfig(
            enabled=payload.enabled,
            default_severity=payload.default_severity,
            rules=rules,
        )
        try:
            portdetector_service.apply_config(config)
        except PortBindingError as exc:
            raise HTTPException(
                status_code=400,
                detail={"message": str(exc), "failed_ports": exc.failed_ports},
            )
        except OSError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        plugin_store.update_port_detector(config)
        return asdict(config)

    @app.put("/api/plugins/mimosanpm")
    def update_mimosanpm_settings(payload: MimosaNpmConfigInput) -> Dict[str, object]:
        current = plugin_store.get_mimosanpm()
        shared_secret = current.shared_secret
        if payload.shared_secret:
            shared_secret = payload.shared_secret
        if payload.rotate_secret or not shared_secret:
            shared_secret = plugin_store.generate_secret()

        config = MimosaNpmConfig(
            enabled=payload.enabled,
            default_severity=payload.default_severity,
            shared_secret=shared_secret,
            alert_fallback=payload.alert_fallback,
            alert_unregistered_domain=payload.alert_unregistered_domain,
            alert_suspicious_path=payload.alert_suspicious_path,
        )
        mimosanpm_service.apply_config(config)
        plugin_store.update_mimosanpm(config)
        return asdict(config)

    @app.post("/api/plugins/mimosanpm/ingest", status_code=202)
    def ingest_mimosanpm(payload: MimosaNpmBatchInput, request: Request) -> Dict[str, object]:
        config = plugin_store.get_mimosanpm()
        if not config.enabled:
            raise HTTPException(
                status_code=503,
                detail="El plugin MimosaNPM está deshabilitado en Mimosa.",
            )

        token = request.headers.get("X-Mimosa-Token")
        if not token or token != config.shared_secret:
            raise HTTPException(status_code=401, detail="Token inválido para MimosaNPM")
        if not payload.alerts:
            raise HTTPException(status_code=400, detail="No se enviaron alertas")

        alerts = [
            MimosaNpmAlert(
                source_ip=entry.source_ip,
                requested_host=entry.host,
                path=entry.path,
                user_agent=entry.user_agent,
                severity=entry.severity,
                status_code=entry.status_code,
                alert_type=entry.alert_type,
                alert_tags=entry.alert_tags,
                log_source=entry.log_source,
            )
            for entry in payload.alerts
        ]
        accepted = mimosanpm_service.ingest(alerts)
        return {"accepted": accepted}

    @app.get("/api/settings/blocking")
    def blocking_settings() -> Dict[str, int]:
        return block_manager.settings()

    @app.put("/api/settings/blocking")
    def update_blocking_settings(payload: BlockingSettingsInput) -> Dict[str, int]:
        block_manager.update_settings(
            default_duration_minutes=payload.default_duration_minutes,
            sync_interval_seconds=payload.sync_interval_seconds,
        )
        return block_manager.settings()

    @app.get("/api/offenses")
    def list_offenses(limit: int = 100) -> List[Dict[str, object]]:
        offenses = offense_store.list_recent(limit)
        serialized = [_serialize_offense(offense) for offense in offenses]

        if not serialized:
            return serialized

        rules = rule_store.list() or [OffenseRule()]
        now = datetime.utcnow()
        latest_created = max(
            (offense.created_at for offense in offenses), default=now
        )
        reference_time = latest_created

        counts_by_ip: Dict[str, Dict[str, int]] = {}
        for offense in offenses:
            ip = offense.source_ip
            counts_by_ip.setdefault(ip, {"total": 0, "last_hour": 0})
            counts_by_ip[ip]["total"] += 1
            if reference_time - offense.created_at <= timedelta(hours=1):
                counts_by_ip[ip]["last_hour"] += 1

        blocks_by_ip: Dict[str, int] = {}
        for ip in counts_by_ip:
            blocks_by_ip[ip] = block_manager.count_for_ip(ip)

        for item, offense in zip(serialized, offenses):
            context = offense.context or {}
            plugin = item.get("plugin") or context.get("plugin") or ""
            event_id = context.get("event_id") or context.get("eventId") or ""
            severity = item.get("severity") or ""
            description = item.get("description") or ""
            description_clean = item.get("description_clean") or description

            counts = counts_by_ip.get(offense.source_ip, {"total": 0, "last_hour": 0})
            total_blocks = blocks_by_ip.get(offense.source_ip, 0)

            status = ""
            warning = False
            for rule in rules:
                if not rule.matches_fields(
                    OffenseEvent(
                        source_ip=offense.source_ip,
                        plugin=plugin,
                        event_id=event_id,
                        severity=severity,
                        description=description,
                    )
                ):
                    if not rule.matches_fields(
                        OffenseEvent(
                            source_ip=offense.source_ip,
                            plugin=plugin,
                            event_id=event_id,
                            severity=severity,
                            description=description_clean,
                        )
                    ):
                        continue

                if rule.passes_thresholds(
                    last_hour=counts["last_hour"],
                    total=counts["total"],
                    total_blocks=total_blocks,
                ):
                    status = "direct"
                    break

                warning = True

            if status == "direct":
                item["escalation_status"] = "direct"
            elif warning:
                item["escalation_status"] = "warning"
            else:
                item["escalation_status"] = ""

        return serialized

    @app.get("/api/offenses/heatmap")
    def offenses_heatmap(limit: int = 300) -> Dict[str, object]:
        profiles = offense_store.list_ip_profiles(limit)
        aggregated: Dict[str, Dict[str, float]] = {}
        total_points = 0

        for profile in profiles:
            point = _parse_geo_point(profile.geo)
            if not point:
                continue
            key = f"{point['lat']:.4f},{point['lon']:.4f}"
            if key not in aggregated:
                aggregated[key] = {
                    "lat": point["lat"],
                    "lon": point["lon"],
                    "count": 0,
                }
            aggregated[key]["count"] += max(int(profile.offenses), 1)
            total_points += 1

        return {
            "points": list(aggregated.values()),
            "total_profiles": len(profiles),
            "points_count": total_points,
        }

    @app.get("/api/offenses/blocks_by_country")
    def blocks_by_country(limit: int = 10, profile_limit: int = 2000) -> Dict[str, object]:
        profiles = offense_store.list_ip_profiles(profile_limit)
        aggregated: Dict[str, Dict[str, object]] = {}

        for profile in profiles:
            if not profile.blocks:
                continue
            meta = _parse_geo_country(profile.geo)
            if not meta:
                continue
            key = meta.get("country_code") or meta.get("country")
            if not key:
                continue
            entry = aggregated.get(key)
            if not entry:
                entry = {
                    "country": meta.get("country") or key,
                    "country_code": meta.get("country_code"),
                    "blocks": 0,
                }
                aggregated[key] = entry
            entry["blocks"] = int(entry["blocks"]) + int(profile.blocks)

        ordered = sorted(aggregated.values(), key=lambda item: item["blocks"], reverse=True)
        return {"countries": ordered[:limit], "total_profiles": len(profiles)}
    @app.post("/api/offenses", status_code=201)
    def create_offense(payload: OffenseInput) -> Dict[str, object]:
        context = payload.context.copy() if payload.context else {}
        if payload.plugin and not context.get("plugin"):
            context["plugin"] = payload.plugin
        if payload.event_id and not context.get("event_id"):
            context["event_id"] = payload.event_id
        offense = offense_store.record(
            **payload.model_dump(exclude={"plugin", "event_id", "context"}),
            context=context or None,
        )
        manager = _rule_manager()
        manager.process_offense(
            OffenseEvent(
                source_ip=payload.source_ip,
                plugin=payload.plugin,
                event_id=payload.event_id,
                severity=payload.severity,
                description=payload.description,
            )
        )
        _cleanup_expired_blocks()
        return _serialize_offense(offense)

    @app.get("/api/rules")
    def list_rules() -> List[Dict[str, object]]:
        return [_serialize_rule(rule) for rule in rule_store.list()]

    @app.post("/api/rules", status_code=201)
    def create_rule(payload: RuleInput) -> Dict[str, object]:
        rule = OffenseRule(**payload.model_dump())
        saved = rule_store.add(rule)
        return _serialize_rule(saved)

    @app.put("/api/rules/{rule_id}")
    def update_rule(rule_id: int, payload: RuleInput) -> Dict[str, object]:
        rule = OffenseRule(**payload.model_dump())
        saved = rule_store.update(rule_id, rule)
        if not saved:
            raise HTTPException(status_code=404, detail="Regla no encontrada")
        return _serialize_rule(saved)

    @app.delete("/api/rules/{rule_id}", status_code=204, response_class=Response)
    def delete_rule(rule_id: int) -> Response:
        rule_store.delete(rule_id)
        return Response(status_code=204)

    @app.get("/api/ips")
    def list_ips(limit: int = 100) -> List[Dict[str, object]]:
        profiles = offense_store.list_ip_profiles(limit)
        return [profile.__dict__ for profile in profiles]

    @app.get("/api/ips/{ip}")
    def ip_details(ip: str) -> Dict[str, object]:
        profile = offense_store.get_ip_profile(ip)
        if not profile:
            raise HTTPException(status_code=404, detail="IP no encontrada")
        offenses = offense_store.list_by_ip(ip, limit=200)
        blocks = block_manager.history_for_ip(ip)
        return {
            "profile": profile.__dict__,
            "offenses": [_serialize_offense(offense) for offense in offenses],
            "blocks": [_serialize_block(block) for block in blocks],
        }

    @app.post("/api/ips/{ip}/refresh")
    def refresh_ip(ip: str) -> Dict[str, object]:
        profile = offense_store.refresh_ip_profile(ip)
        if not profile:
            raise HTTPException(status_code=404, detail="IP no encontrada")
        return profile.__dict__

    @app.get("/api/whitelist")
    def list_whitelist() -> List[Dict[str, object]]:
        entries = offense_store.list_whitelist()
        return [
            {
                "id": entry.id,
                "cidr": entry.cidr,
                "note": entry.note,
                "created_at": entry.created_at.isoformat(),
            }
            for entry in entries
        ]

    @app.post("/api/whitelist", status_code=201)
    def add_whitelist(payload: WhitelistInput) -> Dict[str, object]:
        entry = offense_store.add_whitelist(payload.cidr, payload.note)
        _sync_whitelist_entry(entry.cidr)
        return {
            "id": entry.id,
            "cidr": entry.cidr,
            "note": entry.note,
            "created_at": entry.created_at.isoformat(),
        }

    @app.delete("/api/whitelist/{entry_id}", status_code=204, response_class=Response)
    def delete_whitelist(entry_id: int) -> Response:
        entry = next(
            (item for item in offense_store.list_whitelist() if item.id == entry_id),
            None,
        )
        offense_store.delete_whitelist(entry_id)
        if entry:
            _sync_whitelist_entry(entry.cidr, remove=True)
        return Response(status_code=204)

    @app.get("/api/blocks")
    def list_database_blocks(include_expired: bool = False) -> List[Dict[str, object]]:
        _cleanup_expired_blocks()
        return [_serialize_block(block) for block in block_manager.list(include_expired=include_expired)]

    @app.get("/api/blocks/history")
    def block_history(limit: int = 20) -> List[Dict[str, object]]:
        return block_manager.recent_activity(limit)

    @app.get("/api/firewalls")
    def list_firewalls() -> List[FirewallConfig]:
        return config_store.list()

    @app.post("/api/firewalls", status_code=201)
    def create_firewall(payload: FirewallInput) -> FirewallConfig:
        config = FirewallConfig.new(**payload.model_dump())
        return config_store.add(config)

    @app.put("/api/firewalls/{config_id}")
    def update_firewall(config_id: str, payload: FirewallInput) -> FirewallConfig:
        if not config_store.get(config_id):
            raise HTTPException(status_code=404, detail="Firewall no encontrado")
        updated = FirewallConfig(
            id=config_id,
            **payload.model_dump(),
        )
        config_store.update(config_id, updated)
        gateway_cache.pop(config_id, None)
        return updated

    @app.delete("/api/firewalls/{config_id}", status_code=204, response_class=Response)
    def delete_firewall(config_id: str) -> Response:
        if not config_store.get(config_id):
            raise HTTPException(status_code=404, detail="Firewall no encontrado")
        config_store.delete(config_id)
        gateway_cache.pop(config_id, None)
        return Response(status_code=204)

    @app.get("/api/firewalls/status")
    def firewall_status() -> List[Dict[str, str | bool]]:
        statuses: List[Dict[str, str | bool]] = []
        for config in config_store.list():
            statuses.append(check_firewall_status(config))
        return statuses

    @app.post("/api/firewalls/test")
    def test_firewall(payload: FirewallInput) -> Dict[str, str | bool]:
        temporary_config = FirewallConfig.new(**payload.model_dump())
        return check_firewall_status(temporary_config)

    @app.get("/api/firewalls/{config_id}/block_rule_stats")
    def firewall_block_rule_stats(config_id: str) -> Dict[str, object]:
        _, gateway = _get_firewall(config_id)
        try:
            return gateway.block_rule_stats()
        except NotImplementedError:
            raise HTTPException(status_code=501, detail="Stats no soportadas para este firewall")
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    @app.post("/api/firewalls/{config_id}/flush_states")
    def firewall_flush_states(config_id: str) -> Dict[str, str]:
        _, gateway = _get_firewall(config_id)
        try:
            gateway.flush_states()
        except NotImplementedError:
            raise HTTPException(status_code=501, detail="Flush no soportado para este firewall")
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return {"status": "ok"}

    @app.get("/api/firewalls/{config_id}/rules")
    def list_firewall_rules(config_id: str) -> Dict[str, object]:
        """Lista las reglas de firewall gestionadas por Mimosa."""
        _, gateway = _get_firewall(config_id)
        try:
            rules = gateway.list_firewall_rules()
            return {"rules": rules, "count": len(rules)}
        except NotImplementedError:
            raise HTTPException(
                status_code=501,
                detail="Listado de reglas no soportado para este firewall"
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    @app.get("/api/firewalls/{config_id}/rules/{rule_uuid}")
    def get_firewall_rule(config_id: str, rule_uuid: str) -> Dict[str, object]:
        """Obtiene los detalles de una regla específica."""
        _, gateway = _get_firewall(config_id)
        try:
            rule = gateway.get_firewall_rule(rule_uuid)
            if not rule:
                raise HTTPException(status_code=404, detail="Regla no encontrada")
            return {"rule": rule}
        except NotImplementedError:
            raise HTTPException(
                status_code=501,
                detail="Obtención de reglas no soportado para este firewall"
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    @app.post("/api/firewalls/{config_id}/rules/{rule_uuid}/toggle")
    def toggle_firewall_rule(config_id: str, rule_uuid: str, enabled: bool = True) -> Dict[str, object]:
        """Habilita o deshabilita una regla de firewall."""
        _, gateway = _get_firewall(config_id)
        try:
            success = gateway.toggle_firewall_rule(rule_uuid, enabled)
            if not success:
                raise HTTPException(status_code=400, detail="No se pudo cambiar el estado de la regla")
            return {
                "status": "ok",
                "rule_uuid": rule_uuid,
                "enabled": enabled,
                "message": f"Regla {'habilitada' if enabled else 'deshabilitada'} correctamente"
            }
        except NotImplementedError:
            raise HTTPException(
                status_code=501,
                detail="Toggle de reglas no soportado para este firewall"
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    @app.delete("/api/firewalls/{config_id}/rules/{rule_uuid}")
    def delete_firewall_rule(config_id: str, rule_uuid: str) -> Dict[str, object]:
        """Elimina una regla de firewall."""
        _, gateway = _get_firewall(config_id)
        try:
            success = gateway.delete_firewall_rule(rule_uuid)
            if not success:
                raise HTTPException(status_code=400, detail="No se pudo eliminar la regla")
            return {
                "status": "ok",
                "rule_uuid": rule_uuid,
                "message": "Regla eliminada correctamente"
            }
        except NotImplementedError:
            raise HTTPException(
                status_code=501,
                detail="Eliminación de reglas no soportado para este firewall"
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    @app.get("/api/firewalls/{config_id}/aliases")
    def list_firewall_aliases(config_id: str) -> Dict[str, object]:
        config, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
            desired = [entry.cidr for entry in offense_store.list_whitelist()]
            whitelist_entries = _sync_whitelist_full(gateway, desired)
            block_entries = gateway.list_blocks()
            try:
                blacklist_entries = gateway.list_blacklist()
            except NotImplementedError:
                blacklist_entries = []
            port_entries = gateway.get_ports()
        except NotImplementedError:
            raise HTTPException(
                status_code=501,
                detail="El firewall no expone alias a través de la API",
            )
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

        return {
            "aliases": {
                "temporal": TEMPORAL_ALIAS_NAME,
                "blacklist": BLACKLIST_ALIAS_NAME,
                "whitelist": WHITELIST_ALIAS_NAME,
            },
            "whitelist_entries": whitelist_entries,
            "block_entries": block_entries,
            "blacklist_entries": blacklist_entries,
            "ports_aliases": getattr(
                gateway,
                "ports_alias_names",
                PORT_ALIAS_NAMES,
            ),
            "port_entries": port_entries,
        }

    @app.get("/api/firewalls/{config_id}/blocks")
    def list_firewall_blocks(config_id: str) -> Dict[str, object]:
        config, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
            block_manager.purge_expired(firewall_gateway=gateway)
            sync_info = block_manager.sync_with_firewall(gateway)
            items = gateway.list_blocks()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return {
            "alias": TEMPORAL_ALIAS_NAME,
            "items": items,
            "database": [_serialize_block(block) for block in block_manager.list()],
            "sync": sync_info,
        }

    @app.get("/api/firewalls/{config_id}/blacklist")
    def list_firewall_blacklist(config_id: str) -> Dict[str, object]:
        _, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
            items = gateway.list_blacklist()
        except NotImplementedError:
            raise HTTPException(status_code=501, detail="Blacklist no soportada para este firewall")
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return {"alias": BLACKLIST_ALIAS_NAME, "items": items}

    @app.post("/api/firewalls/{config_id}/blacklist", status_code=201)
    def add_firewall_blacklist(config_id: str, payload: BlacklistInput) -> Dict[str, object]:
        _, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
            gateway.add_to_blacklist(payload.ip, payload.reason or "")
        except NotImplementedError:
            raise HTTPException(status_code=501, detail="Blacklist no soportada para este firewall")
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return {"alias": BLACKLIST_ALIAS_NAME, "ip": payload.ip}

    @app.delete(
        "/api/firewalls/{config_id}/blacklist/{ip}",
        status_code=204,
        response_class=Response,
    )
    def delete_firewall_blacklist(config_id: str, ip: str) -> Response:
        _, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
            gateway.remove_from_blacklist(ip)
        except NotImplementedError:
            raise HTTPException(status_code=501, detail="Blacklist no soportada para este firewall")
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return Response(status_code=204)

    @app.post("/api/firewalls/{config_id}/blocks", status_code=201)
    def add_firewall_block(config_id: str, payload: BlockInput) -> Dict[str, object]:
        config, gateway = _get_firewall(config_id)
        entry = block_manager.add(
            payload.ip,
            payload.reason or "Añadido manualmente",
            payload.duration_minutes,
            sync_with_firewall=payload.sync_with_firewall,
        )
        duration_minutes = None
        if entry.expires_at:
            delta = entry.expires_at - datetime.utcnow()
            duration_minutes = max(int(delta.total_seconds() // 60), 1)
        should_sync = block_manager.should_sync(payload.ip)
        if should_sync:
            try:
                gateway.ensure_ready()
                gateway.block_ip(
                    payload.ip,
                    payload.reason or "",
                    duration_minutes=duration_minutes,
                )
            except httpx.HTTPStatusError as exc:
                block_manager.remove(payload.ip)
                raise HTTPException(status_code=502, detail=str(exc))
        return {
            "alias": TEMPORAL_ALIAS_NAME,
            "ip": payload.ip,
            "reason": payload.reason or "",
            "duration_minutes": duration_minutes,
            "synced_with_firewall": should_sync,
            "sync_with_firewall": payload.sync_with_firewall,
        }

    @app.delete(
        "/api/firewalls/{config_id}/blocks/{ip}",
        status_code=204,
        response_class=Response,
    )
    def delete_firewall_block(config_id: str, ip: str) -> Response:
        _, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
            gateway.unblock_ip(ip)
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        block_manager.remove(ip)
        return Response(status_code=204)

    @app.post("/api/firewalls/{config_id}/setup")
    def setup_firewall(config_id: str) -> Dict[str, str]:
        config, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        except Exception as exc:  # pragma: no cover - errores específicos del cliente
            raise HTTPException(status_code=400, detail=str(exc))
        gateway_cache.pop(config.id, None)
        return {
            "status": "ok",
            "message": f"Alias {TEMPORAL_ALIAS_NAME} y {BLACKLIST_ALIAS_NAME} preparados",
        }

    return app


app = create_app()

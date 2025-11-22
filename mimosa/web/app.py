"""Aplicación FastAPI que sirve el dashboard y el panel de control."""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Literal, Optional

from fastapi import FastAPI, HTTPException, Request
import httpx
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from mimosa.core.api import FirewallGateway
from mimosa.core.blocking import BlockEntry, BlockManager
from mimosa.core.firewall import DummyFirewall
from mimosa.core.offenses import OffenseRecord, OffenseStore
from mimosa.core.rules import OffenseEvent, OffenseRule, OffenseRuleStore, RuleManager
from mimosa.web.config import (
    FirewallConfig,
    FirewallConfigStore,
    build_firewall_gateway,
    check_firewall_status,
)


class FirewallInput(BaseModel):
    """Payload para crear y probar conexiones con firewalls."""

    name: str
    type: Literal["dummy", "pfsense", "opnsense"]
    base_url: str | None = None
    api_key: str | None = None
    api_secret: str | None = None
    alias_name: str = "mimosa_blocklist"
    verify_ssl: bool = True
    timeout: float = 5.0
    apply_changes: bool = True


class BlockInput(BaseModel):
    """Payload para crear o eliminar entradas de bloqueo manual."""

    ip: str
    reason: str | None = None
    duration_minutes: int | None = None


class BlockingSettingsInput(BaseModel):
    """Configuración del gestor de bloqueos."""

    default_duration_minutes: int = 60
    sync_interval_seconds: int = 300


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
) -> FastAPI:
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

    app = FastAPI(title="Mimosa UI", version="0.1.0")
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    )

    offense_store = offense_store or OffenseStore()
    block_manager = block_manager or BlockManager(db_path=offense_store.db_path)
    config_store = config_store or FirewallConfigStore()
    rule_store = rule_store or OffenseRuleStore(db_path=offense_store.db_path)
    gateway_cache: Dict[str, FirewallGateway] = {}

    def _select_gateway() -> FirewallGateway:
        configs = config_store.list()
        if not configs:
            return DummyFirewall()

        primary = configs[0]
        cached = gateway_cache.get(primary.id)
        if cached:
            return cached

        gateway = build_firewall_gateway(primary)
        gateway_cache[primary.id] = gateway
        return gateway

    def _cleanup_expired_blocks() -> None:
        gateway = _select_gateway()
        block_manager.purge_expired(firewall_gateway=gateway)

    def _rule_manager() -> RuleManager:
        return RuleManager(
            offense_store,
            block_manager,
            _select_gateway(),
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

    def _serialize_block(entry: BlockEntry) -> Dict[str, object]:
        return entry.to_dict()

    def _serialize_offense(offense: OffenseRecord) -> Dict[str, object]:
        return {
            "id": offense.id,
            "source_ip": offense.source_ip,
            "description": offense.description,
            "severity": offense.severity,
            "created_at": offense.created_at.isoformat(),
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

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        return templates.TemplateResponse("dashboard.html", {"request": request})

    @app.get("/admin", response_class=HTMLResponse)
    def admin(request: Request):
        return templates.TemplateResponse("admin.html", {"request": request})

    @app.get("/api/stats")
    def stats() -> Dict[str, Dict[str, object]]:
        now = datetime.utcnow()
        seven_days = timedelta(days=7)
        day = timedelta(hours=24)
        hour = timedelta(hours=1)

        return {
            "offenses": {
                "total": offense_store.count_all(),
                "last_7d": offense_store.count_since(now - seven_days),
                "last_24h": offense_store.count_since(now - day),
                "last_1h": offense_store.count_since(now - hour),
                "timeline": {
                    "7d": offense_store.timeline(seven_days, bucket="day"),
                    "24h": offense_store.timeline(day, bucket="hour"),
                    "1h": offense_store.timeline(hour, bucket="minute"),
                },
            },
            "blocks": {
                "current": len(block_manager.list()),
                "timeline": {
                    "7d": block_manager.timeline(seven_days, bucket="day"),
                    "24h": block_manager.timeline(day, bucket="hour"),
                    "1h": block_manager.timeline(hour, bucket="minute"),
                },
            },
        }

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
        return [_serialize_offense(offense) for offense in offenses]

    @app.post("/api/offenses", status_code=201)
    def create_offense(payload: OffenseInput) -> Dict[str, object]:
        offense = offense_store.record(**payload.model_dump())
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

    @app.delete("/api/rules/{rule_id}", status_code=204)
    def delete_rule(rule_id: int) -> None:
        rule_store.delete(rule_id)

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
        return {
            "id": entry.id,
            "cidr": entry.cidr,
            "note": entry.note,
            "created_at": entry.created_at.isoformat(),
        }

    @app.delete("/api/whitelist/{entry_id}", status_code=204)
    def delete_whitelist(entry_id: int) -> None:
        offense_store.delete_whitelist(entry_id)

    @app.get("/api/blocks")
    def list_database_blocks(include_expired: bool = False) -> List[Dict[str, object]]:
        _cleanup_expired_blocks()
        return [_serialize_block(block) for block in block_manager.list(include_expired=include_expired)]

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

    @app.delete("/api/firewalls/{config_id}", status_code=204)
    def delete_firewall(config_id: str) -> None:
        if not config_store.get(config_id):
            raise HTTPException(status_code=404, detail="Firewall no encontrado")
        config_store.delete(config_id)
        gateway_cache.pop(config_id, None)

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
            "alias": config.alias_name,
            "items": items,
            "database": [_serialize_block(block) for block in block_manager.list()],
            "sync": sync_info,
        }

    @app.post("/api/firewalls/{config_id}/blocks", status_code=201)
    def add_firewall_block(config_id: str, payload: BlockInput) -> Dict[str, object]:
        config, gateway = _get_firewall(config_id)
        entry = block_manager.add(
            payload.ip,
            payload.reason or "Añadido manualmente",
            payload.duration_minutes,
        )
        duration_minutes = None
        if entry.expires_at:
            delta = entry.expires_at - datetime.utcnow()
            duration_minutes = max(int(delta.total_seconds() // 60), 1)
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
            "alias": config.alias_name,
            "ip": payload.ip,
            "reason": payload.reason or "",
            "duration_minutes": duration_minutes,
        }

    @app.delete("/api/firewalls/{config_id}/blocks/{ip}", status_code=204)
    def delete_firewall_block(config_id: str, ip: str) -> None:
        _, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
            gateway.unblock_ip(ip)
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        block_manager.remove(ip)

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
        return {"status": "ok", "message": f"Alias {config.alias_name} preparado"}

    return app


app = create_app()

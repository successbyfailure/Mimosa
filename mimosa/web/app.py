"""Aplicación FastAPI que sirve el dashboard y el panel de control."""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from mimosa.core.api import FirewallGateway
from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
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


class BlockInput(BaseModel):
    """Payload para crear o eliminar entradas de bloqueo manual."""

    ip: str
    reason: str | None = None
    duration_minutes: int | None = None


def create_app(
    *,
    offense_store: OffenseStore | None = None,
    block_manager: BlockManager | None = None,
    config_store: FirewallConfigStore | None = None,
) -> FastAPI:
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

    app = FastAPI(title="Mimosa UI", version="0.1.0")
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    )

    offense_store = offense_store or OffenseStore()
    block_manager = block_manager or BlockManager()
    config_store = config_store or FirewallConfigStore()
    gateway_cache: Dict[str, FirewallGateway] = {}

    def _get_firewall(config_id: str) -> tuple[FirewallConfig, FirewallGateway]:
        config = config_store.get(config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Firewall no encontrado")
        gateway = gateway_cache.get(config.id)
        if not gateway:
            gateway = build_firewall_gateway(config)
            gateway_cache[config.id] = gateway
        return config, gateway

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

    @app.get("/api/firewalls")
    def list_firewalls() -> List[FirewallConfig]:
        return config_store.list()

    @app.post("/api/firewalls", status_code=201)
    def create_firewall(payload: FirewallInput) -> FirewallConfig:
        config = FirewallConfig.new(**payload.model_dump())
        return config_store.add(config)

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
        return {"alias": config.alias_name, "items": gateway.list_blocks()}

    @app.post("/api/firewalls/{config_id}/blocks", status_code=201)
    def add_firewall_block(config_id: str, payload: BlockInput) -> Dict[str, object]:
        config, gateway = _get_firewall(config_id)
        gateway.block_ip(
            payload.ip,
            payload.reason or "",
            duration_minutes=payload.duration_minutes,
        )
        block_manager.add(
            payload.ip,
            payload.reason or "Añadido manualmente",
            payload.duration_minutes,
        )
        return {
            "alias": config.alias_name,
            "ip": payload.ip,
            "reason": payload.reason or "",
            "duration_minutes": payload.duration_minutes,
        }

    @app.delete("/api/firewalls/{config_id}/blocks/{ip}", status_code=204)
    def delete_firewall_block(config_id: str, ip: str) -> None:
        _, gateway = _get_firewall(config_id)
        gateway.unblock_ip(ip)
        block_manager.remove(ip)

    return app


app = create_app()

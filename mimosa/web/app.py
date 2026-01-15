"""Aplicación FastAPI que sirve el dashboard y el panel de control."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Literal, Optional

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
import httpx
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

logger = logging.getLogger(__name__)

from mimosa.core.api import FirewallGateway
from mimosa.core.blocking import BlockEntry, BlockManager
from mimosa.core.offenses import IpProfile, OffenseRecord, OffenseStore
from mimosa.core.plugins import (
    MimosaNpmConfig,
    MimosaNpmIgnoreRule,
    MimosaNpmRule,
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
from mimosa.core.telegram_config import TelegramConfigStore
from mimosa.core.repositories.telegram_repository import (
    TelegramUserRepository,
    TelegramInteractionRepository,
)
from mimosa.web.config import (
    FirewallConfig,
    FirewallConfigStore,
    build_firewall_gateway,
    check_firewall_status,
)
from mimosa.web.auth import UserStore


def _load_app_version() -> str:
    """Lee el número de versión desde el archivo compartido de versionado."""

    version_path = Path(__file__).resolve().parents[2] / "version.json"
    try:
        data = json.loads(version_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "0.0.0"

    return str(data.get("version", "0.0.0"))


MIMOSA_LOCATION_KEY = "mimosa_location"


class FirewallInput(BaseModel):
    """Payload para crear y probar conexiones con firewalls."""

    name: str
    type: Literal["opnsense", "pfsense"]
    base_url: str | None = None
    api_key: str | None = None
    api_secret: str | None = None
    enabled: bool = True
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


class MimosaLocationInput(BaseModel):
    """Ubicacion configurable para la UI publica."""

    lat: float
    lon: float


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
    description: str | None = None
    port: int | None = None
    ports: List[int] | None = None
    start: int | None = None
    end: int | None = None


class PortDetectorInput(BaseModel):
    """Configuración expuesta para el plugin Port Detector."""

    enabled: bool = False
    default_severity: str = "medio"
    rules: List[PortDetectorRuleInput] = Field(default_factory=list)


class MimosaNpmRuleInput(BaseModel):
    host: str = "*"
    path: str = "*"
    status: str = "*"
    severity: str = "medio"


class MimosaNpmIgnoreRuleInput(BaseModel):
    host: str = "*"
    path: str = "*"
    status: str = "*"


class MimosaNpmConfigInput(BaseModel):
    """Config pública del agente MimosaNPM."""

    enabled: bool = False
    default_severity: str = "alto"
    rules: List[MimosaNpmRuleInput] = Field(default_factory=list)
    ignore_list: List[MimosaNpmIgnoreRuleInput] = Field(default_factory=list)
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


class UserInput(BaseModel):
    """Entrada para crear un usuario."""

    username: str
    password: str
    role: Literal["admin", "viewer"] = "viewer"


class UserUpdateInput(BaseModel):
    """Entrada para actualizar un usuario."""

    password: Optional[str] = None
    role: Optional[Literal["admin", "viewer"]] = None


class TelegramBotConfigInput(BaseModel):
    """Configuración del bot de Telegram."""

    enabled: bool = False
    bot_token: Optional[str] = None
    welcome_message: str = "Bienvenido al bot de Mimosa"
    unauthorized_message: str = "No estás autorizado para usar este bot"


class TelegramUserAuthInput(BaseModel):
    """Entrada para autorizar/desautorizar usuarios del bot."""

    telegram_id: int
    authorized: bool = True


class LoginInput(BaseModel):
    """Credenciales de acceso para la UI."""

    username: str
    password: str


class GatewayCache:
    """Cache de gateways con TTL para evitar credenciales obsoletas."""

    def __init__(self, ttl_seconds: int = 300):
        self._cache: Dict[str, tuple[FirewallGateway, datetime]] = {}
        self._ttl = timedelta(seconds=ttl_seconds)

    def get(self, key: str) -> Optional[FirewallGateway]:
        """Obtiene un gateway del cache si no ha expirado."""
        if key not in self._cache:
            return None
        gateway, cached_at = self._cache[key]
        if datetime.now(timezone.utc) - cached_at > self._ttl:
            # Entrada expirada, eliminar
            del self._cache[key]
            return None
        return gateway

    def set(self, key: str, gateway: FirewallGateway) -> None:
        """Almacena un gateway en el cache con timestamp actual."""
        self._cache[key] = (gateway, datetime.now(timezone.utc))

    def pop(self, key: str, default=None):
        """Elimina y retorna un gateway del cache."""
        entry = self._cache.pop(key, None)
        return entry[0] if entry else default

    def invalidate_all(self) -> None:
        """Limpia todo el cache."""
        self._cache.clear()


def create_app(
    *,
    offense_store: OffenseStore | None = None,
    block_manager: BlockManager | None = None,
    config_store: FirewallConfigStore | None = None,
    rule_store: OffenseRuleStore | None = None,
    proxytrap_stats_path: Path | str | None = None,
    portdetector_stats_path: Path | str | None = None,
) -> FastAPI:
    app_version = _load_app_version()
    app = FastAPI(title="Mimosa UI", version=app_version)
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    )
    ui_root = Path(__file__).parent / "static" / "ui"

    offense_store = offense_store or OffenseStore()
    block_manager = block_manager or BlockManager(
        db_path=offense_store.db_path, whitelist_checker=offense_store.is_whitelisted
    )
    block_manager.set_whitelist_checker(offense_store.is_whitelisted)
    config_store = config_store or FirewallConfigStore()
    rule_store = rule_store or OffenseRuleStore(db_path=offense_store.db_path)
    plugin_store = PluginConfigStore()
    user_store = UserStore()
    telegram_config_store = TelegramConfigStore(db_path=offense_store.db_path)
    telegram_user_repo = TelegramUserRepository(db_path=offense_store.db_path)
    telegram_interaction_repo = TelegramInteractionRepository(db_path=offense_store.db_path)
    gateway_cache = GatewayCache(ttl_seconds=300)  # TTL de 5 minutos
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

    def _current_user(request: Request) -> Optional[Dict[str, str]]:
        if "session" not in request.scope:
            return None
        return request.session.get("user")

    def _is_public_api(path: str) -> bool:
        return (
            path.startswith("/api/public")
            or path.startswith("/api/auth")
            or path == "/api/plugins/mimosanpm/ingest"
        )

    def _require_admin(request: Request) -> None:
        user = _current_user(request)
        if not user or user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Acceso restringido a administradores")

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            path = request.url.path
            if (path == "/api" or path.startswith("/api/")) and not _is_public_api(path):
                if not _current_user(request):
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Autenticación requerida"},
                    )
            return await call_next(request)

    app.add_middleware(AuthMiddleware)
    session_secret = os.environ.get("MIMOSA_SESSION_SECRET", "mimosa-dev-secret")
    session_max_age = int(os.environ.get("MIMOSA_SESSION_MAX_AGE", "28800"))
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        max_age=session_max_age,
        same_site="lax",
    )

    def _select_gateway() -> FirewallGateway:
        configs = [config for config in config_store.list() if config.enabled]
        if not configs:
            raise RuntimeError("No hay firewalls activos configurados")

        primary = configs[0]
        cached = gateway_cache.get(primary.id)
        if cached:
            return cached

        gateway = build_firewall_gateway(primary)
        gateway_cache.set(primary.id, gateway)
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
        if not config.enabled:
            raise HTTPException(status_code=409, detail="Firewall desactivado")
        gateway = gateway_cache.get(config.id)
        if not gateway:
            gateway = build_firewall_gateway(config)
            gateway_cache.set(config.id, gateway)
        return config, gateway

    def _sync_whitelist_entry(cidr: str, *, remove: bool = False) -> None:
        for config in config_store.list():
            if not config.enabled:
                continue
            gateway = gateway_cache.get(config.id)
            if not gateway:
                gateway = build_firewall_gateway(config)
                gateway_cache.set(config.id, gateway)
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
            except httpx.HTTPError:
                continue

    def _sync_whitelist_full(gateway: FirewallGateway, desired: List[str]) -> List[str]:
        try:
            current = gateway.list_whitelist()
        except NotImplementedError:
            return []
        expanded, had_unresolved = gateway.expand_whitelist_entries(desired)
        desired_set = set(entry for entry in expanded if entry)
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
            if not had_unresolved:
                to_remove.append(entry)

        for entry in missing:
            gateway.add_to_whitelist(entry)
        for entry in to_remove:
            gateway.remove_from_whitelist(entry)

        try:
            return gateway.list_whitelist()
        except NotImplementedError:
            return []

    def _known_plugins() -> set[str]:
        names = {plugin.get("name") for plugin in plugin_store.list()}
        names.update({"blocks", "manual"})
        return {name for name in names if name}

    def _parse_geo_payload(value: str | None) -> Dict[str, object]:
        if not value:
            return {}
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, dict):
            return {}
        return {
            "lat": payload.get("lat"),
            "lon": payload.get("lon"),
            "country": payload.get("country"),
            "country_code": payload.get("country_code"),
        }

    def _extract_reason_counts(raw: str) -> Dict[str, int | None]:
        total = re.search(r"(\d+)\s+ofensas?\s+totales?", raw, re.IGNORECASE)
        hour = re.search(r"(\d+)\s+en\s+1h", raw, re.IGNORECASE)
        blocks = re.search(r"(\d+)\s+bloqueos?\s+previos?", raw, re.IGNORECASE)
        return {
            "offenses_total": int(total.group(1)) if total else None,
            "offenses_1h": int(hour.group(1)) if hour else None,
            "blocks_total": int(blocks.group(1)) if blocks else None,
        }

    def _parse_reason_fields(
        raw: str | None, *, plugin_hint: str | None = None
    ) -> Dict[str, object]:
        if not raw:
            return {
                "reason_text": "",
                "reason_plugin": plugin_hint,
                "reason_counts": {"offenses_total": None, "offenses_1h": None, "blocks_total": None},
            }
        raw = raw.strip()
        counts = _extract_reason_counts(raw)
        base = raw.split(" · ")[0].strip()
        if " - " in base:
            left, right = base.split(" - ", 1)
            if re.search(r"ofensas?|bloqueos?", right, re.IGNORECASE):
                base = left.strip()
        plugin = plugin_hint
        if plugin and base.startswith(f"{plugin}:"):
            base = base[len(plugin) + 1 :].lstrip()
        if not plugin and ":" in base:
            prefix, rest = base.split(":", 1)
            prefix = prefix.strip()
            if prefix and all(ch.isalnum() or ch in "-_." for ch in prefix):
                plugin = prefix
                base = rest.lstrip()
        if not plugin and " " in base:
            first, rest = base.split(" ", 1)
            if first.lower() in _known_plugins():
                plugin = first
                base = rest.strip() or base
        return {"reason_text": base or raw, "reason_plugin": plugin, "reason_counts": counts}

    def _serialize_block(entry: BlockEntry) -> Dict[str, object]:
        payload = entry.to_dict()
        payload.update(_parse_reason_fields(payload.get("reason")))
        return payload

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
        reason_fields = _parse_reason_fields(description, plugin_hint=plugin)
        plugin = plugin or reason_fields.get("reason_plugin")
        profile = offense_store.get_ip_profile(offense.source_ip)
        geo = _parse_geo_payload(profile.geo if profile else None)

        return {
            "id": offense.id,
            "source_ip": offense.source_ip,
            "description": offense.description,
            "description_clean": description_clean,
            "plugin": plugin,
            "reason_text": reason_fields.get("reason_text"),
            "reason_plugin": reason_fields.get("reason_plugin"),
            "reason_counts": reason_fields.get("reason_counts"),
            "severity": offense.severity,
            "created_at": created_at.isoformat(),
            "host": offense.host,
            "path": offense.path,
            "user_agent": offense.user_agent,
            "context": offense.context,
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
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
            "enabled": rule.enabled,
        }

    def _load_setting(key: str) -> Optional[str]:
        try:
            with sqlite3.connect(offense_store.db_path) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key = ? LIMIT 1;",
                    (key,),
                ).fetchone()
        except sqlite3.DatabaseError:
            return None
        return row[0] if row else None

    def _save_setting(key: str, value: str) -> None:
        with sqlite3.connect(offense_store.db_path) as conn:
            conn.execute(
                """
                INSERT INTO settings(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                """,
                (key, value),
            )

    def _get_mimosa_location() -> Optional[Dict[str, float]]:
        raw = _load_setting(MIMOSA_LOCATION_KEY)
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        lat = payload.get("lat")
        lon = payload.get("lon")
        if lat is None or lon is None:
            return None
        try:
            return {"lat": float(lat), "lon": float(lon)}
        except (TypeError, ValueError):
            return None

    def _set_mimosa_location(lat: float, lon: float) -> Dict[str, float]:
        location = {"lat": float(lat), "lon": float(lon)}
        _save_setting(MIMOSA_LOCATION_KEY, json.dumps(location))
        return location

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

    @app.post("/api/auth/login")
    def login(payload: LoginInput, request: Request) -> Dict[str, Dict[str, str]]:
        account = user_store.authenticate(payload.username, payload.password)
        if not account:
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        request.session["user"] = {"username": account.username, "role": account.role}
        return {"user": {"username": account.username, "role": account.role}}

    @app.post("/api/auth/logout", status_code=204)
    def logout(request: Request) -> Response:
        if hasattr(request, "session"):
            request.session.clear()
        return Response(status_code=204)

    @app.get("/api/auth/session")
    def session(request: Request) -> Dict[str, Optional[Dict[str, str]]]:
        return {"user": _current_user(request)}

    @app.get("/api/public/version")
    def public_version() -> Dict[str, str]:
        return {"version": app_version}

    @app.get("/api/users")
    def list_users(request: Request) -> List[Dict[str, str]]:
        _require_admin(request)
        return [
            {
                "username": user.username,
                "role": user.role,
                "created_at": user.created_at,
            }
            for user in user_store.list()
        ]

    @app.post("/api/users", status_code=201)
    def create_user(request: Request, payload: UserInput) -> Dict[str, str]:
        _require_admin(request)
        try:
            account = user_store.add_user(payload.username, payload.password, role=payload.role)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "username": account.username,
            "role": account.role,
            "created_at": account.created_at,
        }

    @app.put("/api/users/{username}")
    def update_user(request: Request, username: str, payload: UserUpdateInput) -> Dict[str, str]:
        _require_admin(request)
        account = user_store.get(username)
        if not account:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        if payload.role and account.role == "admin" and payload.role != "admin":
            admins = [user for user in user_store.list() if user.role == "admin"]
            if len(admins) <= 1:
                raise HTTPException(status_code=400, detail="Debe existir al menos un administrador")
        try:
            updated = user_store.update_user(
                username,
                password=payload.password,
                role=payload.role,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "username": updated.username,
            "role": updated.role,
            "created_at": updated.created_at,
        }

    @app.delete("/api/users/{username}", status_code=204, response_class=Response)
    def delete_user(request: Request, username: str) -> Response:
        _require_admin(request)
        account = user_store.get(username)
        if not account:
            return Response(status_code=204)
        if account.role == "admin":
            admins = [user for user in user_store.list() if user.role == "admin"]
            if len(admins) <= 1:
                raise HTTPException(status_code=400, detail="Debe existir al menos un administrador")
        user_store.delete_user(username)
        return Response(status_code=204)

    # ====== Endpoints del Bot de Telegram ======

    @app.get("/api/telegram/config")
    def get_telegram_config(request: Request) -> Dict[str, object]:
        """Obtiene la configuración del bot de Telegram."""
        _require_admin(request)
        config = telegram_config_store.get_config()
        config_dict = config.to_dict()
        # No enviar el token completo al frontend por seguridad
        if config_dict.get("bot_token"):
            token = str(config_dict["bot_token"])
            if len(token) > 10:
                config_dict["bot_token"] = token[:8] + "..." + token[-8:]
        return config_dict

    @app.put("/api/telegram/config")
    async def update_telegram_config(
        request: Request, payload: TelegramBotConfigInput
    ) -> Dict[str, str]:
        """Actualiza la configuración del bot de Telegram."""
        _require_admin(request)
        from mimosa.core.domain.telegram import TelegramBotConfig

        previous_config = telegram_config_store.get_config()
        new_token = payload.bot_token.strip() if payload.bot_token else None
        if new_token:
            masked_current = None
            if previous_config.bot_token and len(previous_config.bot_token) > 10:
                masked_current = (
                    previous_config.bot_token[:8] + "..." + previous_config.bot_token[-8:]
                )
            if masked_current and new_token == masked_current:
                new_token = previous_config.bot_token

        config = TelegramBotConfig(
            enabled=payload.enabled,
            bot_token=new_token,
            welcome_message=payload.welcome_message,
            unauthorized_message=payload.unauthorized_message,
        )
        telegram_config_store.save_config(config)
        try:
            await _sync_telegram_bot(force_restart=True)
        except Exception as exc:
            telegram_config_store.save_config(previous_config)
            try:
                await _sync_telegram_bot(force_restart=True)
            except Exception:
                logger.exception("No se pudo restaurar el estado anterior del bot de Telegram")
            raise HTTPException(status_code=400, detail=str(exc))
        return {"status": "ok", "message": "Configuración actualizada"}

    @app.post("/api/telegram/toggle")
    async def toggle_telegram_bot(request: Request) -> Dict[str, object]:
        """Activa o desactiva el bot de Telegram (toggle rápido)."""
        _require_admin(request)
        config = telegram_config_store.get_config()
        new_state = not config.enabled
        telegram_config_store.update_setting("enabled", new_state)
        try:
            await _sync_telegram_bot()
        except Exception as exc:
            telegram_config_store.update_setting("enabled", config.enabled)
            try:
                await _sync_telegram_bot()
            except Exception:
                logger.exception("No se pudo restaurar el estado anterior del bot de Telegram")
            raise HTTPException(status_code=400, detail=str(exc))

        status_msg = "habilitado" if new_state else "deshabilitado"
        return {
            "status": "ok",
            "enabled": new_state,
            "message": f"Bot {status_msg}"
        }

    @app.get("/api/telegram/users")
    def list_telegram_users(request: Request) -> Dict[str, List[Dict[str, object]]]:
        """Lista todos los usuarios del bot (autorizados y no autorizados)."""
        _require_admin(request)
        authorized = telegram_user_repo.find_all_authorized()
        unauthorized = telegram_user_repo.find_all_unauthorized(limit=50)

        return {
            "authorized": [user.to_dict() for user in authorized],
            "unauthorized": [user.to_dict() for user in unauthorized],
        }

    @app.post("/api/telegram/users/{telegram_id}/authorize")
    def authorize_telegram_user(request: Request, telegram_id: int) -> Dict[str, str]:
        """Autoriza a un usuario para usar el bot."""
        _require_admin(request)
        user_data = _current_user(request)
        if not user_data:
            raise HTTPException(status_code=401, detail="No autenticado")

        authorized_by = user_data.get("username", "unknown")
        now = datetime.now(timezone.utc)

        # Verificar si el usuario existe
        user = telegram_user_repo.find_by_telegram_id(telegram_id)
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        # Autorizar
        telegram_user_repo.authorize_user(telegram_id, authorized_by, now)
        return {"status": "ok", "message": "Usuario autorizado"}

    @app.post("/api/telegram/users/{telegram_id}/unauthorize")
    def unauthorize_telegram_user(request: Request, telegram_id: int) -> Dict[str, str]:
        """Desautoriza a un usuario del bot."""
        _require_admin(request)

        # Desautorizar
        telegram_user_repo.unauthorize_user(telegram_id)
        return {"status": "ok", "message": "Usuario desautorizado"}

    @app.delete("/api/telegram/users/{telegram_id}", status_code=204, response_class=Response)
    def delete_telegram_user(request: Request, telegram_id: int) -> Response:
        """Elimina un usuario del bot."""
        _require_admin(request)
        telegram_user_repo.delete(telegram_id)
        return Response(status_code=204)

    @app.get("/api/telegram/interactions")
    def list_telegram_interactions(
        request: Request, limit: int = 100
    ) -> List[Dict[str, object]]:
        """Lista las interacciones recientes con el bot."""
        _require_admin(request)
        interactions = telegram_interaction_repo.find_recent(limit=limit)
        return [interaction.to_dict() for interaction in interactions]

    @app.get("/api/telegram/stats")
    def get_telegram_stats(request: Request) -> Dict[str, object]:
        """Obtiene estadísticas del bot de Telegram."""
        _require_admin(request)
        authorized_count = len(telegram_user_repo.find_all_authorized())
        all_users = telegram_user_repo.find_all()
        total_interactions = telegram_interaction_repo.count_total()

        return {
            "authorized_users": authorized_count,
            "total_users": len(all_users),
            "total_interactions": total_interactions,
            "bot_enabled": telegram_config_store.is_enabled(),
        }

    def _stats_payload() -> Dict[str, Dict[str, object]]:
        now = datetime.now(timezone.utc)
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

    @app.websocket("/ws/live")
    async def live_feed(websocket: WebSocket) -> None:
        await websocket.accept()
        session = websocket.scope.get("session") or {}
        if not session.get("user"):
            await websocket.close(code=4401)
            return
        try:
            while True:
                try:
                    stats_payload = _stats_payload()
                except sqlite3.DatabaseError:
                    offense_store.reset()
                    block_manager.reset()
                    proxytrap_service.reset_stats()
                    stats_payload = _stats_payload()
                offenses = [_serialize_offense(item) for item in offense_store.list_recent(10)]
                blocks = block_manager.recent_activity(limit=10)
                await websocket.send_json(
                    {
                        "stats": stats_payload,
                        "offenses": offenses,
                        "blocks": blocks,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                await asyncio.sleep(5)
        except WebSocketDisconnect:
            return

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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
            rules=[MimosaNpmRule(**rule.model_dump()) for rule in payload.rules],
            ignore_list=[
                MimosaNpmIgnoreRule(**rule.model_dump()) for rule in payload.ignore_list
            ],
            shared_secret=shared_secret,
            alert_fallback=payload.alert_fallback,
            alert_unregistered_domain=payload.alert_unregistered_domain,
            alert_suspicious_path=payload.alert_suspicious_path,
        )
        mimosanpm_service.apply_config(config)
        plugin_store.update_mimosanpm(config)
        return asdict(config)

    @app.get("/api/plugins/mimosanpm/events")
    def list_mimosanpm_events(limit: int = 200) -> List[Dict[str, object]]:
        offenses = offense_store.list_recent_by_description_prefix("mimosanpm:", limit)
        return [_serialize_offense(offense) for offense in offenses]

    @app.get("/api/plugins/mimosanpm/stats")
    def mimosanpm_stats(limit: int = 10, sample: int = 500) -> Dict[str, object]:
        offenses = offense_store.list_recent_by_description_prefix(
            "mimosanpm:",
            max(sample, limit),
        )
        domain_counts: Dict[str, int] = {}
        path_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}

        for offense in offenses:
            host = (offense.host or "desconocido").strip().lower()
            if not host:
                host = "desconocido"
            path = (offense.path or "/").strip() or "/"
            status_value = None
            if offense.context and isinstance(offense.context, dict):
                status_value = offense.context.get("status_code")
            status = str(status_value) if status_value is not None else "n/a"

            domain_counts[host] = domain_counts.get(host, 0) + 1
            path_counts[path] = path_counts.get(path, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1

        def top_entries(counts: Dict[str, int], key_name: str) -> List[Dict[str, object]]:
            ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            return [
                {key_name: key, "count": count}
                for key, count in ordered[:limit]
            ]

        return {
            "total": len(offenses),
            "sample": sample,
            "top_domains": top_entries(domain_counts, "domain"),
            "top_paths": top_entries(path_counts, "path"),
            "top_status_codes": top_entries(status_counts, "status"),
        }

    @app.get("/api/dashboard/top_ips")
    def dashboard_top_ips(limit: int = 10) -> List[Dict[str, object]]:
        profiles = offense_store.list_ip_profiles(500)
        scored = []
        for profile in profiles:
            score = int(profile.offenses) + int(profile.blocks) * 3
            scored.append(
                {
                    "ip": profile.ip,
                    "offenses": int(profile.offenses),
                    "blocks": int(profile.blocks),
                    "score": score,
                    "last_seen": profile.last_seen.isoformat(),
                }
            )
        scored.sort(key=lambda item: (item["score"], item["last_seen"]), reverse=True)
        return scored[:limit]

    @app.get("/api/dashboard/feed")
    def dashboard_feed(limit: int = 50, plugin: str | None = None) -> List[Dict[str, object]]:
        offenses = offense_store.list_recent(limit=max(limit, 200))
        serialized = [_serialize_offense(offense) for offense in offenses]
        if plugin:
            normalized = plugin.lower().strip()
            serialized = [
                entry
                for entry in serialized
                if (entry.get("plugin") or "").lower() == normalized
            ]
        return serialized[:limit]

    @app.get("/api/dashboard/blocks/expiring")
    def dashboard_expiring_blocks(
        within_minutes: int = 60, limit: int = 10
    ) -> List[Dict[str, object]]:
        now = datetime.now(timezone.utc)
        entries = []
        for block in block_manager.list():
            if not block.expires_at:
                continue
            delta = block.expires_at - now
            minutes = int(delta.total_seconds() // 60)
            if minutes < 0 or minutes > within_minutes:
                continue
            reason_fields = _parse_reason_fields(block.reason)
            entries.append(
                {
                    "ip": block.ip,
                    "reason": block.reason,
                    "reason_text": reason_fields.get("reason_text"),
                    "reason_plugin": reason_fields.get("reason_plugin"),
                    "reason_counts": reason_fields.get("reason_counts"),
                    "expires_at": block.expires_at.isoformat(),
                    "minutes_left": minutes,
                }
            )
        entries.sort(key=lambda item: item["minutes_left"])
        return entries[:limit]

    @app.get("/api/dashboard/blocks/reasons")
    def dashboard_block_reasons(limit: int = 10) -> List[Dict[str, object]]:
        counts: Dict[str, Dict[str, object]] = {}
        for entry in block_manager.history():
            reason = entry.reason or "sin razón"
            reason_fields = _parse_reason_fields(reason)
            if reason not in counts:
                counts[reason] = {
                    "reason": reason,
                    "reason_text": reason_fields.get("reason_text"),
                    "reason_plugin": reason_fields.get("reason_plugin"),
                    "count": 0,
                    "last_at": entry.created_at,
                }
            counts[reason]["count"] = int(counts[reason]["count"]) + 1
            if entry.created_at > counts[reason]["last_at"]:
                counts[reason]["last_at"] = entry.created_at
        ordered = sorted(counts.values(), key=lambda item: item["count"], reverse=True)
        return [
            {
                "reason": item["reason"],
                "reason_text": item["reason_text"],
                "reason_plugin": item["reason_plugin"],
                "count": item["count"],
                "last_at": item["last_at"].isoformat(),
            }
            for item in ordered[:limit]
        ]

    @app.get("/api/dashboard/health")
    def dashboard_health() -> Dict[str, object]:
        firewalls = []
        for config in config_store.list():
            if not config.enabled:
                firewalls.append(
                    {
                        "id": config.id,
                        "name": config.name,
                        "type": config.type,
                        "available": False,
                        "latency_ms": None,
                        "error": "Desactivado",
                    }
                )
                continue
            try:
                gateway = build_firewall_gateway(config)
                start = datetime.now(timezone.utc)
                gateway.check_connection()
                latency_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
                firewalls.append(
                    {
                        "id": config.id,
                        "name": config.name,
                        "type": config.type,
                        "available": True,
                        "latency_ms": latency_ms,
                        "error": None,
                    }
                )
            except Exception as exc:  # pragma: no cover - depende del firewall
                firewalls.append(
                    {
                        "id": config.id,
                        "name": config.name,
                        "type": config.type,
                        "available": False,
                        "latency_ms": None,
                        "error": str(exc),
                    }
                )

        now = datetime.now(timezone.utc)
        plugin_stats = []
        proxytrap_config = plugin_store.get_proxytrap()
        portdetector_config = plugin_store.get_port_detector()
        mimosanpm_config = plugin_store.get_mimosanpm()
        plugin_stats.append(
            {
                "name": "proxytrap",
                "enabled": proxytrap_config.enabled,
                "last_event_at": offense_store.last_seen_by_description_prefix("proxytrap:") or None,
                "last_24h": offense_store.count_by_description_prefix_since(
                    "proxytrap:", now - timedelta(hours=24)
                ),
            }
        )
        plugin_stats.append(
            {
                "name": "portdetector",
                "enabled": portdetector_config.enabled,
                "last_event_at": offense_store.last_seen_by_description_prefix("portdetector ") or None,
                "last_24h": offense_store.count_by_description_prefix_since(
                    "portdetector ", now - timedelta(hours=24)
                ),
            }
        )
        plugin_stats.append(
            {
                "name": "mimosanpm",
                "enabled": mimosanpm_config.enabled,
                "last_event_at": offense_store.last_seen_by_description_prefix("mimosanpm:") or None,
                "last_24h": offense_store.count_by_description_prefix_since(
                    "mimosanpm:", now - timedelta(hours=24)
                ),
            }
        )

        for item in plugin_stats:
            if item["last_event_at"]:
                item["last_event_at"] = item["last_event_at"].isoformat()

        return {"firewalls": firewalls, "plugins": plugin_stats}

    @app.post("/api/plugins/mimosanpm/ingest", status_code=202)
    def ingest_mimosanpm(payload: MimosaNpmBatchInput, request: Request) -> Dict[str, object]:
        config = plugin_store.get_mimosanpm()
        if not config.enabled:
            raise HTTPException(
                status_code=503,
                detail="El plugin MimosaNPM está deshabilitado en Mimosa.",
            )

        token = request.headers.get("X-Mimosa-Token")
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                token = auth_header[7:]
        token = token.strip() if token else None
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

    @app.get("/api/settings/location")
    def settings_location() -> Dict[str, float | None]:
        location = _get_mimosa_location()
        if not location:
            return {"lat": None, "lon": None}
        return location

    @app.put("/api/settings/location")
    def update_settings_location(payload: MimosaLocationInput) -> Dict[str, float]:
        if not (-90 <= payload.lat <= 90) or not (-180 <= payload.lon <= 180):
            raise HTTPException(status_code=400, detail="Coordenadas fuera de rango")
        return _set_mimosa_location(payload.lat, payload.lon)

    @app.get("/api/offenses")
    def list_offenses(limit: int = 100) -> List[Dict[str, object]]:
        offenses = offense_store.list_recent(limit)
        serialized = [_serialize_offense(offense) for offense in offenses]

        if not serialized:
            return serialized

        rules = rule_store.list() or [OffenseRule()]
        now = datetime.now(timezone.utc)
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

            item["reason_counts"] = {
                "offenses_total": counts["total"],
                "offenses_1h": counts["last_hour"],
                "blocks_total": total_blocks,
            }

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

    def _resolve_blocks_window(window: str) -> tuple[List[BlockEntry], str]:
        normalized = (window or "").lower()
        label = "total"
        if normalized in {"current", "actual", "activos"}:
            label = "current"
            return block_manager.list(), label
        if normalized in {"24h", "24horas"}:
            label = "24h"
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        elif normalized in {"week", "7d", "semana"}:
            label = "week"
            cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        elif normalized in {"month", "30d", "mes"}:
            label = "month"
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        else:
            return block_manager.history(), label
        return [entry for entry in block_manager.history() if entry.created_at >= cutoff], label

    def _resolve_offenses_window(window: str) -> tuple[Dict[str, int], str]:
        normalized = (window or "").lower()
        label = "total"
        since = None
        if normalized in {"24h", "24horas"}:
            label = "24h"
            since = datetime.now(timezone.utc) - timedelta(hours=24)
        elif normalized in {"week", "7d", "semana"}:
            label = "week"
            since = datetime.now(timezone.utc) - timedelta(days=7)
        elif normalized in {"month", "30d", "mes"}:
            label = "month"
            since = datetime.now(timezone.utc) - timedelta(days=30)
        return offense_store.offense_counts_by_ip(since), label

    def _resolve_public_window(window: str) -> tuple[Optional[datetime], str]:
        normalized = (window or "").lower()
        label = "total"
        since = None
        if normalized in {"24h", "24horas"}:
            label = "24h"
            since = datetime.now(timezone.utc) - timedelta(hours=24)
        elif normalized in {"week", "7d", "semana"}:
            label = "week"
            since = datetime.now(timezone.utc) - timedelta(days=7)
        elif normalized in {"month", "30d", "mes"}:
            label = "month"
            since = datetime.now(timezone.utc) - timedelta(days=30)
        return since, label

    @app.get("/api/public/heatmap")
    def public_heatmap(limit: int = 300, window: str = "total") -> Dict[str, object]:
        counts, window_label = _resolve_offenses_window(window)
        aggregated: Dict[str, Dict[str, float]] = {}
        profiles_seen = 0
        total_points = 0
        profile_cache: Dict[str, Optional[IpProfile]] = {}

        for ip, count in counts.items():
            profile = profile_cache.get(ip)
            if profile is None:
                profile = offense_store.get_ip_profile(ip)
                profile_cache[ip] = profile
            if not profile:
                continue
            point = _parse_geo_point(profile.geo)
            if not point:
                continue
            profiles_seen += 1
            key = f"{point['lat']:.4f},{point['lon']:.4f}"
            if key not in aggregated:
                aggregated[key] = {
                    "lat": point["lat"],
                    "lon": point["lon"],
                    "count": 0,
                }
            aggregated[key]["count"] += max(int(count), 1)
            total_points += 1

        points = list(aggregated.values())
        points.sort(key=lambda item: item["count"], reverse=True)
        if limit > 0:
            points = points[:limit]

        return {
            "points": points,
            "total_profiles": profiles_seen,
            "points_count": total_points,
            "window": window_label,
        }

    @app.get("/api/public/offenses_by_country")
    def public_offenses_by_country(limit: int = 10, window: str = "total") -> Dict[str, object]:
        counts, window_label = _resolve_offenses_window(window)
        aggregated: Dict[str, Dict[str, object]] = {}
        name_index: Dict[str, str] = {}
        profile_cache: Dict[str, Optional[IpProfile]] = {}

        for ip, count in counts.items():
            profile = profile_cache.get(ip)
            if profile is None:
                profile = offense_store.get_ip_profile(ip)
                profile_cache[ip] = profile
            if not profile:
                continue
            meta = _parse_geo_country(profile.geo)
            if not meta:
                continue
            country_name = (meta.get("country") or "").strip()
            country_code = meta.get("country_code")
            normalized_name = country_name.lower()
            key = None
            if country_code:
                key = country_code.upper()
            elif normalized_name:
                key = name_index.get(normalized_name)
                if not key:
                    key = f"name:{normalized_name}"
            if not key:
                continue
            existing_key = name_index.get(normalized_name) if normalized_name else None
            if country_code and existing_key and existing_key != key:
                existing_entry = aggregated.pop(existing_key, None)
                if existing_entry:
                    aggregated[key] = existing_entry
            entry = aggregated.get(key)
            if not entry:
                entry = {
                    "country": country_name or country_code or key,
                    "country_code": country_code,
                    "offenses": 0,
                }
                aggregated[key] = entry
                if normalized_name:
                    name_index[normalized_name] = key
            if country_code and not entry.get("country_code"):
                entry["country_code"] = country_code
            entry["offenses"] = int(entry["offenses"]) + int(count)

        ordered = sorted(aggregated.values(), key=lambda item: item["offenses"], reverse=True)
        return {
            "countries": ordered[:limit],
            "total_countries": len(aggregated),
            "total_profiles": len(counts),
            "window": window_label,
        }

    @app.get("/api/public/feed")
    def public_feed(limit: int = 30) -> List[Dict[str, object]]:
        offenses = offense_store.list_recent(limit)
        profile_cache: Dict[str, Optional[IpProfile]] = {}
        payloads: List[Dict[str, object]] = []
        for offense in offenses:
            serialized = _serialize_offense(offense)
            ip = offense.source_ip
            profile = profile_cache.get(ip)
            if profile is None:
                profile = offense_store.get_ip_profile(ip)
                profile_cache[ip] = profile
            country_meta = _parse_geo_country(profile.geo) if profile else None
            point_meta = _parse_geo_point(profile.geo) if profile else None
            serialized["country_code"] = (
                country_meta.get("country_code") if country_meta else None
            )
            serialized["country"] = (
                country_meta.get("country") if country_meta else None
            )
            serialized["lat"] = point_meta.get("lat") if point_meta else None
            serialized["lon"] = point_meta.get("lon") if point_meta else None
            payloads.append(serialized)
        return payloads

    @app.get("/api/public/offense_types")
    def public_offense_types(
        limit: int = 8,
        sample: int = 500,
        window: str = "24h",
    ) -> Dict[str, object]:
        since, window_label = _resolve_public_window(window)
        offenses = offense_store.list_recent(max(sample, limit))
        counts: Dict[str, int] = {}
        total = 0

        for offense in offenses:
            if since and offense.created_at < since:
                continue
            serialized = _serialize_offense(offense)
            plugin = (serialized.get("plugin") or "").strip()
            description = (serialized.get("description_clean") or serialized.get("description") or "").strip()
            context = offense.context if isinstance(offense.context, dict) else {}
            port = context.get("port")
            protocol = context.get("protocol")

            if port:
                type_name = f"port:{port}"
                if protocol:
                    type_name = f"{type_name}/{protocol}"
            elif offense.path:
                type_name = f"path:{offense.path}"
            elif offense.host:
                type_name = f"host:{offense.host}"
            else:
                type_name = description or plugin or "desconocido"
            if plugin and type_name.lower().startswith(plugin.lower()):
                type_name = type_name[len(plugin) :].lstrip(" :-")
                if not type_name:
                    type_name = plugin
            counts[type_name] = counts.get(type_name, 0) + 1
            total += 1

        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        types = [{"type": key, "count": count} for key, count in ordered[:limit]]
        return {
            "types": types,
            "total": total,
            "window": window_label,
            "sample": sample,
        }

    @app.get("/api/public/mimosa_location")
    def public_mimosa_location() -> Dict[str, float | None]:
        location = _get_mimosa_location()
        if not location:
            return {"lat": None, "lon": None}
        return location

    @app.get("/api/offenses/heatmap")
    def offenses_heatmap(limit: int = 300, window: str = "total") -> Dict[str, object]:
        entries, window_label = _resolve_blocks_window(window)
        aggregated: Dict[str, Dict[str, float]] = {}
        ip_counts: Dict[str, int] = {}
        profiles_seen = 0
        total_points = 0
        profile_cache: Dict[str, Optional[IpProfile]] = {}

        if window_label == "current":
            for entry in entries:
                ip_counts[entry.ip] = ip_counts.get(entry.ip, 0) + 1
        else:
            for entry in entries:
                ip_counts[entry.ip] = ip_counts.get(entry.ip, 0) + 1

        for ip, count in ip_counts.items():
            profile = profile_cache.get(ip)
            if profile is None:
                profile = offense_store.get_ip_profile(ip)
                profile_cache[ip] = profile
            if not profile:
                continue
            point = _parse_geo_point(profile.geo)
            if not point:
                continue
            profiles_seen += 1
            key = f"{point['lat']:.4f},{point['lon']:.4f}"
            if key not in aggregated:
                aggregated[key] = {
                    "lat": point["lat"],
                    "lon": point["lon"],
                    "count": 0,
                }
            aggregated[key]["count"] += max(int(count), 1)
            total_points += 1

        points = list(aggregated.values())
        points.sort(key=lambda item: item["count"], reverse=True)
        if limit > 0:
            points = points[:limit]

        return {
            "points": points,
            "total_profiles": profiles_seen,
            "points_count": total_points,
            "window": window_label,
        }

    @app.get("/api/offenses/blocks_by_country")
    def blocks_by_country(limit: int = 10, window: str = "total") -> Dict[str, object]:
        entries, window_label = _resolve_blocks_window(window)
        aggregated: Dict[str, Dict[str, object]] = {}
        name_index: Dict[str, str] = {}
        ip_counts: Dict[str, int] = {}
        profile_cache: Dict[str, Optional[IpProfile]] = {}

        for entry in entries:
            ip_counts[entry.ip] = ip_counts.get(entry.ip, 0) + 1

        for ip, count in ip_counts.items():
            profile = profile_cache.get(ip)
            if profile is None:
                profile = offense_store.get_ip_profile(ip)
                profile_cache[ip] = profile
            if not profile:
                continue
            meta = _parse_geo_country(profile.geo)
            if not meta:
                continue
            country_name = (meta.get("country") or "").strip()
            country_code = meta.get("country_code")
            normalized_name = country_name.lower()
            key = None
            if country_code:
                key = country_code.upper()
            elif normalized_name:
                key = name_index.get(normalized_name)
                if not key:
                    key = f"name:{normalized_name}"
            if not key:
                continue
            existing_key = name_index.get(normalized_name) if normalized_name else None
            if country_code and existing_key and existing_key != key:
                existing_entry = aggregated.pop(existing_key, None)
                if existing_entry:
                    aggregated[key] = existing_entry
            entry = aggregated.get(key)
            if not entry:
                entry = {
                    "country": country_name or country_code or key,
                    "country_code": country_code,
                    "blocks": 0,
                }
                aggregated[key] = entry
                if normalized_name:
                    name_index[normalized_name] = key
            if country_code and not entry.get("country_code"):
                entry["country_code"] = country_code
            entry["blocks"] = int(entry["blocks"]) + int(count)

        ordered = sorted(aggregated.values(), key=lambda item: item["blocks"], reverse=True)
        return {
            "countries": ordered[:limit],
            "total_countries": len(aggregated),
            "total_profiles": len(ip_counts),
            "window": window_label,
        }
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

    @app.post("/api/rules/{rule_id}/toggle")
    def toggle_rule(rule_id: int) -> Dict[str, object]:
        """Activa o desactiva una regla de bloqueo."""
        new_state = rule_store.toggle(rule_id)
        if new_state is False:
            # Verificar si la regla existe
            rules = rule_store.list()
            if not any(r.id == rule_id for r in rules):
                raise HTTPException(status_code=404, detail="Regla no encontrada")
        return {"id": rule_id, "enabled": new_state}

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

    @app.get("/api/dashboard/ip_types")
    def dashboard_ip_types() -> Dict[str, int]:
        """Estadísticas de IPs por tipo (datacenter, residential, etc.)."""
        return offense_store.count_by_ip_type()

    @app.get("/api/dashboard/reaction_time")
    def dashboard_reaction_time(window: Optional[str] = None) -> Dict[str, object]:
        """Estadísticas de tiempo de reacción entre ofensa y bloqueo.

        Args:
            window: Ventana temporal: '24h', '7d' o None para todo.
        """
        return offense_store.get_reaction_time_stats(window=window)

    @app.post("/api/admin/refresh-cloud-ranges")
    def refresh_cloud_ranges() -> Dict[str, object]:
        """Actualiza las listas de rangos de cloud providers."""
        counts = offense_store.refresh_cloud_ranges()
        return {"status": "updated", "counts": counts}

    @app.get("/api/admin/cloud-stats")
    def get_cloud_stats() -> Dict[str, int]:
        """Devuelve estadísticas de los rangos de cloud cargados."""
        return offense_store.get_cloud_stats()

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
        try:
            _sync_whitelist_entry(entry.cidr)
        except RuntimeError as exc:
            offense_store.delete_whitelist(entry.id)
            raise HTTPException(status_code=400, detail=str(exc)) from exc
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
        history = block_manager.recent_activity(limit)
        for entry in history:
            entry.update(_parse_reason_fields(entry.get("reason")))
        return history

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
    def firewall_status() -> List[Dict[str, object]]:
        statuses: List[Dict[str, object]] = []
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
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    @app.post("/api/firewalls/{config_id}/flush_states")
    def firewall_flush_states(config_id: str) -> Dict[str, str]:
        _, gateway = _get_firewall(config_id)
        try:
            gateway.flush_states()
        except NotImplementedError:
            raise HTTPException(status_code=501, detail="Flush no soportado para este firewall")
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
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
            delta = entry.expires_at - datetime.now(timezone.utc)
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
            except httpx.HTTPError as exc:
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
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        block_manager.remove(ip)
        return Response(status_code=204)

    @app.post("/api/firewalls/{config_id}/setup")
    def setup_firewall(config_id: str) -> Dict[str, str]:
        config, gateway = _get_firewall(config_id)
        try:
            gateway.ensure_ready()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        except Exception as exc:  # pragma: no cover - errores específicos del cliente
            raise HTTPException(status_code=400, detail=str(exc))
        gateway_cache.pop(config.id, None)
        return {
            "status": "ok",
            "message": f"Alias {TEMPORAL_ALIAS_NAME} y {BLACKLIST_ALIAS_NAME} preparados",
        }

    @app.get("/{full_path:path}")
    def spa_entry(full_path: str):
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Ruta no encontrada")
        if full_path == "ws" or full_path.startswith("ws/"):
            raise HTTPException(status_code=404, detail="Ruta no encontrada")
        if full_path:
            candidate = ui_root / full_path
            if candidate.is_file():
                return FileResponse(candidate)
        index_path = ui_root / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        raise HTTPException(status_code=404, detail="UI build no encontrado")

    # Inicializar el bot de Telegram
    from mimosa.core.telegram_bot import TelegramBotService

    telegram_bot = TelegramBotService(
        config_store=telegram_config_store,
        user_repo=telegram_user_repo,
        interaction_repo=telegram_interaction_repo,
        offense_store=offense_store,
        block_manager=block_manager,
        rule_store=rule_store,
    )

    async def _sync_telegram_bot(force_restart: bool = False) -> None:
        config = telegram_config_store.get_config()
        if not config.enabled or not config.bot_token:
            if telegram_bot.is_running():
                await telegram_bot.stop()
            return

        if telegram_bot.is_running():
            if force_restart:
                await telegram_bot.stop()
                await telegram_bot.start()
            return

        await telegram_bot.start()

    @app.on_event("startup")
    async def startup_event():
        """Inicia los servicios en segundo plano."""
        try:
            await telegram_bot.start()
        except Exception as e:
            logger.error(f"Error al iniciar el bot de Telegram: {e}")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Detiene los servicios en segundo plano."""
        try:
            await telegram_bot.stop()
        except Exception as e:
            logger.error(f"Error al detener el bot de Telegram: {e}")

    return app


app = create_app()

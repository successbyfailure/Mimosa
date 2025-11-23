"""Integraciones ligeras con proxies reversos externos.

De momento sólo se soporta Nginx Proxy Manager (NPM) usando su API
HTTP. El objetivo principal es registrar entradas que apunten a la IP
de Mimosa para los dominios declarados por ProxyTrap.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import httpx


@dataclass
class ReverseProxyResult:
    """Resultado de una sincronización con el proxy reverso."""

    created: List[str]
    skipped: List[str]
    errors: List[str]


class NginxProxyManagerClient:
    """Cliente mínimo para la API de Nginx Proxy Manager."""

    def __init__(self, base_url: str, token: str) -> None:
        if not base_url:
            raise ValueError("Se requiere base_url para el proxy reverso")
        if not token:
            raise ValueError("Se requiere api_token para el proxy reverso")
        sanitized = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=sanitized,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )

    def list_hosts(self) -> List[Dict[str, object]]:
        response = self._client.get("/api/nginx/proxy-hosts")
        response.raise_for_status()
        data = response.json()
        items = data.get("data") if isinstance(data, dict) else None
        if not items and isinstance(data, list):
            items = data
        if not isinstance(items, list):
            return []
        hosts: List[Dict[str, object]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            hosts.append(
                {
                    "id": item.get("id"),
                    "domain_names": item.get("domain_names", []),
                    "forward_ip": (item.get("forward_host") or ""),
                    "forward_port": item.get("forward_port"),
                }
            )
        return hosts

    def create_host(
        self,
        hostname: str,
        *,
        forward_ip: str,
        forward_port: int,
        forward_scheme: str = "http",
    ) -> None:
        payload = {
            "domain_names": [hostname],
            "forward_host": forward_ip,
            "forward_port": forward_port,
            "forward_scheme": forward_scheme,
            "access_list_id": 0,
            "ssl_forced": False,
            "caching_enabled": False,
            "block_exploits": True,
            "http2_support": True,
            "allow_websocket_upgrade": True,
        }
        response = self._client.post("/api/nginx/proxy-hosts", json=payload)
        response.raise_for_status()


class ReverseProxyManager:
    """Orquesta la creación de entradas en el proxy reverso."""

    def __init__(self) -> None:
        self._clients: Dict[str, NginxProxyManagerClient] = {}

    def _npm_client(self, base_url: str, token: str) -> NginxProxyManagerClient:
        cache_key = f"{base_url}|{token}"
        cached = self._clients.get(cache_key)
        if cached:
            return cached
        client = NginxProxyManagerClient(base_url, token)
        self._clients[cache_key] = client
        return client

    def sync_hosts(
        self,
        *,
        provider: str,
        api_url: str,
        api_token: str,
        forward_ip: str,
        forward_port: int,
        hostnames: List[str],
        forward_scheme: str = "http",
    ) -> ReverseProxyResult:
        if not hostnames:
            return ReverseProxyResult(created=[], skipped=[], errors=[])
        if provider != "npm":
            raise NotImplementedError(f"Proveedor de proxy no soportado: {provider}")

        client = self._npm_client(api_url, api_token)
        existing = client.list_hosts()
        created: List[str] = []
        skipped: List[str] = []
        errors: List[str] = []

        known = {
            domain: entry
            for entry in existing
            for domain in entry.get("domain_names", []) or []
        }

        for hostname in hostnames:
            if hostname in known:
                skipped.append(hostname)
                continue
            try:
                client.create_host(
                    hostname,
                    forward_ip=forward_ip,
                    forward_port=forward_port,
                    forward_scheme=forward_scheme,
                )
                created.append(hostname)
            except httpx.HTTPError as exc:  # pragma: no cover - dependiente del proxy
                errors.append(f"{hostname}: {exc}")

        return ReverseProxyResult(created=created, skipped=skipped, errors=errors)


__all__ = ["ReverseProxyManager", "ReverseProxyResult"]

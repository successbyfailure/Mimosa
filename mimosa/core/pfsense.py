"""Cliente mínimo para integrar pfSense/OPNsense como firewall remoto.

Proporciona métodos para añadir o eliminar direcciones en una tabla
(Alias) y consultar su contenido usando la API REST. Opcionalmente
permite programar una eliminación automática en una duración dada.
"""
from __future__ import annotations

import threading
from datetime import timedelta
from typing import Dict, List, Optional

import httpx
from mimosa.core.api import FirewallGateway


class _BaseSenseClient(FirewallGateway):
    """Base compartida para clientes de pfSense y OPNsense.

    Gestiona la autenticación HTTP básica, el temporizador de expiración
    opcional y delega en cada implementación concreta los endpoints a
    invocar.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        alias_name: str = "mimosa_blocklist",
        *,
        verify_ssl: bool = True,
        timeout: float = 10.0,
        client: Optional[httpx.Client] = None,
        apply_changes: bool = True,
    ) -> None:
        sanitized_url = base_url.rstrip("/")
        self.base_url = sanitized_url
        self.alias_name = alias_name
        self._client = client or self._build_client(
            sanitized_url, api_key, api_secret, verify_ssl, timeout
        )
        self._lock = threading.Lock()
        self._timers: Dict[str, threading.Timer] = {}
        self._apply_changes = apply_changes

    def block_ip(
        self, ip: str, reason: str = "", duration_minutes: Optional[int] = None
    ) -> None:
        """Añade una IP al alias configurado.

        Si ``duration_minutes`` es mayor que cero se programa una tarea
        para eliminar automáticamente la IP tras el periodo indicado
        usando :func:`unblock_ip`.
        """

        self._block_ip_backend(ip, reason)
        self._apply_changes_if_enabled()
        if duration_minutes and duration_minutes > 0:
            self._schedule_unblock(ip, minutes=duration_minutes)

    def unblock_ip(self, ip: str) -> None:
        """Elimina una IP del alias configurado."""

        self._unblock_ip_backend(ip)
        self._apply_changes_if_enabled()
        with self._lock:
            timer = self._timers.pop(ip, None)
        if timer:
            timer.cancel()

    def list_table(self) -> List[str]:
        """Devuelve el contenido actual del alias configurado."""

        return self._list_table_backend()

    def list_blocks(self) -> List[str]:
        """Compatibilidad con la interfaz :class:`FirewallGateway`."""

        return self.list_table()

    @property
    def _status_endpoint(self) -> str:
        """Endpoint usado para validar la conectividad del cliente."""

        raise NotImplementedError

    def check_connection(self) -> None:
        """Comprueba conectividad sin depender de un alias existente."""

        self._request("GET", self._status_endpoint)

    def ensure_ready(self) -> None:
        """Intenta garantizar que el alias de bloqueos exista antes de usarlo."""

        created = self._ensure_alias_exists()
        if created:
            self._apply_changes_if_enabled()

    def _schedule_unblock(self, ip: str, *, minutes: int) -> None:
        delay = timedelta(minutes=minutes).total_seconds()
        timer = threading.Timer(delay, lambda: self.unblock_ip(ip))
        with self._lock:
            existing = self._timers.pop(ip, None)
            if existing:
                existing.cancel()
            self._timers[ip] = timer
        timer.daemon = True
        timer.start()

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self.base_url}{path}"
        response = self._client.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def _build_client(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool,
        timeout: float,
    ) -> httpx.Client:
        raise NotImplementedError

    def _block_ip_backend(self, ip: str, reason: str) -> None:
        raise NotImplementedError

    def _unblock_ip_backend(self, ip: str) -> None:
        raise NotImplementedError

    def _list_table_backend(self) -> List[str]:
        raise NotImplementedError

    def _ensure_alias_exists(self) -> bool:
        """Crea el alias de bloqueos si la plataforma lo soporta.

        Devuelve ``True`` si se ha solicitado la creación del alias
        (permitiendo lanzar un reload del firewall) o ``False`` si ya
        existía.
        """

        raise NotImplementedError

    @property
    def _apply_endpoint(self) -> str:
        """Endpoint para aplicar/reload cambios en el firewall."""

        raise NotImplementedError

    def _apply_changes_if_enabled(self) -> None:
        if not self._apply_changes:
            return
        self._request("POST", self._apply_endpoint)


class OPNsenseClient(_BaseSenseClient):
    """Cliente HTTP para OPNsense.

    Utiliza los endpoints documentados en
    https://docs.opnsense.org/development/api.html bajo
    ``/api/firewall/alias_util`` y autenticación básica con el API key y
    secret proporcionados por OPNsense.
    """

    def _build_client(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool,
        timeout: float,
    ) -> httpx.Client:
        return httpx.Client(
            base_url=base_url,
            auth=(api_key, api_secret),
            verify=verify_ssl,
            timeout=timeout,
        )

    def _block_ip_backend(self, ip: str, reason: str) -> None:
        self._request(
            "POST",
            f"/api/firewall/alias_util/add/{self.alias_name}/{ip}",
            json={"description": reason} if reason else None,
        )

    def _unblock_ip_backend(self, ip: str) -> None:
        self._request("POST", f"/api/firewall/alias_util/remove/{self.alias_name}/{ip}")

    def _list_table_backend(self) -> List[str]:
        try:
            response = self._request(
                "GET", f"/api/firewall/alias_util/list/{self.alias_name}"
            )
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                created = self._ensure_alias_exists()
                if created:
                    self._apply_changes_if_enabled()
                response = self._request(
                    "GET", f"/api/firewall/alias_util/list/{self.alias_name}"
                )
            else:
                raise
        data = response.json()
        if isinstance(data, dict) and "items" in data:
            return [entry.get("address", "") for entry in data.get("items", [])]
        if isinstance(data, list):
            return data
        return []

    def _ensure_alias_exists(self) -> bool:
        try:
            self._request("GET", f"/api/firewall/alias_util/list/{self.alias_name}")
            return False
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code != 404:
                raise

        payload = {
            "alias": {
                "name": self.alias_name,
                "type": "network",
                "content": "",
                "description": "Mimosa blocklist",
                "enabled": "1",
            }
        }

        try:
            # API moderna (24.7+) documentada en
            # https://docs.opnsense.org/development/api/core/firewall.html
            self._request("POST", "/api/firewall/alias/addItem", json=payload)
            return True
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code != 404:
                raise

        # Compatibilidad con instalaciones antiguas donde alias_util sigue
        # siendo el punto de entrada para crear alias vacíos.
        legacy_payload = {
            "name": self.alias_name,
            "type": "network",
            "content": "",
            "description": "Mimosa blocklist",
            "enabled": "1",
        }

        self._request("POST", "/api/firewall/alias_util/add", json=legacy_payload)

        # Si el alias aún no existe, es posible que el listado falle por un 404
        # inicial. Reintentamos tras haber solicitado la creación.
        self._request("GET", f"/api/firewall/alias_util/list/{self.alias_name}")
        return True

    @property
    def _status_endpoint(self) -> str:
        return "/api/core/firmware/info"

    @property
    def _apply_endpoint(self) -> str:
        return "/api/firewall/filter/apply"


class PFSenseClient(_BaseSenseClient):
    """Cliente HTTP para pfSense usando la API pfRest.

    pfRest expone endpoints bajo ``/api/v1`` para gestionar alias.
    Requiere un API key y secret configurados en el paquete pfRest,
    enviados como cabeceras ``X-API-KEY`` y ``X-API-SECRET``.
    """

    def _build_client(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool,
        timeout: float,
    ) -> httpx.Client:
        return httpx.Client(
            base_url=base_url,
            headers={"X-API-KEY": api_key, "X-API-SECRET": api_secret},
            verify=verify_ssl,
            timeout=timeout,
        )

    def _block_ip_backend(self, ip: str, reason: str) -> None:
        payload = {"address": ip, "descr": reason or ""}
        self._request(
            "POST", f"/api/v1/firewall/alias/{self.alias_name}/address", json=payload
        )

    def _unblock_ip_backend(self, ip: str) -> None:
        self._request(
            "DELETE", f"/api/v1/firewall/alias/{self.alias_name}/address/{ip}"
        )

    def _list_table_backend(self) -> List[str]:
        try:
            response = self._request("GET", f"/api/v1/firewall/alias/{self.alias_name}")
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                created = self._ensure_alias_exists()
                if created:
                    self._apply_changes_if_enabled()
                response = self._request("GET", f"/api/v1/firewall/alias/{self.alias_name}")
            else:
                raise
        data = response.json()
        if isinstance(data, dict):
            for key in ("addresses", "items", "data"):
                if key in data and isinstance(data[key], list):
                    return [entry.get("address", entry) for entry in data[key]]
        if isinstance(data, list):
            return [item.get("address", item) if isinstance(item, dict) else item for item in data]
        return []

    def _ensure_alias_exists(self) -> bool:
        try:
            self._request("GET", f"/api/v1/firewall/alias/{self.alias_name}")
            return False
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code != 404:
                raise

        payload = {
            "name": self.alias_name,
            "type": "host",
            "descr": "Mimosa blocklist",
            "addresses": [],
        }
        self._request("POST", "/api/v1/firewall/alias", json=payload)
        return True

    @property
    def _status_endpoint(self) -> str:
        return "/api/v1/status/system"

    @property
    def _apply_endpoint(self) -> str:
        return "/api/v1/diagnostics/filter/reload"

    def check_connection(self) -> None:
        """Comprueba conectividad y detecta credenciales inválidas."""

        try:
            super().check_connection()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise PermissionError(
                    "Las credenciales de pfRest no son válidas o carecen de permisos"
                ) from exc
            raise

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


class PFSenseClient(FirewallGateway):
    """Cliente HTTP contra la API de pfSense/OPNsense.

    El cliente asume la existencia de un alias (tabla) en el firewall y
    utiliza las rutas REST estándar de OPNsense/pfSense para gestión de
    alias (`/api/firewall/alias_util`). El API key y secret se usan como
    autenticación básica, tal y como documenta OPNsense.

    Parameters
    ----------
    base_url:
        URL base de la API (por ejemplo, ``https://firewall.local``). No
        debe incluir el sufijo ``/api``.
    api_key:
        Token de API (usuario) proporcionado por pfSense/OPNsense.
    api_secret:
        Secreto asociado al API key.
    alias_name:
        Nombre del alias/tabla que se actualizará (por defecto
        ``mimosa_blocklist``).
    verify_ssl:
        Si se debe verificar el certificado TLS del firewall.
    timeout:
        Timeout para cada petición HTTP, en segundos.
    client:
        Instancia de ``httpx.Client`` ya configurada. Si se omite se crea
        una por defecto.
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
    ) -> None:
        sanitized_url = base_url.rstrip("/")
        self.base_url = sanitized_url
        self.alias_name = alias_name
        self._client = client or httpx.Client(
            base_url=sanitized_url,
            auth=(api_key, api_secret),
            verify=verify_ssl,
            timeout=timeout,
        )
        self._lock = threading.Lock()
        self._timers: Dict[str, threading.Timer] = {}

    def block_ip(
        self, ip: str, reason: str = "", duration_minutes: Optional[int] = None
    ) -> None:
        """Añade una IP al alias configurado.

        Si ``duration_minutes`` es mayor que cero se programa una tarea
        para eliminar automáticamente la IP tras el periodo indicado
        usando :func:`unblock_ip`.
        """

        self._request(
            "POST",
            f"/api/firewall/alias_util/add/{self.alias_name}/{ip}",
            json={"description": reason} if reason else None,
        )
        if duration_minutes and duration_minutes > 0:
            self._schedule_unblock(ip, minutes=duration_minutes)

    def unblock_ip(self, ip: str) -> None:
        """Elimina una IP del alias configurado."""

        self._request("POST", f"/api/firewall/alias_util/remove/{self.alias_name}/{ip}")
        with self._lock:
            timer = self._timers.pop(ip, None)
        if timer:
            timer.cancel()

    def list_table(self) -> List[str]:
        """Devuelve el contenido actual del alias configurado."""

        response = self._request(
            "GET", f"/api/firewall/alias_util/list/{self.alias_name}"
        )
        data = response.json()
        if isinstance(data, dict) and "items" in data:
            return [entry.get("address", "") for entry in data.get("items", [])]
        if isinstance(data, list):
            return data
        return []

    def list_blocks(self) -> List[str]:
        """Compatibilidad con la interfaz :class:`FirewallGateway`."""

        return self.list_table()

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

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

    def ensure_port_forwards(
        self,
        *,
        target_ip: str,
        ports: List[int],
        protocol: str = "tcp",
        description: str | None = None,
        interface: str = "wan",
    ) -> Dict[str, object]:
        normalized_ports = sorted({int(port) for port in ports if port})
        existing = self.list_services()
        conflicts: List[Dict[str, object]] = []
        already_present: List[int] = []
        created: List[int] = []
        for port in normalized_ports:
            match = next(
                (svc for svc in existing if svc.get("port") == port and svc.get("protocol") == protocol),
                None,
            )
            if match and match.get("target") == target_ip:
                already_present.append(port)
                continue
            if match and match.get("target") != target_ip:
                conflicts.append(match)
                continue
            self._create_port_forward(
                port=port,
                protocol=protocol,
                target_ip=target_ip,
                description=description,
                interface=interface,
            )
            created.append(port)
        if created:
            self._apply_changes_if_enabled()
        return {"created": created, "conflicts": conflicts, "already_present": already_present}

    def list_services(self) -> List[Dict[str, object]]:
        return self._list_port_forwards()

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

    def _list_port_forwards(self) -> List[Dict[str, object]]:
        """Devuelve las reglas de NAT/port-forward conocidas."""

        raise NotImplementedError

    def _create_port_forward(
        self,
        *,
        port: int,
        protocol: str,
        target_ip: str,
        description: str | None,
        interface: str,
    ) -> None:
        """Crea una regla de NAT que apunte a Mimosa."""

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
        response = self._request(
            "POST",
            f"/api/firewall/alias_util/add/{self.alias_name}",
            json={"address": ip, "description": reason} if reason else {"address": ip},
        )
        data = response.json()
        if isinstance(data, dict) and data.get("status") not in {"done", "ok", None}:
            raise RuntimeError(f"No se pudo añadir la IP al alias: {data}")

    def _unblock_ip_backend(self, ip: str) -> None:
        try:
            response = self._request(
                "POST",
                f"/api/firewall/alias_util/delete/{self.alias_name}",
                json={"address": ip},
            )
            data = response.json()
            if isinstance(data, dict) and data.get("status") not in {"done", "ok", None}:
                raise RuntimeError(f"No se pudo eliminar la IP del alias: {data}")
            return
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code != 404:
                raise

        current = self._list_table_backend()
        if ip not in current:
            return

        remaining = [address for address in current if address != ip]
        self._request("POST", f"/api/firewall/alias_util/flush/{self.alias_name}")

        for address in remaining:
            self._request(
                "POST",
                f"/api/firewall/alias_util/add/{self.alias_name}",
                json={"address": address},
            )

    def block_rule_stats(self, *, interface: str = "wan") -> Dict[str, object]:
        response = self._request(
            "GET",
            "/api/firewall/filter/search_rule",
            params={"interface": interface, "show_all": "1"},
        )
        data = response.json()
        rows = data.get("rows", []) if isinstance(data, dict) else []
        matches: List[Dict[str, object]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            haystack = " ".join(
                str(value) for value in row.values() if value is not None
            )
            if self.alias_name in haystack:
                matches.append(row)

        if not matches:
            return {"supported": True, "matches": 0, "states": 0, "rule": None, "uuid": None}

        best = max(matches, key=lambda item: int(item.get("states") or 0))
        return {
            "supported": True,
            "matches": len(matches),
            "states": int(best.get("states") or 0),
            "rule": best.get("descr") or best.get("tracker") or best.get("uuid"),
            "uuid": best.get("uuid") or best.get("tracker"),
        }

    def _list_port_forwards(self) -> List[Dict[str, object]]:
        response = self._request("GET", "/api/firewall/nat/searchNAT")
        data = response.json()
        rows = data.get("rows", []) if isinstance(data, dict) else []
        services: List[Dict[str, object]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            raw_port = (
                row.get("dstbeginport")
                or row.get("destination_port")
                or row.get("destination_port_start")
                or row.get("dstport")
            )
            if not raw_port:
                continue
            try:
                port = int(str(raw_port).split(":")[0])
            except ValueError:
                continue
            services.append(
                {
                    "id": row.get("uuid") or row.get("tracker") or row.get("id"),
                    "description": row.get("descr") or row.get("description"),
                    "port": port,
                    "protocol": (row.get("protocol") or row.get("proto") or "tcp").lower(),
                    "target": row.get("target")
                    or row.get("natip")
                    or row.get("redirect_targetip"),
                }
            )
        return services

    def _create_port_forward(
        self,
        *,
        port: int,
        protocol: str,
        target_ip: str,
        description: str | None,
        interface: str,
    ) -> None:
        payload = {
            "nat": {
                "interface": interface,
                "proto": protocol,
                "src": {"any": "1"},
                "dst": {"any": "1", "port": str(port)},
                "redirect_targetip": target_ip,
                "redirect_targetport": str(port),
                "descr": description or f"Mimosa {protocol}:{port}",
                "natreflection": "enable",
                "top": "yes",
            }
        }
        try:
            self._request("POST", "/api/firewall/nat/addNAT", json=payload)
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                self._request("POST", "/api/firewall/nat/addPortForward", json=payload)
            else:
                raise

    def flush_states(self) -> Dict[str, object]:
        response = self._request("POST", "/api/core/diagnostics/flushState")
        payload = response.json()
        return payload if isinstance(payload, dict) else {"status": "ok"}

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
        if isinstance(data, dict):
            if "rows" in data:
                return [entry.get("ip", "") for entry in data.get("rows", [])]
            if "items" in data:
                return [entry.get("address", "") for entry in data.get("items", [])]
        if isinstance(data, list):
            return data
        return []

    def _ensure_alias_exists(self) -> bool:
        try:
            response = self._request("GET", "/api/firewall/alias/searchItem")
            data = response.json()
            rows = data.get("rows", []) if isinstance(data, dict) else []
            if any(row.get("name") == self.alias_name for row in rows):
                return False
        except httpx.HTTPStatusError:
            pass

        payload = {
            "alias": {
                "name": self.alias_name,
                "type": "host",
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

    def _list_port_forwards(self) -> List[Dict[str, object]]:
        response = self._request("GET", "/api/v1/firewall/nat/port_forward")
        data = response.json()
        items = data.get("data") if isinstance(data, dict) else data
        if not isinstance(items, list):
            return []
        services: List[Dict[str, object]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_port = item.get("destination_port") or item.get("dstport")
            try:
                port = int(str(raw_port).split(":")[0]) if raw_port else None
            except ValueError:
                port = None
            if not port:
                continue
            services.append(
                {
                    "id": item.get("tracker") or item.get("id"),
                    "description": item.get("descr") or item.get("description"),
                    "port": port,
                    "protocol": (item.get("protocol") or item.get("proto") or "tcp").lower(),
                    "target": item.get("target")
                    or item.get("local-port")
                    or item.get("redirect_targetip"),
                }
            )
        return services

    def _create_port_forward(
        self,
        *,
        port: int,
        protocol: str,
        target_ip: str,
        description: str | None,
        interface: str,
    ) -> None:
        payload = {
            "interface": interface,
            "protocol": protocol,
            "source": {"address": "any"},
            "destination": {"address": "any", "port": str(port)},
            "target": target_ip,
            "local-port": str(port),
            "description": description or f"Mimosa {protocol}:{port}",
            "natreflection": "enable",
        }
        self._request("POST", "/api/v1/firewall/nat/port_forward", json=payload)

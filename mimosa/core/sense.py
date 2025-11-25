"""Cliente mínimo para integrar pfSense/OPNsense como firewall remoto.

Proporciona métodos para añadir o eliminar direcciones en una tabla
(Alias) y consultar su contenido usando la API REST.
"""
from __future__ import annotations

from typing import Dict, List, Optional

import httpx
from mimosa.core.api import FirewallGateway

TEMPORAL_ALIAS_NAME = "mimosa_temporal_list"
BLACKLIST_ALIAS_NAME = "mimosa_blacklist"
PORT_ALIAS_NAMES = {"tcp": "mimosa_ports_tcp", "udp": "mimosa_ports_udp"}


class _BaseSenseClient(FirewallGateway):
    """Base compartida para clientes de pfSense y OPNsense.

    Gestiona la autenticación HTTP básica y delega en cada
    implementación concreta los endpoints a invocar.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        *,
        verify_ssl: bool = True,
        timeout: float = 10.0,
        client: Optional[httpx.Client] = None,
        apply_changes: bool = True,
    ) -> None:
        sanitized_url = base_url.rstrip("/")
        self.base_url = sanitized_url
        # Alias fijos gestionados por Mimosa
        self.alias_name = TEMPORAL_ALIAS_NAME
        self.temporal_alias = TEMPORAL_ALIAS_NAME
        self.blacklist_alias = BLACKLIST_ALIAS_NAME
        self.ports_alias_names = dict(PORT_ALIAS_NAMES)
        self._client = client or self._build_client(
            sanitized_url, api_key, api_secret, verify_ssl, timeout
        )
        self._apply_changes = apply_changes

    def _ports_alias_name_for(self, protocol: str) -> str:
        normalized = (protocol or "tcp").lower()
        return self.ports_alias_names.get(normalized, self.ports_alias_names["tcp"])

    def block_ip(
        self, ip: str, reason: str = "", duration_minutes: Optional[int] = None
    ) -> None:
        """Añade una IP al alias configurado.

        La duración se gestiona en capas superiores; este cliente solo
        comunica el bloqueo al firewall remoto y aplica los cambios
        necesarios.
        """

        self._block_ip_backend(ip, reason, alias_name=self.temporal_alias)
        self._apply_changes_if_enabled()

    def unblock_ip(self, ip: str) -> None:
        """Elimina una IP del alias configurado."""

        self._unblock_ip_backend(ip, alias_name=self.temporal_alias)
        self._apply_changes_if_enabled()

    def list_table(self) -> List[str]:
        """Devuelve el contenido actual del alias configurado."""

        return self._list_table_backend()

    def list_blocks(self) -> List[str]:
        """Compatibilidad con la interfaz :class:`FirewallGateway`."""

        return self.list_table()

    def apply_changes(self) -> None:
        """Aplica/reload los cambios pendientes en el firewall remoto."""

        self._request("POST", self._apply_endpoint)

    def get_status(self) -> Dict[str, object]:
        """Comprueba conectividad y prepara alias requeridos.

        Devuelve un diccionario con detalles de disponibilidad y si se han
        preparado recursos (alias) durante la llamada.
        """

        status: Dict[str, object] = {
            "available": False,
            "alias_ready": False,
            "alias_created": False,
            "applied_changes": False,
        }

        self.check_connection()
        status["available"] = True

        temporal_created = self._ensure_alias_exists(
            self.temporal_alias, "Mimosa temporal blocks"
        )
        blacklist_created = self._ensure_alias_exists(
            self.blacklist_alias, "Mimosa blacklist"
        )
        status["alias_ready"] = True
        status["alias_created"] = temporal_created or blacklist_created
        status["alias_details"] = {
            "temporal": {"name": self.temporal_alias, "created": temporal_created},
            "blacklist": {"name": self.blacklist_alias, "created": blacklist_created},
        }

        ports_status: Dict[str, Dict[str, bool]] = {}
        try:
            for protocol in ("tcp", "udp"):
                created = self._ensure_ports_alias_exists(protocol)
                ports_status[protocol] = {"ready": True, "created": created}
        except NotImplementedError:
            ports_status = {
                protocol: {"ready": False, "created": False}
                for protocol in ("tcp", "udp")
            }

        status["ports_alias_status"] = ports_status
        status["ports_alias_ready"] = all(
            entry.get("ready") for entry in ports_status.values()
        )
        status["ports_alias_created"] = any(
            entry.get("created") for entry in ports_status.values()
        )

        alias_created = status["alias_created"]
        ports_alias_created = status["ports_alias_created"]

        if (alias_created or ports_alias_created) and self._apply_changes:
            self.apply_changes()
            status["applied_changes"] = True

        return status

    @property
    def _status_endpoint(self) -> str:
        """Endpoint usado para validar la conectividad del cliente."""

        raise NotImplementedError

    def check_connection(self) -> None:
        """Comprueba conectividad sin depender de un alias existente."""

        self._request("GET", self._status_endpoint)

    def ensure_ready(self) -> None:
        """Intenta garantizar que el alias de bloqueos exista antes de usarlo."""

        self.get_status()

    def create_alias(self, *, name: str, alias_type: str, description: str) -> None:
        """Crea un alias del tipo indicado."""

        raise NotImplementedError

    def get_ports(self) -> Dict[str, List[int]]:
        ports_by_protocol: Dict[str, List[int]] = {}
        for protocol in ("tcp", "udp"):
            try:
                ports = self._list_ports_alias(protocol)
            except NotImplementedError:
                ports_by_protocol[protocol] = []
                continue

            normalized: List[int] = []
            for value in ports:
                try:
                    normalized.append(int(value))
                except (TypeError, ValueError):
                    continue
            ports_by_protocol[protocol] = sorted(set(normalized))

        return ports_by_protocol

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

    def list_blacklist(self) -> List[str]:
        return self._list_alias_values(self.blacklist_alias)

    def add_to_blacklist(self, ip: str, reason: str = "") -> None:
        self._block_ip_backend(ip, reason, alias_name=self.blacklist_alias)
        self._apply_changes_if_enabled()

    def remove_from_blacklist(self, ip: str) -> None:
        self._unblock_ip_backend(ip, alias_name=self.blacklist_alias)
        self._apply_changes_if_enabled()

    def _block_ip_backend(self, ip: str, reason: str, *, alias_name: str) -> None:
        raise NotImplementedError

    def _unblock_ip_backend(self, ip: str, *, alias_name: str) -> None:
        raise NotImplementedError

    def _list_table_backend(self) -> List[str]:
        raise NotImplementedError

    def _ensure_alias_exists(self, alias_name: str, description: str) -> bool:
        """Crea el alias de bloqueos si la plataforma lo soporta.

        Devuelve ``True`` si se ha solicitado la creación del alias
        (permitiendo lanzar un reload del firewall) o ``False`` si ya
        existía.
        """

        raise NotImplementedError

    def _list_ports_alias(self, protocol: str) -> List[str | int]:
        """Devuelve los valores actuales del alias de puertos."""

        raise NotImplementedError

    @property
    def _apply_endpoint(self) -> str:
        """Endpoint para aplicar/reload cambios en el firewall."""

        raise NotImplementedError

    def _apply_changes_if_enabled(self) -> None:
        if not self._apply_changes:
            return
        self.apply_changes()


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

    def _alias_exists(self, alias_name: str) -> bool:
        try:
            response = self._request("GET", "/api/firewall/alias/searchItem")
        except httpx.HTTPStatusError:
            return False
        data = response.json()
        rows = data.get("rows", []) if isinstance(data, dict) else []
        return any(row.get("name") == alias_name for row in rows)

    def create_alias(self, *, name: str, alias_type: str, description: str) -> None:
        payload = {
            "alias": {
                "name": name,
                "type": alias_type,
                "content": "",
                "description": description,
                "enabled": "1",
            }
        }

        self._request("POST", "/api/firewall/alias/addItem", json=payload)

    def _block_ip_backend(self, ip: str, reason: str, *, alias_name: str) -> None:
        response = self._request(
            "POST",
            f"/api/firewall/alias_util/add/{alias_name}",
            json={"address": ip, "description": reason} if reason else {"address": ip},
        )
        data = response.json()
        if isinstance(data, dict) and data.get("status") not in {"done", "ok", None}:
            raise RuntimeError(f"No se pudo añadir la IP al alias: {data}")

    def _unblock_ip_backend(self, ip: str, *, alias_name: str) -> None:
        try:
            response = self._request(
                "POST",
                f"/api/firewall/alias_util/delete/{alias_name}",
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
        self._request("POST", f"/api/firewall/alias_util/flush/{alias_name}")

        for address in remaining:
            self._request(
                "POST",
                f"/api/firewall/alias_util/add/{alias_name}",
                json={"address": address},
            )

    def _list_ports_alias(self, protocol: str) -> List[str | int]:
        alias_name = self._ports_alias_name_for(protocol)
        return self._list_alias_values(alias_name)

    def _list_alias_values(self, alias_name: str) -> List[str]:
        try:
            response = self._request("GET", f"/api/firewall/alias_util/list/{alias_name}")
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                return []
            raise
        data = response.json()
        if isinstance(data, dict):
            if "rows" in data:
                return [str(entry.get("ip", "")) for entry in data.get("rows", []) if entry.get("ip")]
            if "items" in data:
                return [
                    str(entry.get("address", ""))
                    for entry in data.get("items", [])
                    if entry.get("address")
                ]
        if isinstance(data, list):
            return [str(item.get("address", item)) if isinstance(item, dict) else str(item) for item in data if item]
        return []

    def _list_table_backend(self) -> List[str]:
        try:
            response = self._request(
                "GET", f"/api/firewall/alias_util/list/{self.temporal_alias}"
            )
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                created = self._ensure_alias_exists(
                    self.temporal_alias, "Mimosa temporal blocks"
                )
                if created:
                    self._apply_changes_if_enabled()
                response = self._request(
                    "GET", f"/api/firewall/alias_util/list/{self.temporal_alias}"
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

    def _ensure_alias_exists(self, alias_name: str, description: str) -> bool:  # type: ignore[override]
        if self._alias_exists(alias_name):
            return False

        self.create_alias(
            name=alias_name,
            alias_type="host",
            description=description,
        )
        return True

    def _ensure_ports_alias_exists(self, protocol: str) -> bool:
        alias_name = self._ports_alias_name_for(protocol)
        if self._alias_exists(alias_name):
            return False

        self.create_alias(
            name=alias_name,
            alias_type="port",
            description="Mimosa published ports",
        )
        return True

    def _list_ports_alias(self, protocol: str) -> List[str | int]:
        alias_name = self._ports_alias_name_for(protocol)
        return self._list_alias_values(alias_name)

    @property
    def _status_endpoint(self) -> str:
        return "/api/core/firmware/info"

    @property
    def _apply_endpoint(self) -> str:
        return "/api/firewall/filter/apply"


class PFSenseClient(_BaseSenseClient):
    """Cliente HTTP para pfSense usando la API pfRest.

    pfRest expone endpoints bajo ``/api/v1`` para gestionar alias, aunque
    algunas instalaciones publican la API bajo prefijos diferentes (p.ej.
    ``/rest`` o ``/restapi/v1``). Este cliente detecta automáticamente el
    prefijo válido cuando recibe un 404 y vuelve a intentar la petición con
    las variantes conocidas.

    Requiere un API key y secret configurados en el paquete pfRest, enviados
    como cabeceras ``X-API-KEY`` y ``X-API-SECRET``.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        *,
        verify_ssl: bool = True,
        timeout: float = 10.0,
        client: Optional[httpx.Client] = None,
        apply_changes: bool = True,
    ) -> None:
        self.api_prefix = "/api/v1"
        self._api_prefix_candidates = ["/api/v1", "/rest", "/rest/api", "/rest/v1", "/restapi/v1"]
        self._prefix_validated = False
        super().__init__(
            base_url,
            api_key,
            api_secret,
            verify_ssl=verify_ssl,
            timeout=timeout,
            client=client,
            apply_changes=apply_changes,
        )

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        normalized = prefix.strip() or "/api/v1"
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized.rstrip("/")

    def _path(self, route: str, *, prefix: str | None = None) -> str:
        normalized_route = route if route.startswith("/") else f"/{route}"
        normalized_prefix = self._normalize_prefix(prefix or self.api_prefix)
        return f"{normalized_prefix}{normalized_route}"

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:  # type: ignore[override]
        route = path.lstrip("/")
        prefixes = [self._normalize_prefix(p) for p in self._api_prefix_candidates]
        if self.api_prefix not in prefixes:
            prefixes.insert(0, self._normalize_prefix(self.api_prefix))

        last_error: httpx.HTTPStatusError | None = None
        for candidate in prefixes:
            full_path = self._path(route, prefix=candidate)
            try:
                response = self._client.request(
                    method, f"{self.base_url}{full_path}", **kwargs
                )
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                last_error = exc
                should_retry = (
                    not self._prefix_validated
                    and exc.response.status_code == 404
                    and candidate != prefixes[-1]
                )
                if not should_retry:
                    raise
                continue

            if candidate != self.api_prefix:
                self.api_prefix = candidate
            self._prefix_validated = True
            return response

        if last_error:
            raise last_error
        raise RuntimeError("No se pudo completar la petición a pfSense")

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

    def _alias_exists(self, alias_name: str) -> bool:
        try:
            self._request("GET", f"firewall/alias/{alias_name}")
            return True
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return False
            raise

    def create_alias(self, *, name: str, alias_type: str, description: str) -> None:
        payload = {
            "name": name,
            "type": alias_type,
            "descr": description,
            "addresses": [],
        }
        self._request("POST", "firewall/alias", json=payload)

    def _block_ip_backend(self, ip: str, reason: str, *, alias_name: str) -> None:
        payload = {"address": ip, "descr": reason or ""}
        self._request("POST", f"firewall/alias/{alias_name}/address", json=payload)

    def _unblock_ip_backend(self, ip: str, *, alias_name: str) -> None:
        self._request("DELETE", f"firewall/alias/{alias_name}/address/{ip}")

    def _list_table_backend(self) -> List[str]:
        try:
            response = self._request("GET", f"firewall/alias/{self.temporal_alias}")
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                created = self._ensure_alias_exists(
                    self.temporal_alias, "Mimosa temporal blocks"
                )
                if created:
                    self._apply_changes_if_enabled()
                response = self._request("GET", f"firewall/alias/{self.temporal_alias}")
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

    def _list_alias_values(self, alias_name: str) -> List[str]:
        try:
            response = self._request("GET", f"firewall/alias/{alias_name}")
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                return []
            raise

        data = response.json()
        values: List[str] = []
        if isinstance(data, dict):
            for key in ("addresses", "items", "data"):
                if key in data and isinstance(data[key], list):
                    values = [
                        str(entry.get("address", entry))
                        if isinstance(entry, dict)
                        else str(entry)
                        for entry in data[key]
                        if entry
                    ]
                    break
        elif isinstance(data, list):
            values = [
                str(entry.get("address", entry)) if isinstance(entry, dict) else str(entry)
                for entry in data
                if entry
            ]
        return values

    def _ensure_alias_exists(self, alias_name: str, description: str) -> bool:  # type: ignore[override]
        if self._alias_exists(alias_name):
            return False

        self.create_alias(
            name=alias_name,
            alias_type="host",
            description=description,
        )
        return True

    def _ensure_ports_alias_exists(self, protocol: str) -> bool:
        alias_name = self._ports_alias_name_for(protocol)
        if self._alias_exists(alias_name):
            return False

        self.create_alias(
            name=alias_name,
            alias_type="port",
            description="Mimosa published ports",
        )
        return True

    @property
    def _status_endpoint(self) -> str:
        return "status/system"

    @property
    def _apply_endpoint(self) -> str:
        return "diagnostics/filter/reload"

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

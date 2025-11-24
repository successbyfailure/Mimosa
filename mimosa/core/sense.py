"""Cliente mínimo para integrar pfSense/OPNsense como firewall remoto.

Proporciona métodos para añadir o eliminar direcciones en una tabla
(Alias) y consultar su contenido usando la API REST.
"""
from __future__ import annotations

from typing import Dict, List, Optional

import httpx
from mimosa.core.api import FirewallGateway


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
        self.ports_alias_name = "mimosa_ports"
        self._client = client or self._build_client(
            sanitized_url, api_key, api_secret, verify_ssl, timeout
        )
        self._apply_changes = apply_changes

    def block_ip(
        self, ip: str, reason: str = "", duration_minutes: Optional[int] = None
    ) -> None:
        """Añade una IP al alias configurado.

        La duración se gestiona en capas superiores; este cliente solo
        comunica el bloqueo al firewall remoto y aplica los cambios
        necesarios.
        """

        self._block_ip_backend(ip, reason)
        self._apply_changes_if_enabled()

    def unblock_ip(self, ip: str) -> None:
        """Elimina una IP del alias configurado."""

        self._unblock_ip_backend(ip)
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
            "ports_alias_ready": False,
            "ports_alias_created": False,
            "applied_changes": False,
        }

        self.check_connection()
        status["available"] = True

        alias_created = self._ensure_alias_exists()
        status["alias_ready"] = True
        status["alias_created"] = alias_created

        ports_alias_created = False
        try:
            ports_alias_created = self._ensure_ports_alias_exists()
            status["ports_alias_ready"] = True
            status["ports_alias_created"] = ports_alias_created
        except NotImplementedError:
            status["ports_alias_ready"] = False
            status["ports_alias_created"] = False

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

    def add_port(
        self,
        *,
        target_ip: str,
        port: int,
        protocol: str = "tcp",
        description: str | None = None,
        interface: str = "wan",
    ) -> None:
        self._create_port_forward(
            port=port,
            protocol=protocol,
            target_ip=target_ip,
            description=description,
            interface=interface,
        )

        alias_changed = False
        try:
            alias_changed = self._add_port_to_alias(int(port))
        except NotImplementedError:
            alias_changed = False

        if alias_changed or self._apply_changes:
            self._apply_changes_if_enabled()

    def remove_port(
        self, port: int, *, protocol: str = "tcp", interface: str = "wan"
    ) -> None:
        removed_rule = False
        try:
            removed_rule = self._delete_port_forward(
                port=int(port), protocol=protocol, interface=interface
            )
        except NotImplementedError:
            removed_rule = False

        alias_changed = False
        try:
            alias_changed = self._remove_port_from_alias(int(port))
        except NotImplementedError:
            alias_changed = False

        if (removed_rule or alias_changed) and self._apply_changes:
            self._apply_changes_if_enabled()

    def get_ports(self) -> List[int]:
        try:
            ports = self._list_ports_alias()
        except NotImplementedError:
            return []
        normalized: List[int] = []
        for value in ports:
            try:
                normalized.append(int(value))
            except (TypeError, ValueError):
                continue
        return sorted(set(normalized))

    def list_services(self) -> List[Dict[str, object]]:
        return self._list_port_forwards()

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

    def _delete_port_forward(
        self, *, port: int, protocol: str, interface: str
    ) -> bool:
        """Elimina la regla de NAT asociada al puerto indicado."""

        raise NotImplementedError

    def _add_port_to_alias(self, port: int) -> bool:
        """Añade un puerto al alias de Mimosa.

        Devuelve ``True`` si se modificó el alias.
        """

        raise NotImplementedError

    def _remove_port_from_alias(self, port: int) -> bool:
        """Elimina un puerto del alias de Mimosa.

        Devuelve ``True`` si se modificó el alias.
        """

        raise NotImplementedError

    def _list_ports_alias(self) -> List[str | int]:
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

        try:
            # API moderna (24.7+)
            self._request("POST", "/api/firewall/alias/addItem", json=payload)
            return
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code != 404:
                raise

        legacy_payload = {
            "name": name,
            "type": "port" if alias_type == "port" else "network",
            "content": "",
            "description": description,
            "enabled": "1",
        }

        self._request("POST", "/api/firewall/alias_util/add", json=legacy_payload)
        self._request("GET", f"/api/firewall/alias_util/list/{name}")

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

    def _add_port_to_alias(self, port: int) -> bool:
        desired = str(int(port))
        current = set(self._list_alias_values(self.ports_alias_name))
        if desired in current:
            return False

        self._ensure_ports_alias_exists()
        self._request(
            "POST",
            f"/api/firewall/alias_util/add/{self.ports_alias_name}",
            json={"address": desired},
        )
        return True

    def _remove_port_from_alias(self, port: int) -> bool:
        desired = str(int(port))
        current = set(self._list_alias_values(self.ports_alias_name))
        if desired not in current:
            return False

        self._request(
            "POST",
            f"/api/firewall/alias_util/delete/{self.ports_alias_name}",
            json={"address": desired},
        )
        return True

    def _list_ports_alias(self) -> List[str | int]:
        return self._list_alias_values(self.ports_alias_name)

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

    def _list_port_forwards(self) -> List[Dict[str, object]]:
        data = self._search_nat_rules()
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
                    "interface": row.get("interface") or row.get("if"),
                    "target": row.get("target")
                    or row.get("natip")
                    or row.get("redirect_targetip"),
                }
            )
        return services

    def _search_nat_rules(self) -> Dict[str, object]:
        """Recupera reglas NAT probando las variantes de endpoint conocidas."""

        endpoints = [
            # Confirmed in the upstream core API tree
            "/api/firewall/filter/searchRule",
            "/api/firewall/source_nat/searchRule",
            # Legacy endpoints kept for compatibility where available
            "/api/firewall/nat/searchNAT",
        ]

        last_exc: httpx.HTTPStatusError | None = None
        for endpoint in endpoints:
            try:
                response = self._request("GET", endpoint)
                return response.json()
            except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
                last_exc = exc
                if exc.response.status_code == 404:
                    continue
                raise

        if last_exc:
            raise last_exc

        return {}

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

    def _delete_port_forward(
        self, *, port: int, protocol: str, interface: str
    ) -> bool:
        desired_protocol = protocol.lower()
        match = next(
            (
                svc
                for svc in self._list_port_forwards()
                if svc.get("port") == int(port)
                and svc.get("protocol") == desired_protocol
                and (svc.get("interface") in {None, interface})
            ),
            None,
        )
        if not match or not match.get("id"):
            return False

        try:
            self._request("POST", f"/api/firewall/nat/delNAT/{match['id']}")
        except httpx.HTTPStatusError as exc:  # pragma: no cover - dependiente del firewall
            if exc.response.status_code == 404:
                self._request(
                    "POST", f"/api/firewall/nat/delPortForward/{match['id']}"
                )
            else:
                raise
        return True

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
        if self._alias_exists(self.alias_name):
            return False

        self.create_alias(
            name=self.alias_name,
            alias_type="host",
            description="Mimosa blocklist",
        )
        return True

    def _ensure_ports_alias_exists(self) -> bool:
        if self._alias_exists(self.ports_alias_name):
            return False

        self.create_alias(
            name=self.ports_alias_name,
            alias_type="port",
            description="Mimosa published ports",
        )
        return True

    def _add_port_to_alias(self, port: int) -> bool:
        desired = str(int(port))
        current = set(self._list_alias_values(self.ports_alias_name))
        if desired in current:
            return False

        self._ensure_ports_alias_exists()
        payload = {"address": desired, "descr": "Mimosa port"}
        self._request(
            "POST",
            f"/api/v1/firewall/alias/{self.ports_alias_name}/address",
            json=payload,
        )
        return True

    def _remove_port_from_alias(self, port: int) -> bool:
        desired = str(int(port))
        current = set(self._list_alias_values(self.ports_alias_name))
        if desired not in current:
            return False

        self._request(
            "DELETE",
            f"/api/v1/firewall/alias/{self.ports_alias_name}/address/{desired}",
        )
        return True

    def _list_ports_alias(self) -> List[str | int]:
        return self._list_alias_values(self.ports_alias_name)

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

    def _alias_exists(self, alias_name: str) -> bool:
        try:
            self._request("GET", f"/api/v1/firewall/alias/{alias_name}")
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
        self._request("POST", "/api/v1/firewall/alias", json=payload)

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

    def _list_alias_values(self, alias_name: str) -> List[str]:
        try:
            response = self._request("GET", f"/api/v1/firewall/alias/{alias_name}")
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

    def _ensure_alias_exists(self) -> bool:
        if self._alias_exists(self.alias_name):
            return False

        self.create_alias(
            name=self.alias_name,
            alias_type="host",
            description="Mimosa blocklist",
        )
        return True

    def _ensure_ports_alias_exists(self) -> bool:
        if self._alias_exists(self.ports_alias_name):
            return False

        self.create_alias(
            name=self.ports_alias_name,
            alias_type="port",
            description="Mimosa published ports",
        )
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
                    "interface": item.get("interface"),
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

    def _delete_port_forward(
        self, *, port: int, protocol: str, interface: str
    ) -> bool:
        desired_protocol = protocol.lower()
        match = next(
            (
                svc
                for svc in self._list_port_forwards()
                if svc.get("port") == int(port)
                and svc.get("protocol") == desired_protocol
                and (svc.get("interface") in {None, interface})
            ),
            None,
        )
        if not match or not match.get("id"):
            return False

        self._request(
            "DELETE", f"/api/v1/firewall/nat/port_forward/{match['id']}"
        )
        return True

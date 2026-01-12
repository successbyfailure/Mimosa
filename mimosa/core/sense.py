"""Cliente mínimo para integrar OPNsense como firewall remoto.

Proporciona métodos para añadir o eliminar direcciones en una tabla
(Alias) y consultar su contenido usando la API REST.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Dict, Iterable, List, Optional
import httpx
from mimosa.core.api import FirewallGateway

TEMPORAL_ALIAS_NAME = "mimosa_temporal_list"
BLACKLIST_ALIAS_NAME = "mimosa_blacklist"
WHITELIST_ALIAS_NAME = "mimosa_whitelist"
MIMOSA_IP_ALIAS_NAME = "mimosa_host"
PORT_ALIAS_NAMES = {"tcp": "mimosa_ports_tcp", "udp": "mimosa_ports_udp"}
FIREWALL_RULE_DESCRIPTIONS = {
    "whitelist": "Mimosa - Whitelist (allow)",
    "temporal": "Mimosa - Temporal blocks",
    "blacklist": "Mimosa - Permanent blacklist",
}
FIREWALL_RULE_SPECS = {
    "whitelist": {
        "alias_name": WHITELIST_ALIAS_NAME,
        "action": "pass",
        "sequence": 1,
        "enabled": True,
    },
    "temporal": {
        "alias_name": TEMPORAL_ALIAS_NAME,
        "action": "block",
        "sequence": 2,
        "enabled": False,
    },
    "blacklist": {
        "alias_name": BLACKLIST_ALIAS_NAME,
        "action": "block",
        "sequence": 3,
        "enabled": False,
    },
}


class _BaseSenseClient(FirewallGateway):
    """Base compartida para clientes Sense (OPNsense).

    Gestiona la autenticación HTTP básica y delega en la
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
        self.whitelist_alias = WHITELIST_ALIAS_NAME
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

        try:
            self.check_connection()
        except httpx.HTTPError as exc:
            status["error"] = str(exc)
            return status
        status["available"] = True

        mimosa_ip_value = os.getenv("MIMOSA_IP")
        mimosa_ip_created = False
        if mimosa_ip_value:
            mimosa_ip_created = self._ensure_alias_exists(
                MIMOSA_IP_ALIAS_NAME, "Mimosa host"
            )
            try:
                self._block_ip_backend(
                    mimosa_ip_value,
                    "Mimosa host",
                    alias_name=MIMOSA_IP_ALIAS_NAME,
                )
            except NotImplementedError:
                pass

        whitelist_created = self._ensure_alias_exists(
            WHITELIST_ALIAS_NAME, "Mimosa whitelist"
        )
        temporal_created = self._ensure_alias_exists(
            self.temporal_alias, "Mimosa temporal blocks"
        )
        blacklist_created = self._ensure_alias_exists(
            self.blacklist_alias, "Mimosa blacklist"
        )
        status["alias_ready"] = True
        status["alias_created"] = (
            mimosa_ip_created or whitelist_created or temporal_created or blacklist_created
        )
        status["alias_details"] = {
            "whitelist": {"name": WHITELIST_ALIAS_NAME, "created": whitelist_created},
            "temporal": {"name": self.temporal_alias, "created": temporal_created},
            "blacklist": {"name": self.blacklist_alias, "created": blacklist_created},
        }
        if mimosa_ip_value:
            status["alias_details"]["mimosa_host"] = {
                "name": MIMOSA_IP_ALIAS_NAME,
                "created": mimosa_ip_created,
                "value": mimosa_ip_value,
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

        # Asegurar que existan las reglas de firewall para los alias
        rules_status = {
            "created": {"whitelist": False, "temporal": False, "blacklist": False},
            "updated": {"whitelist": False, "temporal": False, "blacklist": False},
        }
        try:
            rules_status = self._ensure_firewall_rules_exist()
            status["firewall_rules_ready"] = True
            status["firewall_rules_created"] = any(rules_status["created"].values())
            status["firewall_rules_updated"] = any(rules_status["updated"].values())
            status["firewall_rules_details"] = rules_status
        except (NotImplementedError, AttributeError):
            # Cliente no soporta reglas de firewall
            status["firewall_rules_ready"] = False
            status["firewall_rules_created"] = False

        alias_created = status["alias_created"]
        ports_alias_created = status["ports_alias_created"]
        rules_created_any = status.get("firewall_rules_created", False)
        rules_updated_any = status.get("firewall_rules_updated", False)

        if (
            alias_created
            or ports_alias_created
            or rules_created_any
            or rules_updated_any
        ) and self._apply_changes:
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

    def set_ports_alias(self, protocol: str, ports: Iterable[int]) -> None:
        """Reemplaza el contenido del alias de puertos indicado."""

        raise NotImplementedError

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

    def list_whitelist(self) -> List[str]:
        return self._list_alias_values(self.whitelist_alias)

    def add_to_blacklist(self, ip: str, reason: str = "") -> None:
        self._block_ip_backend(ip, reason, alias_name=self.blacklist_alias)
        self._apply_changes_if_enabled()

    def add_to_whitelist(self, ip: str, reason: str = "") -> None:
        self._block_ip_backend(ip, reason, alias_name=self.whitelist_alias)
        self._apply_changes_if_enabled()

    def remove_from_blacklist(self, ip: str) -> None:
        self._unblock_ip_backend(ip, alias_name=self.blacklist_alias)
        self._apply_changes_if_enabled()

    def remove_from_whitelist(self, ip: str) -> None:
        self._unblock_ip_backend(ip, alias_name=self.whitelist_alias)
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

    def _flush_states_for_ip(self, ip: str) -> bool:
        payloads = [
            {"ip": ip},
            {"address": ip},
            {"src": ip},
            {"source": ip},
            {"addr": ip},
        ]
        for payload in payloads:
            try:
                response = self._request(
                    "POST", "/api/diagnostics/firewall/killstates", json=payload
                )
                data = response.json()
                if isinstance(data, dict):
                    status = data.get("status") or data.get("result")
                    if status in {"ok", "done", "success", None}:
                        return True
                return True
            except httpx.HTTPStatusError:
                continue
        return False

    def block_ip(
        self, ip: str, reason: str = "", duration_minutes: Optional[int] = None
    ) -> None:
        """Añade una IP al alias y corta estados activos."""

        self._block_ip_backend(ip, reason, alias_name=self.temporal_alias)
        self._apply_changes_if_enabled()
        self._flush_states_for_ip(ip)

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

    def _get_alias_item(self, alias_name: str) -> Optional[Dict[str, object]]:
        uuid = self._get_alias_uuid(alias_name)
        if not uuid:
            return None
        try:
            response = self._request("GET", f"/api/firewall/alias/getItem/{uuid}")
        except httpx.HTTPError:
            return None
        data = response.json()
        alias = data.get("alias") if isinstance(data, dict) else None
        return alias if isinstance(alias, dict) else None

    def _ensure_alias_type(self, alias_name: str, alias_type: str) -> bool:
        alias_item = self._get_alias_item(alias_name)
        if not alias_item:
            return False
        current_type = alias_item.get("type")
        if isinstance(current_type, dict):
            current_type = self._extract_selected_key(current_type)
        if current_type == alias_type:
            return False
        uuid = self._get_alias_uuid(alias_name)
        if not uuid:
            return False
        content = alias_item.get("content", "")
        if isinstance(content, dict):
            selected = []
            for key, value in content.items():
                if isinstance(value, dict) and value.get("selected") == 1:
                    selected.append(str(value.get("value", key)))
            content = "\n".join(selected)
        if alias_type == "network":
            normalized = []
            for entry in str(content).splitlines():
                entry = entry.strip()
                if not entry:
                    continue
                resolved = self._resolve_whitelist_addresses(entry)
                normalized.extend(resolved)
            content = "\n".join(sorted(set(normalized)))
        payload = {
            "alias": {
                "enabled": alias_item.get("enabled", "1"),
                "name": alias_name,
                "type": alias_type,
                "content": content,
                "description": alias_item.get("description", ""),
            }
        }
        response = self._request("POST", f"/api/firewall/alias/setItem/{uuid}", json=payload)
        result = response.json()
        if result.get("result") != "saved":
            raise RuntimeError(
                f"No se pudo actualizar el alias {alias_name}: {result.get('validations', result)}"
            )
        return True

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

    def _normalize_whitelist_address(self, address: str) -> str:
        try:
            network = ipaddress.ip_network(address, strict=False)
        except ValueError:
            return address
        if network.prefixlen == network.max_prefixlen:
            suffix = "/128" if network.version == 6 else "/32"
            return f"{network.network_address}{suffix}"
        return str(network)

    def _resolve_whitelist_addresses(self, value: str) -> List[str]:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None

        if network is not None:
            return [self._normalize_whitelist_address(value)]

        try:
            infos = socket.getaddrinfo(value, None)
        except socket.gaierror:
            return []

        addresses = []
        for info in infos:
            ip = info[4][0]
            if ip:
                addresses.append(self._normalize_whitelist_address(ip))

        return sorted(set(addresses))

    def add_to_whitelist(self, ip: str, reason: str = "") -> None:  # type: ignore[override]
        addresses = self._resolve_whitelist_addresses(ip)
        if not addresses:
            raise RuntimeError(f"No se pudo resolver el host: {ip}")
        for address in addresses:
            self._block_ip_backend(address, reason, alias_name=self.whitelist_alias)
        self._apply_changes_if_enabled()

    def remove_from_whitelist(self, ip: str) -> None:  # type: ignore[override]
        addresses = self._resolve_whitelist_addresses(ip)
        if not addresses:
            return
        for address in addresses:
            self._unblock_ip_backend(address, alias_name=self.whitelist_alias)
        self._apply_changes_if_enabled()

    def list_whitelist(self) -> List[str]:  # type: ignore[override]
        entries = self._list_alias_values(self.whitelist_alias)
        normalized = []
        for entry in entries:
            if "/" in entry:
                normalized.append(entry)
                continue
            try:
                ip = ipaddress.ip_address(entry)
            except ValueError:
                normalized.append(entry)
                continue
            suffix = "/128" if ip.version == 6 else "/32"
            normalized.append(f"{entry}{suffix}")
        return normalized

    def expand_whitelist_entries(self, entries: List[str]) -> tuple[List[str], bool]:  # type: ignore[override]
        expanded: List[str] = []
        had_unresolved = False
        for entry in entries:
            if not entry:
                continue
            addresses = self._resolve_whitelist_addresses(entry)
            if addresses:
                expanded.extend(addresses)
            else:
                had_unresolved = True
        return expanded, had_unresolved

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
        desired_type = "network" if alias_name == WHITELIST_ALIAS_NAME else "host"
        if self._alias_exists(alias_name):
            if alias_name == WHITELIST_ALIAS_NAME:
                changed = self._ensure_alias_type(alias_name, desired_type)
                if changed:
                    self._apply_changes_if_enabled()
            return False

        self.create_alias(
            name=alias_name,
            alias_type=desired_type,
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

    def _get_alias_uuid(self, alias_name: str) -> Optional[str]:
        """Obtiene el UUID de un alias por su nombre."""
        try:
            response = self._request("GET", "/api/firewall/alias/searchItem")
            data = response.json()
            rows = data.get("rows", [])
            alias_row = next((row for row in rows if row.get("name") == alias_name), None)
            return alias_row.get("uuid") if alias_row else None
        except httpx.HTTPError:
            return None

    def _list_ports_alias(self, protocol: str) -> List[str | int]:
        """Lista los puertos de un alias usando el endpoint getItem.

        El endpoint alias_util/list no funciona correctamente para alias de tipo
        'port', por lo que usamos getItem para obtener el contenido real.
        """
        alias_name = self._ports_alias_name_for(protocol)
        uuid = self._get_alias_uuid(alias_name)

        if not uuid:
            return []

        try:
            response = self._request("GET", f"/api/firewall/alias/getItem/{uuid}")
            data = response.json()
            content = data.get("alias", {}).get("content", {})

            if not isinstance(content, dict):
                return []

            # Extraer solo los items con "selected": 1 que son números de puerto válidos
            ports = []
            for key, value in content.items():
                if isinstance(value, dict) and value.get("selected") == 1:
                    try:
                        port_num = int(key)
                        if 1 <= port_num <= 65535:
                            ports.append(port_num)
                    except (ValueError, TypeError):
                        continue

            return ports

        except httpx.HTTPError:
            return []

    def set_ports_alias(self, protocol: str, ports: Iterable[int]) -> None:  # type: ignore[override]
        """Establece los puertos de un alias usando el endpoint setItem.

        El endpoint alias_util/add no funciona correctamente para alias de tipo
        'port', por lo que usamos setItem para actualizar el contenido completo.
        """
        alias_name = self._ports_alias_name_for(protocol)
        self._ensure_ports_alias_exists(protocol)

        uuid = self._get_alias_uuid(alias_name)
        if not uuid:
            raise RuntimeError(f"No se pudo obtener UUID del alias {alias_name}")

        # Sanitizar y ordenar puertos
        sanitized = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})

        # El formato correcto para alias de tipo 'port' es con saltos de línea
        content = "\n".join(str(port) for port in sanitized) if sanitized else ""

        payload = {
            "alias": {
                "enabled": "1",
                "name": alias_name,
                "type": "port",
                "content": content,
                "description": "Mimosa published ports",
            }
        }

        response = self._request("POST", f"/api/firewall/alias/setItem/{uuid}", json=payload)
        result = response.json()

        if result.get("result") != "saved":
            raise RuntimeError(
                f"No se pudo actualizar el alias de puertos: {result.get('validations', result)}"
            )

        self._apply_changes_if_enabled()

    def _find_rule_by_description(
        self, description: str
    ) -> tuple[Optional[str], Optional[Dict[str, object]]]:
        """Busca una regla de firewall por su descripción y devuelve su UUID.

        Usa el endpoint /get en lugar de /searchRule porque searchRule puede
        no devolver todas las reglas dependiendo de filtros internos.
        """
        try:
            response = self._request("GET", "/api/firewall/filter/get")
            data = response.json()

            # Las reglas están en filter.rules.rule como un dict UUID -> rule_data
            rules = data.get("filter", {}).get("rules", {}).get("rule", {})

            for uuid, rule in rules.items():
                # La descripción puede estar en diferentes campos
                rule_desc = rule.get("description", "")
                # En algunos casos puede ser un dict con 'value'
                if isinstance(rule_desc, dict):
                    rule_desc = rule_desc.get("value", "")

                if rule_desc == description:
                    return uuid, rule

            return None, None
        except httpx.HTTPError:
            return None, None

    def _extract_rule_scalar(self, value: object) -> Optional[str]:
        if isinstance(value, dict):
            if "value" in value:
                return str(value.get("value"))
            if "selected" in value:
                return str(value.get("selected"))
        if value is None:
            return None
        return str(value)

    def _extract_selected_key(self, value: object) -> Optional[str]:
        if isinstance(value, dict):
            for key, entry in value.items():
                if isinstance(entry, dict) and entry.get("selected") == 1:
                    return str(key)
        return None

    def _extract_selected_value(self, value: object) -> Optional[str]:
        if isinstance(value, dict):
            for key, entry in value.items():
                if isinstance(entry, dict) and entry.get("selected") == 1:
                    return str(entry.get("value", key))
        return None

    def _create_firewall_rule(
        self,
        alias_name: str,
        description: str,
        action: str = "block",
        interface: str = "wan",
        log: bool = True,
        sequence: Optional[int] = None,
        enabled: bool = True,
    ) -> str:
        """Crea una regla de firewall para un alias.

        Args:
            alias_name: Nombre del alias
            description: Descripción de la regla
            action: Acción de la regla ("block" o "pass")
            interface: Interfaz donde aplicar (default: wan)
            log: Si loguear las coincidencias
            sequence: Número de secuencia (orden) de la regla. Menor = mayor prioridad

        Returns:
            UUID de la regla creada
        """
        rule_data = {
            "enabled": "1" if enabled else "0",
            "action": action,
            "quick": "1",
            "interface": interface,
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": alias_name,
            "destination_net": "any",
            "description": description,
            "log": "1" if log else "0",
        }

        # Agregar secuencia si se especifica (para ordenar reglas)
        if sequence is not None:
            rule_data["sequence"] = str(sequence)

        payload = {"rule": rule_data}

        response = self._request("POST", "/api/firewall/filter/addRule", json=payload)
        result = response.json()

        if result.get("result") != "saved":
            raise RuntimeError(f"No se pudo crear la regla de firewall: {result}")

        return result.get("uuid", "")

    def _update_firewall_rule(
        self,
        rule_uuid: str,
        current_rule: Dict[str, object],
        *,
        alias_name: str,
        description: str,
        action: str,
        interface: str,
        sequence: int,
    ) -> None:
        direction = self._extract_selected_key(current_rule.get("direction")) or "in"
        ipprotocol = self._extract_selected_key(current_rule.get("ipprotocol")) or "inet"
        protocol = self._extract_selected_key(current_rule.get("protocol")) or "any"
        interface_value = (
            self._extract_selected_key(current_rule.get("interface")) or interface
        )

        rule_data = {
            "enabled": self._extract_rule_scalar(current_rule.get("enabled")) or "1",
            "action": action,
            "quick": self._extract_rule_scalar(current_rule.get("quick")) or "1",
            "interface": interface_value,
            "direction": direction,
            "ipprotocol": ipprotocol,
            "protocol": protocol,
            "source_net": alias_name,
            "destination_net": self._extract_rule_scalar(current_rule.get("destination_net")) or "any",
            "description": description,
            "log": self._extract_rule_scalar(current_rule.get("log")) or "1",
            "sequence": str(sequence),
        }
        payload = {"rule": rule_data}
        response = self._request(
            "POST", f"/api/firewall/filter/setRule/{rule_uuid}", json=payload
        )
        result = response.json()
        if result.get("result") != "saved":
            raise RuntimeError(f"No se pudo actualizar la regla de firewall: {result}")

    def _ensure_firewall_rules_exist(
        self, interface: str = "wan"
    ) -> Dict[str, Dict[str, bool]]:
        """Asegura que existan las reglas de firewall para los alias de Mimosa.

        Crea tres reglas si no existen (en orden de evaluación):
        1. Regla para PERMITIR whitelist (mimosa_whitelist) - sequence 1
        2. Regla para BLOQUEAR alias temporal (mimosa_temporal_list) - sequence 2
        3. Regla para BLOQUEAR blacklist permanente (mimosa_blacklist) - sequence 3

        Args:
            interface: Interfaz donde crear las reglas (default: wan)

        Returns:
            Dict con estado de creación y actualización:
            {"created": {...}, "updated": {...}}
        """
        import logging

        logger = logging.getLogger(__name__)
        created = {"whitelist": False, "temporal": False, "blacklist": False}
        updated = {"whitelist": False, "temporal": False, "blacklist": False}

        for rule_type, spec in FIREWALL_RULE_SPECS.items():
            description = FIREWALL_RULE_DESCRIPTIONS[rule_type]
            rule_uuid, rule_data = self._find_rule_by_description(description)
            alias_name = spec["alias_name"]

            if not rule_uuid:
                try:
                    self._create_firewall_rule(
                        alias_name=alias_name,
                        description=description,
                        action=spec["action"],
                        interface=interface,
                        sequence=spec["sequence"],
                        enabled=bool(spec.get("enabled", True)),
                    )
                    created[rule_type] = True
                except Exception as exc:
                    logger.warning(
                        "No se pudo crear la regla %s (%s): %s",
                        rule_type,
                        description,
                        exc,
                    )
                continue

            if not rule_data:
                continue

            current_action = self._extract_selected_key(rule_data.get("action")) or ""
            current_interface = (
                self._extract_selected_value(rule_data.get("interface")) or ""
            )
            current_source = self._extract_rule_scalar(rule_data.get("source_net")) or ""
            current_sequence_raw = self._extract_rule_scalar(rule_data.get("sequence"))
            try:
                current_sequence = int(current_sequence_raw) if current_sequence_raw else None
            except ValueError:
                current_sequence = None

            needs_update = (
                current_action.lower() != spec["action"]
                or current_interface.lower() != interface.lower()
                or current_source != alias_name
                or current_sequence != spec["sequence"]
            )

            if not needs_update:
                continue

            try:
                current_rule = self.get_firewall_rule(rule_uuid)
                if not current_rule:
                    current_rule = {}
                self._update_firewall_rule(
                    rule_uuid,
                    current_rule,
                    alias_name=alias_name,
                    description=description,
                    action=spec["action"],
                    interface=interface,
                    sequence=spec["sequence"],
                )
                updated[rule_type] = True
            except Exception as exc:
                logger.warning(
                    "No se pudo actualizar la regla %s (%s): %s",
                    rule_type,
                    description,
                    exc,
                )

        return {"created": created, "updated": updated}

    def list_firewall_rules(self) -> List[Dict[str, object]]:
        """Lista las reglas de firewall gestionadas por Mimosa."""
        try:
            response = self._request("GET", "/api/firewall/filter/get")
            data = response.json()
            rules_dict = data.get("filter", {}).get("rules", {}).get("rule", {})

            mimosa_rules = []
            for uuid, rule in rules_dict.items():
                # Obtener descripción
                desc = rule.get("description", "")
                if isinstance(desc, dict):
                    desc = desc.get("value", "")

                # Solo reglas de Mimosa
                if desc in FIREWALL_RULE_DESCRIPTIONS.values():
                    # Extraer valores útiles
                    enabled = rule.get("enabled", "0")

                    # Obtener acción seleccionada
                    action_dict = rule.get("action", {})
                    action = "unknown"
                    if isinstance(action_dict, dict):
                        for key, value in action_dict.items():
                            if isinstance(value, dict) and value.get("selected") == 1:
                                action = key.lower()
                                break

                    # Obtener interfaz seleccionada
                    interface_dict = rule.get("interface", {})
                    interface = "unknown"
                    if isinstance(interface_dict, dict):
                        for key, value in interface_dict.items():
                            if isinstance(value, dict) and value.get("selected") == 1:
                                interface = value.get("value", key)
                                break

                    # Obtener origen
                    source = rule.get("source_net", "")
                    if isinstance(source, dict):
                        source = source.get("value", "")

                    # Determinar el tipo de regla basándose en la descripción
                    rule_type = "unknown"
                    if "Whitelist" in desc:
                        rule_type = "whitelist"
                    elif "Temporal" in desc:
                        rule_type = "temporal"
                    elif "blacklist" in desc.lower():
                        rule_type = "blacklist"

                    mimosa_rules.append({
                        "uuid": uuid,
                        "description": desc,
                        "enabled": enabled == "1",
                        "action": action,
                        "interface": interface,
                        "source_net": source,
                        "type": rule_type
                    })

            return mimosa_rules
        except httpx.HTTPError:
            return []

    def get_firewall_rule(self, rule_uuid: str) -> Dict[str, object]:
        """Obtiene los detalles de una regla de firewall específica."""
        try:
            response = self._request("GET", f"/api/firewall/filter/getRule/{rule_uuid}")
            data = response.json()
            return data.get("rule", {})
        except httpx.HTTPError:
            return {}

    def toggle_firewall_rule(self, rule_uuid: str, enabled: bool) -> bool:
        """Habilita o deshabilita una regla de firewall.

        Usa el endpoint toggleRule de OPNsense que es más simple y confiable
        que setRule para cambiar solo el estado enabled/disabled.
        """
        import logging
        logger = logging.getLogger(__name__)

        try:
            # Verificar que la regla existe
            current_rule = self.get_firewall_rule(rule_uuid)
            if not current_rule:
                logger.error(f"Rule {rule_uuid} not found")
                return False

            # Obtener estado actual
            current_enabled = current_rule.get("enabled", {})
            if isinstance(current_enabled, dict):
                current_enabled = current_enabled.get("selected", "0")

            logger.info(f"Rule {rule_uuid} current status: {current_enabled}, target: {enabled}")

            # Determinar si necesita toggle
            is_currently_enabled = str(current_enabled) == "1"
            needs_toggle = is_currently_enabled != enabled

            if not needs_toggle:
                logger.info(f"Rule already in desired state, no toggle needed")
                return True

            # Usar toggleRule endpoint de OPNsense
            response = self._request("POST", f"/api/firewall/filter/toggleRule/{rule_uuid}")
            result = response.json()

            logger.info(f"ToggleRule response: {result}")

            if result.get("result") == "saved" or result.get("changed") is True:
                # Aplicar cambios si está configurado
                if self._apply_changes:
                    logger.info("Applying changes to firewall")
                    self.apply_changes()
                return True

            logger.warning(f"ToggleRule did not succeed: {result}")
            return False
        except httpx.HTTPError as e:
            logger.error(f"HTTPError toggling rule: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error toggling rule: {e}")
            return False

    def delete_firewall_rule(self, rule_uuid: str) -> bool:
        """Elimina una regla de firewall."""
        import logging
        logger = logging.getLogger(__name__)

        try:
            # Verificar que la regla existe
            current_rule = self.get_firewall_rule(rule_uuid)
            if not current_rule:
                logger.error(f"Rule {rule_uuid} not found")
                return False

            logger.info(f"Deleting rule {rule_uuid}")

            # Eliminar regla usando delRule endpoint
            response = self._request("POST", f"/api/firewall/filter/delRule/{rule_uuid}")
            result = response.json()

            logger.info(f"DelRule response: {result}")

            if result.get("result") == "deleted":
                # Aplicar cambios si está configurado
                if self._apply_changes:
                    logger.info("Applying changes to firewall")
                    self.apply_changes()
                return True

            logger.warning(f"DelRule did not succeed: {result}")
            return False
        except httpx.HTTPError as e:
            logger.error(f"HTTPError deleting rule: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting rule: {e}")
            return False

    @property
    def _status_endpoint(self) -> str:
        return "/api/core/firmware/status"

    @property
    def _apply_endpoint(self) -> str:
        return "/api/firewall/filter/apply"

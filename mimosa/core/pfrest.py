"""Cliente para pfSense usando el paquete pfrest."""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional
import ipaddress
import os
from urllib.parse import urlparse

import httpx

from mimosa.core.api import FirewallGateway
from mimosa.core.sense import (
    BLACKLIST_ALIAS_NAME,
    FIREWALL_RULE_DESCRIPTIONS,
    FIREWALL_RULE_SPECS,
    MIMOSA_IP_ALIAS_NAME,
    PORT_ALIAS_NAMES,
    TEMPORAL_ALIAS_NAME,
    WHITELIST_ALIAS_NAME,
)


class PFSenseRestClient(FirewallGateway):
    """Cliente básico para pfSense con pfrest."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        *,
        verify_ssl: bool = True,
        timeout: float = 10.0,
        apply_changes: bool = True,
        client: Optional[httpx.Client] = None,
    ) -> None:
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else base_url
        self.base_url = base.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.temporal_alias = TEMPORAL_ALIAS_NAME
        self.blacklist_alias = BLACKLIST_ALIAS_NAME
        self.whitelist_alias = WHITELIST_ALIAS_NAME
        self.ports_alias_names = dict(PORT_ALIAS_NAMES)
        self._apply_changes = apply_changes
        self._explicit_root = bool(parsed.path and parsed.path.strip("/"))
        self.api_root = f"/{parsed.path.strip('/')}" if parsed.path.strip("/") else "/api/v2"
        self._client = client or httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_ssl,
            headers=self._build_headers(),
        )

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _build_url(self, path: str) -> str:
        suffix = path if path.startswith("/") else f"/{path}"
        return f"{self.api_root.rstrip('/')}{suffix}"

    def _request(self, method: str, path: str, *, params: Dict[str, object] | None = None, json: Dict[str, object] | None = None) -> httpx.Response:
        response = self._client.request(method, self._build_url(path), params=params, json=json)
        response.raise_for_status()
        return response

    def _extract_data(self, payload: object) -> object:
        if isinstance(payload, dict):
            for key in ("data", "response", "items"):
                if key in payload:
                    return payload[key]
        return payload

    def apply_changes(self) -> None:
        try:
            self._request("POST", "/firewall/apply")
        except httpx.HTTPError:
            # Algunos despliegues no requieren apply explícito.
            return

    def check_connection(self) -> None:
        try:
            self._request("GET", "/firewall/aliases")
            return
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404 and not self._explicit_root:
                self._detect_api_root()
                self._request("GET", "/firewall/aliases")
                return
        self.list_blocks()

    def _detect_api_root(self) -> None:
        candidates = ["/api/v2", "/pfrest/api/v2", "/restapi/v2"]
        for candidate in candidates:
            self.api_root = candidate
            try:
                self._request("GET", "/firewall/aliases")
                return
            except httpx.HTTPError:
                continue

    def get_status(self) -> Dict[str, object]:
        status: Dict[str, object] = {
            "available": False,
            "alias_ready": False,
            "alias_created": False,
            "applied_changes": False,
            "firewall_rules_ready": False,
            "firewall_rules_created": False,
            "firewall_rules_updated": False,
            "nat_ready": False,
            "nat_created": False,
            "nat_updated": False,
        }
        try:
            self.check_connection()
        except httpx.HTTPError as exc:
            status["error"] = str(exc)
            return status
        status["available"] = True

        created = {}
        mimosa_ip_value = os.getenv("MIMOSA_IP")
        mimosa_ip_created = False
        if mimosa_ip_value:
            mimosa_ip_created = self._ensure_alias_exists(
                MIMOSA_IP_ALIAS_NAME,
                "host",
                "Mimosa host",
                addresses=[mimosa_ip_value],
            )
        created["whitelist"] = self._ensure_alias_exists(
            self.whitelist_alias, "host", "Mimosa whitelist"
        )
        created["temporal"] = self._ensure_alias_exists(
            self.temporal_alias, "host", "Mimosa temporal blocks"
        )
        created["blacklist"] = self._ensure_alias_exists(
            self.blacklist_alias, "host", "Mimosa blacklist"
        )
        status["alias_ready"] = True
        status["alias_created"] = any(created.values())
        status["alias_details"] = {
            "whitelist": {"name": self.whitelist_alias, "created": created["whitelist"]},
            "temporal": {"name": self.temporal_alias, "created": created["temporal"]},
            "blacklist": {"name": self.blacklist_alias, "created": created["blacklist"]},
        }
        if mimosa_ip_value:
            status["alias_details"]["mimosa_host"] = {
                "name": MIMOSA_IP_ALIAS_NAME,
                "created": mimosa_ip_created,
                "value": mimosa_ip_value,
            }

        ports_status: Dict[str, Dict[str, bool]] = {}
        for protocol, alias_name in self.ports_alias_names.items():
            ports_status[protocol] = {
                "ready": True,
                "created": self._ensure_alias_exists(
                    alias_name, "port", "Mimosa published ports"
                ),
            }
        status["ports_alias_status"] = ports_status
        status["ports_alias_ready"] = all(entry["ready"] for entry in ports_status.values())
        status["ports_alias_created"] = any(entry["created"] for entry in ports_status.values())

        try:
            rules_status = self._ensure_firewall_rules_exist()
            status["firewall_rules_ready"] = True
            status["firewall_rules_created"] = any(rules_status["created"].values())
            status["firewall_rules_updated"] = any(rules_status["updated"].values())
            status["firewall_rules_details"] = rules_status
        except httpx.HTTPError:
            status["firewall_rules_ready"] = False
            status["firewall_rules_created"] = False

        if mimosa_ip_value:
            try:
                nat_status = self._ensure_nat_port_forwards_exist(mimosa_ip_value)
                status["nat_ready"] = True
                status["nat_created"] = any(nat_status["created"].values())
                status["nat_updated"] = any(nat_status["updated"].values())
                status["nat_details"] = nat_status
            except httpx.HTTPError:
                status["nat_ready"] = False
                status["nat_created"] = False

        should_apply = (
            status["alias_created"]
            or status["ports_alias_created"]
            or status.get("firewall_rules_created", False)
            or status.get("firewall_rules_updated", False)
            or status.get("nat_created", False)
            or status.get("nat_updated", False)
        )
        if should_apply:
            if self._apply_changes:
                self.apply_changes()
                status["applied_changes"] = True

        return status

    def _list_port_forwards(self) -> List[Dict[str, object]]:
        response = self._request("GET", "/firewall/nat/port_forwards")
        data = self._extract_data(response.json())
        if isinstance(data, list):
            return data
        return []

    def _list_all_firewall_rules(self) -> List[Dict[str, object]]:
        response = self._request("GET", "/firewall/rules")
        data = self._extract_data(response.json())
        if isinstance(data, list):
            return data
        return []

    def _find_port_forward(self, description: str, protocol: str) -> Optional[Dict[str, object]]:
        for entry in self._list_port_forwards():
            if entry.get("descr") == description and entry.get("protocol") == protocol:
                return entry
        return None

    def _ensure_nat_port_forwards_exist(self, mimosa_ip_value: str) -> Dict[str, Dict[str, bool]]:
        created = {"tcp": False, "udp": False}
        updated = {"tcp": False, "udp": False}
        destination = "wan:ip"
        interface = "wan"
        source = "any"
        ipprotocol = "inet"
        target = MIMOSA_IP_ALIAS_NAME if mimosa_ip_value else ""
        force_associated_rule = {"tcp": False, "udp": False}
        found_associated_rule = {"tcp": False, "udp": False}

        if target:
            alias_to_protocol = {alias: proto for proto, alias in self.ports_alias_names.items()}
            for rule in self._list_all_firewall_rules():
                destination_port = rule.get("destination_port")
                if destination_port not in alias_to_protocol:
                    continue
                associated_rule_id = rule.get("associated_rule_id")
                if not (isinstance(associated_rule_id, str) and associated_rule_id.startswith("nat_")):
                    continue
                destination_value = rule.get("destination")
                protocol_hint = alias_to_protocol.get(destination_port)
                if protocol_hint:
                    found_associated_rule[protocol_hint] = True
                if destination_value == target:
                    continue
                protocol = str(rule.get("protocol") or "").lower()
                if protocol == "tcp/udp":
                    force_associated_rule["tcp"] = True
                    force_associated_rule["udp"] = True
                elif protocol in force_associated_rule:
                    force_associated_rule[protocol] = True
                rule_id = rule.get("id")
                if rule_id is None:
                    continue
                self._request("DELETE", "/firewall/rule", params={"id": rule_id})

            for protocol in found_associated_rule:
                if not found_associated_rule[protocol]:
                    force_associated_rule[protocol] = True

        for protocol, alias_name in self.ports_alias_names.items():
            description = f"Mimosa NAT {protocol.upper()}"
            existing = self._find_port_forward(description, protocol)
            payload = {
                "interface": interface,
                "ipprotocol": ipprotocol,
                "protocol": protocol,
                "source": source,
                "source_port": None,
                "destination": destination,
                "destination_port": alias_name,
                "target": target,
                "local_port": alias_name,
                "disabled": False,
                "nordr": False,
                "nosync": False,
                "descr": description,
                "natreflection": None,
            }

            if not existing:
                payload["associated_rule_id"] = "new"
                self._request("POST", "/firewall/nat/port_forward", json=payload)
                created[protocol] = True
                continue

            entry_id = existing.get("id")
            if entry_id is None:
                continue
            needs_update = (
                existing.get("interface") != interface
                or existing.get("ipprotocol") != ipprotocol
                or existing.get("destination") != destination
                or existing.get("destination_port") != alias_name
                or existing.get("target") != target
                or existing.get("local_port") != alias_name
                or bool(existing.get("disabled", False)) is True
            )
            if force_associated_rule.get(protocol):
                params = {"id": entry_id}
                if self._apply_changes:
                    params["apply"] = "true"
                self._request("DELETE", "/firewall/nat/port_forward", params=params)
                payload["associated_rule_id"] = "new"
                self._request("POST", "/firewall/nat/port_forward", json=payload)
                updated[protocol] = True
                continue
            if not needs_update:
                continue
            payload["id"] = entry_id
            self._request(
                "PATCH",
                "/firewall/nat/port_forward",
                params={"id": entry_id},
                json=payload,
            )
            updated[protocol] = True

        return {"created": created, "updated": updated}

    def _ensure_firewall_rules_exist(self, interface: str = "wan") -> Dict[str, Dict[str, bool]]:
        created = {"whitelist": False, "temporal": False, "blacklist": False}
        updated = {"whitelist": False, "temporal": False, "blacklist": False}

        existing = self.list_firewall_rules()
        by_description = {rule["description"]: rule for rule in existing if rule.get("description")}

        for rule_type, spec in FIREWALL_RULE_SPECS.items():
            description = FIREWALL_RULE_DESCRIPTIONS[rule_type]
            alias_name = spec["alias_name"]
            action = spec["action"]
            disabled = not bool(spec.get("enabled", True))
            current = by_description.get(description)

            if not current:
                payload = {
                    "type": action,
                    "interface": [interface],
                    "ipprotocol": "inet",
                    "protocol": "tcp/udp",
                    "source": alias_name,
                    "destination": "any",
                    "descr": description,
                    "disabled": disabled,
                    "log": True,
                    "quick": True,
                    "direction": "in",
                }
                self._request("POST", "/firewall/rule", json=payload)
                created[rule_type] = True
                continue

            needs_update = (
                str(current.get("action", "")).lower() != str(action).lower()
                or str(current.get("source_net", "")) != alias_name
                or str(current.get("interface", "")).lower() != str(interface).lower()
            )
            if not needs_update:
                continue

            rule_id = current.get("uuid")
            if not rule_id:
                continue
            current_enabled = bool(current.get("enabled", True))
            payload = {
                "id": rule_id,
                "type": action,
                "interface": [interface],
                "ipprotocol": "inet",
                "protocol": "tcp/udp",
                "source": alias_name,
                "destination": "any",
                "descr": description,
                "disabled": not current_enabled,
                "log": True,
                "quick": True,
                "direction": "in",
            }
            self._request("PATCH", "/firewall/rule", params={"id": rule_id}, json=payload)
            updated[rule_type] = True

        return {"created": created, "updated": updated}

    def _list_aliases(self) -> List[Dict[str, object]]:
        response = self._request("GET", "/firewall/aliases")
        data = self._extract_data(response.json())
        if isinstance(data, list):
            return data
        return []

    def _find_alias(self, name: str) -> Optional[Dict[str, object]]:
        for alias in self._list_aliases():
            if alias.get("name") == name:
                return alias
        return None

    def _alias_id(self, alias: Dict[str, object]) -> Optional[str]:
        for key in ("id", "aliasid", "uuid"):
            if key in alias:
                return str(alias[key])
        return None

    def _ensure_alias_exists(
        self, name: str, alias_type: str, description: str, addresses: Optional[List[str]] = None
    ) -> bool:
        existing = self._find_alias(name)
        if existing:
            if existing.get("type") != alias_type and name != self.whitelist_alias:
                current = self._parse_alias_addresses(existing)
                self._update_alias(existing, alias_type=alias_type, addresses=current)
            if addresses:
                current = self._parse_alias_addresses(existing)
                desired = [addr for addr in addresses if addr]
                if sorted(current) != sorted(desired):
                    self._update_alias_addresses(existing, desired)
            return False
        payload = {
            "name": name,
            "type": alias_type,
            "address": addresses or [],
            "detail": ["Mimosa"] * len(addresses or []),
            "descr": description,
            "enabled": True,
        }
        params = {"apply": "true"} if self._apply_changes else None
        self._request("POST", "/firewall/alias", params=params, json=payload)
        return True

    def _update_alias(
        self,
        alias: Dict[str, object],
        *,
        alias_type: Optional[str] = None,
        addresses: Optional[List[str]] = None,
    ) -> None:
        alias_id = self._alias_id(alias)
        if not alias_id:
            raise RuntimeError("Alias sin ID en pfrest")
        payload: Dict[str, object] = {"id": alias_id}
        if alias_type:
            payload["type"] = alias_type
        if addresses is not None:
            payload["address"] = addresses
            payload["detail"] = ["Mimosa"] * len(addresses)
        params = {"id": alias_id}
        if self._apply_changes:
            params["apply"] = "true"
        self._request("PATCH", "/firewall/alias", params=params, json=payload)
        if self._apply_changes:
            self.apply_changes()

    def _parse_alias_addresses(self, alias: Dict[str, object]) -> List[str]:
        addresses = alias.get("address") or alias.get("addresses")
        if isinstance(addresses, list):
            return [str(entry).strip() for entry in addresses if str(entry).strip()]
        if isinstance(addresses, str):
            return [item.strip() for item in addresses.split() if item.strip()]
        return []

    def _update_alias_addresses(
        self, alias: Dict[str, object], addresses: List[str]
    ) -> None:
        self._update_alias(alias, addresses=addresses)

    def _is_cidr(self, value: str) -> bool:
        if "/" not in value:
            return False
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _select_whitelist_alias_type(self, entries: List[str]) -> str:
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            if self._is_cidr(entry):
                return "network"
        return "host"

    def _normalize_whitelist_entries(self, entries: List[str], alias_type: str) -> List[str]:
        normalized: List[str] = []
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            if alias_type == "network" and self._is_ip(entry):
                normalized.append(f"{entry}/32")
                continue
            normalized.append(entry)
        return sorted(set(normalized))

    def _list_alias_values(self, alias_name: str) -> List[str]:
        alias = self._find_alias(alias_name)
        if not alias:
            return []
        return self._parse_alias_addresses(alias)

    def _block_ip_backend(self, ip: str, alias_name: str) -> None:
        alias = self._find_alias(alias_name)
        if not alias:
            alias_type = "host"
            if alias_name == self.whitelist_alias:
                alias_type = self._select_whitelist_alias_type([ip])
            self._ensure_alias_exists(alias_name, alias_type, "Mimosa alias")
            alias = self._find_alias(alias_name)
        if not alias:
            raise RuntimeError(f"No se encontró el alias {alias_name}")
        addresses = self._parse_alias_addresses(alias)
        if ip not in addresses:
            addresses.append(ip)
            self._update_alias_addresses(alias, addresses)

    def _unblock_ip_backend(self, ip: str, alias_name: str) -> None:
        alias = self._find_alias(alias_name)
        if not alias:
            return
        addresses = [entry for entry in self._parse_alias_addresses(alias) if entry != ip]
        self._update_alias_addresses(alias, addresses)

    def block_ip(self, ip: str, reason: str = "", duration_minutes: Optional[int] = None) -> None:
        self._block_ip_backend(ip, self.temporal_alias)
        self._flush_states_for_ip(ip)

    def unblock_ip(self, ip: str) -> None:
        self._unblock_ip_backend(ip, self.temporal_alias)

    def list_blocks(self) -> List[str]:
        return self._list_alias_values(self.temporal_alias)

    def get_ports(self) -> Dict[str, List[int]]:
        ports: Dict[str, List[int]] = {}
        for protocol, alias_name in self.ports_alias_names.items():
            entries = self._list_alias_values(alias_name)
            sanitized: List[int] = []
            for entry in entries:
                try:
                    port = int(entry)
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    sanitized.append(port)
            ports[protocol] = sorted(set(sanitized))
        return ports

    def set_ports_alias(self, protocol: str, ports: Iterable[int]) -> None:
        alias_name = self.ports_alias_names.get(protocol.lower(), self.ports_alias_names["tcp"])
        alias = self._find_alias(alias_name)
        if not alias:
            self._ensure_alias_exists(alias_name, "port", "Mimosa published ports")
            alias = self._find_alias(alias_name)
        if not alias:
            raise RuntimeError(f"No se encontró el alias {alias_name}")
        payload_ports = [str(port) for port in sorted(set(int(p) for p in ports if 1 <= int(p) <= 65535))]
        self._update_alias_addresses(alias, payload_ports)

    def list_blacklist(self) -> List[str]:
        return self._list_alias_values(self.blacklist_alias)

    def list_whitelist(self) -> List[str]:
        return self._list_alias_values(self.whitelist_alias)

    def add_to_blacklist(self, ip: str, reason: str = "") -> None:
        self._block_ip_backend(ip, self.blacklist_alias)

    def add_to_whitelist(self, ip: str, reason: str = "") -> None:
        alias = self._find_alias(self.whitelist_alias)
        current = self._parse_alias_addresses(alias) if alias else []
        desired = current + [ip]
        alias_type = self._select_whitelist_alias_type(desired)
        desired = self._normalize_whitelist_entries(desired, alias_type)
        if not alias:
            self._ensure_alias_exists(
                self.whitelist_alias, alias_type, "Mimosa whitelist", addresses=desired
            )
            return
        if alias.get("type") != alias_type:
            self._update_alias(alias, alias_type=alias_type, addresses=desired)
            return
        if sorted(current) != sorted(desired):
            self._update_alias_addresses(alias, desired)

    def remove_from_blacklist(self, ip: str) -> None:
        self._unblock_ip_backend(ip, self.blacklist_alias)

    def remove_from_whitelist(self, ip: str) -> None:
        self._unblock_ip_backend(ip, self.whitelist_alias)

    def block_rule_stats(self) -> Dict[str, object]:
        raise NotImplementedError

    def flush_states(self) -> None:
        try:
            self._request("DELETE", "/firewall/states", params={"source": "0.0.0.0/0"})
            self._request("DELETE", "/firewall/states", params={"destination": "0.0.0.0/0"})
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"No se pudo limpiar estados: {exc}") from exc

    def _flush_states_for_ip(self, ip: str) -> None:
        try:
            self._request("DELETE", "/firewall/states", params={"source": ip})
            self._request("DELETE", "/firewall/states", params={"destination": ip})
        except httpx.HTTPStatusError:
            # No interrumpir el bloqueo si falla el flush selectivo.
            return

    def list_firewall_rules(self) -> List[Dict[str, object]]:
        response = self._request("GET", "/firewall/rules")
        data = self._extract_data(response.json())
        if not isinstance(data, list):
            return []

        rules: List[Dict[str, object]] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            description = entry.get("descr") or ""
            if description not in FIREWALL_RULE_DESCRIPTIONS.values():
                continue
            rule_id = entry.get("id")
            action = entry.get("type") or entry.get("action") or "unknown"
            interface = entry.get("interface") or []
            if isinstance(interface, list) and interface:
                interface_value = str(interface[0])
            elif isinstance(interface, str):
                interface_value = interface
            else:
                interface_value = "unknown"
            source = entry.get("source") or ""
            rule_type = "unknown"
            if source == WHITELIST_ALIAS_NAME or "Whitelist" in description:
                rule_type = "whitelist"
            elif source == TEMPORAL_ALIAS_NAME or "Temporal" in description:
                rule_type = "temporal"
            elif source == BLACKLIST_ALIAS_NAME or "blacklist" in description.lower():
                rule_type = "blacklist"

            rules.append(
                {
                    "uuid": str(rule_id) if rule_id is not None else "",
                    "description": description,
                    "enabled": not bool(entry.get("disabled", False)),
                    "action": str(action).lower(),
                    "interface": interface_value,
                    "source_net": source,
                    "type": rule_type,
                }
            )

        return rules

    def get_firewall_rule(self, rule_uuid: str) -> Dict[str, object]:
        response = self._request("GET", "/firewall/rule", params={"id": rule_uuid})
        data = self._extract_data(response.json())
        if isinstance(data, dict):
            return data
        return {}

    def toggle_firewall_rule(self, rule_uuid: str, enabled: bool) -> bool:
        payload = {"id": rule_uuid, "disabled": not enabled}
        self._request("PATCH", "/firewall/rule", params={"id": rule_uuid}, json=payload)
        if self._apply_changes:
            self.apply_changes()
        return True

    def delete_firewall_rule(self, rule_uuid: str) -> bool:
        self._request("DELETE", "/firewall/rule", params={"id": rule_uuid})
        if self._apply_changes:
            self.apply_changes()
        return True

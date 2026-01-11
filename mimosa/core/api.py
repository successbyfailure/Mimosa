"""API interna del núcleo de Mimosa.

Expone endpoints internos para interacción entre módulos (web, proxy, bot).
"""
from datetime import datetime
from typing import Dict, List, Optional

from mimosa.core.blocking import BlockEntry, BlockManager
from pydantic import BaseModel


class BlockRequest(BaseModel):
    """Solicitud para bloquear un origen malicioso."""

    source_ip: str
    reason: str
    duration_minutes: int | None = None


class BlockResponse(BaseModel):
    """Respuesta de una acción de bloqueo."""

    blocked: bool
    message: str


class CoreAPI:
    """Punto de entrada para acciones de seguridad compartidas."""

    def __init__(
        self,
        firewall_gateway: "FirewallGateway",
        block_manager: Optional[BlockManager] = None,
    ):
        self.firewall_gateway = firewall_gateway
        self.block_manager = block_manager or BlockManager()

    def register_block(self, request: BlockRequest) -> BlockResponse:
        """Registra un bloqueo de IP usando la integración de firewall."""

        entry = self.block_manager.add(
            request.source_ip, request.reason, request.duration_minutes
        )
        sync_with_firewall = self.block_manager.should_sync(request.source_ip)
        duration_minutes = None
        if entry.expires_at:
            delta = entry.expires_at - datetime.utcnow()
            duration_minutes = max(int(delta.total_seconds() // 60), 1)
        if sync_with_firewall:
            self.firewall_gateway.block_ip(
                request.source_ip, request.reason, duration_minutes=duration_minutes
            )
        expiry = (
            f" expira {entry.expires_at.isoformat(timespec='seconds')}"
            if entry.expires_at
            else ""
        )
        message_suffix = " (solo base de datos)" if not sync_with_firewall else ""
        return BlockResponse(
            blocked=True,
            message=f"IP {request.source_ip} bloqueada{expiry}{message_suffix}",
        )

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:
        """Atajo para bloquear sin crear manualmente un :class:`BlockRequest`."""

        self.register_block(
            BlockRequest(
                source_ip=ip, reason=reason, duration_minutes=duration_minutes
            )
        )

    def unblock_ip(self, ip: str) -> None:
        """Elimina un bloqueo tanto del firewall como del registro local."""

        self.block_manager.remove(ip)
        self.firewall_gateway.unblock_ip(ip)

    def list_blocks(self) -> List[BlockEntry]:
        """Devuelve la lista actual de IPs bloqueadas con su metadata."""

        return self.block_manager.list()


class FirewallGateway:
    """Interfaz mínima requerida por el núcleo para operar con el firewall."""

    def apply_changes(self) -> None:
        """Aplica los cambios pendientes en el firewall remoto."""

        raise NotImplementedError

    def get_status(self) -> dict:
        """Devuelve información básica de disponibilidad y preparación."""

        self.check_connection()
        return {"available": True}

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:
        raise NotImplementedError

    def list_blocks(self) -> List[str]:
        raise NotImplementedError

    def unblock_ip(self, ip: str) -> None:
        raise NotImplementedError

    def ensure_ready(self) -> None:
        """Prepara los recursos necesarios para operar (alias, tablas, etc.).

        La implementación por defecto reutiliza :meth:`get_status` para validar
        conectividad. Integraciones concretas pueden sobreescribir este método
        para crear automáticamente la infraestructura necesaria.
        """

        self.get_status()

    def check_connection(self) -> None:
        """Verifica conectividad con el firewall remoto.

        La implementación por defecto reutiliza ``list_blocks`` para evitar
        duplicar llamadas en clientes sencillos. Integraciones concretas
        pueden sobrescribir este método para usar un endpoint de healthcheck
        que no dependa de que el alias de bloqueos exista previamente.
        """

        self.list_blocks()

    def get_ports(self) -> Dict[str, List[int]]:
        """Devuelve el contenido de los alias de puertos publicados."""

        raise NotImplementedError

    def list_blacklist(self) -> List[str]:
        """Devuelve las IPs bloqueadas de forma permanente."""

        raise NotImplementedError

    def list_whitelist(self) -> List[str]:
        """Devuelve las IPs permitidas de forma permanente."""

        raise NotImplementedError

    def add_to_blacklist(self, ip: str, reason: str = "") -> None:
        """Añade una IP a la lista negra permanente."""

        raise NotImplementedError

    def add_to_whitelist(self, ip: str, reason: str = "") -> None:
        """Añade una IP a la whitelist permanente."""

        raise NotImplementedError

    def remove_from_blacklist(self, ip: str) -> None:
        """Elimina una IP de la lista negra permanente."""

        raise NotImplementedError

    def remove_from_whitelist(self, ip: str) -> None:
        """Elimina una IP de la whitelist permanente."""

        raise NotImplementedError

    def block_rule_stats(self) -> Dict[str, object]:
        """Devuelve estadísticas de reglas de bloqueo en el firewall."""

        raise NotImplementedError

    def flush_states(self) -> None:
        """Fuerza un flush de estados en el firewall remoto."""

        raise NotImplementedError

    def list_firewall_rules(self) -> List[Dict[str, object]]:
        """Lista las reglas de firewall gestionadas por Mimosa."""

        raise NotImplementedError

    def get_firewall_rule(self, rule_uuid: str) -> Dict[str, object]:
        """Obtiene los detalles de una regla de firewall específica."""

        raise NotImplementedError

    def toggle_firewall_rule(self, rule_uuid: str, enabled: bool) -> bool:
        """Habilita o deshabilita una regla de firewall.

        Args:
            rule_uuid: UUID de la regla
            enabled: True para habilitar, False para deshabilitar

        Returns:
            True si se aplicó el cambio exitosamente
        """

        raise NotImplementedError

    def delete_firewall_rule(self, rule_uuid: str) -> bool:
        """Elimina una regla de firewall.

        Args:
            rule_uuid: UUID de la regla a eliminar

        Returns:
            True si se eliminó exitosamente
        """

        raise NotImplementedError

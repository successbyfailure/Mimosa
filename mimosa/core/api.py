"""API interna del núcleo de Mimosa.

Expone endpoints internos para interacción entre módulos (web, proxy, bot).
"""
from typing import List, Optional

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
        self.firewall_gateway.block_ip(
            request.source_ip, request.reason, duration_minutes=request.duration_minutes
        )
        expiry = (
            f" expira {entry.expires_at.isoformat(timespec='seconds')}"
            if entry.expires_at
            else ""
        )
        return BlockResponse(
            blocked=True, message=f"IP {request.source_ip} bloqueada{expiry}"
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

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:
        raise NotImplementedError

    def list_blocks(self) -> List[str]:
        raise NotImplementedError

    def unblock_ip(self, ip: str) -> None:
        raise NotImplementedError

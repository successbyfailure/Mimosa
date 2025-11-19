"""API interna del núcleo de Mimosa.

Expone endpoints internos para interacción entre módulos (web, proxy, bot).
"""
from typing import List
from pydantic import BaseModel


class BlockRequest(BaseModel):
    """Solicitud para bloquear un origen malicioso."""

    source_ip: str
    reason: str


class BlockResponse(BaseModel):
    """Respuesta de una acción de bloqueo."""

    blocked: bool
    message: str


class CoreAPI:
    """Punto de entrada para acciones de seguridad compartidas."""

    def __init__(self, firewall_gateway: "FirewallGateway"):
        self.firewall_gateway = firewall_gateway

    def register_block(self, request: BlockRequest) -> BlockResponse:
        """Registra un bloqueo de IP usando la integración de firewall."""

        self.firewall_gateway.block_ip(request.source_ip, request.reason)
        return BlockResponse(blocked=True, message=f"IP {request.source_ip} bloqueada")

    def list_blocks(self) -> List[str]:
        """Devuelve la lista actual de IPs bloqueadas."""

        return self.firewall_gateway.list_blocks()


class FirewallGateway:
    """Interfaz mínima requerida por el núcleo para operar con el firewall."""

    def block_ip(self, ip: str, reason: str) -> None:
        raise NotImplementedError

    def list_blocks(self) -> List[str]:
        raise NotImplementedError

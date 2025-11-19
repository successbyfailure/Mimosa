"""Endpoint que actúa como reverse proxy controlado."""
from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/trap")
async def trap(request: Request) -> dict:
    """Recibe peticiones del reverse proxy para inspección previa."""

    body = await request.body()
    # En una versión completa se evaluaría la petición antes de reenviarla.
    return {"received": len(body)}

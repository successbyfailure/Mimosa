"""Endpoint que actúa como reverse proxy controlado."""
import logging
from datetime import datetime
from typing import Dict, List

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from mimosa.core.offenses import OffenseStore

router = APIRouter()
logger = logging.getLogger(__name__)
forbidden_interface_attempts: List[Dict[str, str]] = []
offense_store = OffenseStore()


@router.post("/trap")
async def trap(request: Request) -> dict:
    """Recibe peticiones del reverse proxy para inspección previa."""

    body = await request.body()
    # En una versión completa se evaluaría la petición antes de reenviarla.
    return {"received": len(body)}


def _register_forbidden_interface_attempt(request: Request) -> Dict[str, str]:
    """Registra detalles básicos del intento de acceso a una interfaz prohibida."""

    attempt = {
        "host": request.headers.get("host", "desconocido"),
        "path": request.url.path,
        "method": request.method,
        "client": request.client.host if request.client else "desconocido",
        "user_agent": request.headers.get("user-agent", ""),
        "timestamp": datetime.utcnow().isoformat(),
    }
    forbidden_interface_attempts.append(attempt)
    logger.warning(
        "Intento de acceso a interfaz prohibida: host=%s path=%s method=%s client=%s",
        attempt["host"],
        attempt["path"],
        attempt["method"],
        attempt["client"],
    )
    offense_store.record(
        source_ip=attempt["client"],
        description="Acceso a interfaz prohibida detectado",
        severity="alto",
        host=attempt["host"],
        path=attempt["path"],
        user_agent=attempt["user_agent"],
        context={"method": attempt["method"]},
    )
    return attempt


@router.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
async def forbidden_interface(full_path: str, request: Request) -> JSONResponse:
    """Captura cualquier ruta y devuelve un 404 falso tras registrarla."""

    _register_forbidden_interface_attempt(request)
    return JSONResponse({"detail": "Not Found"}, status_code=404)

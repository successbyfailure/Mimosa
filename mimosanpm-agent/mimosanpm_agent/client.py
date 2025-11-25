from __future__ import annotations

import logging
from typing import Iterable

import httpx

LOGGER = logging.getLogger(__name__)


class MimosaClient:
    """Cliente HTTP para enviar alertas al endpoint de Mimosa."""

    def __init__(self, api_url: str, shared_secret: str) -> None:
        self.api_url = api_url
        self.shared_secret = shared_secret

    def send_alerts(self, alerts: Iterable[dict[str, object]]) -> int:
        payload = {"alerts": list(alerts)}
        if not payload["alerts"]:
            return 0

        response = httpx.post(
            self.api_url,
            headers={"X-Mimosa-Token": self.shared_secret},
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        body = response.json()
        accepted = body.get("accepted", body.get("processed", 0))
        LOGGER.info("Alertas enviadas: %s aceptadas", accepted)
        return int(accepted)

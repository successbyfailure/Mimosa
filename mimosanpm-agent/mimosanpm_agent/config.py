from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AgentSettings:
    """Configuración del agente MimosaNPM obtenida de variables de entorno."""

    api_url: str
    shared_secret: str
    log_glob: str
    poll_interval: float
    batch_size: int
    known_domains: set[str]
    state_path: Path

    @classmethod
    def from_env(cls) -> "AgentSettings":
        env = os.environ
        api_url = env.get("MIMOSA_API_URL")
        shared_secret = env.get("MIMOSA_SHARED_SECRET")
        if not api_url or not shared_secret:
            raise ValueError(
                "Debes configurar MIMOSA_API_URL y MIMOSA_SHARED_SECRET en el entorno"
            )

        return cls(
            api_url=api_url.rstrip("/"),
            shared_secret=shared_secret,
            log_glob=env.get("NPM_LOG_GLOB", "/data/logs/*_access.log"),
            poll_interval=float(env.get("POLL_INTERVAL", "5")),
            batch_size=int(env.get("BATCH_SIZE", "50")),
            known_domains={
                domain.strip().lower()
                for domain in env.get("KNOWN_DOMAINS", "").split(",")
                if domain.strip()
            },
            state_path=Path(env.get("STATE_PATH", "/state/mimosanpm-agent.json")),
        )

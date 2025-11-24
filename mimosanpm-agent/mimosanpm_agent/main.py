from __future__ import annotations

import logging
import signal
import sys
import time
from typing import Iterable

from mimosanpm_agent.client import MimosaClient
from mimosanpm_agent.config import AgentSettings
from mimosanpm_agent.log_watcher import LogFollower, AccessLogEntry, filter_unknown_domains

LOGGER = logging.getLogger(__name__)
RUNNING = True


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _stop(*_: object) -> None:
    global RUNNING
    RUNNING = False
    LOGGER.info("Saliendo del agente MimosaNPM...")


def _batch_alerts(entries: Iterable[AccessLogEntry], batch_size: int) -> Iterable[list[dict[str, object]]]:
    batch: list[dict[str, object]] = []
    for entry in entries:
        batch.append(entry.to_alert())
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def main() -> int:
    _setup_logging()
    settings = AgentSettings.from_env()
    follower = LogFollower(settings.log_glob, settings.state_path)
    client = MimosaClient(settings.api_url, settings.shared_secret)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    LOGGER.info("Arrancando agente MimosaNPM; leyendo %s", settings.log_glob)

    while RUNNING:
        entries = follower.read_new()
        filtered = filter_unknown_domains(entries, settings.known_domains)
        for batch in _batch_alerts(filtered, settings.batch_size):
            try:
                client.send_alerts(batch)
            except Exception as exc:  # noqa: BLE001 - se registra y continúa
                LOGGER.error("No se pudo enviar un lote de alertas: %s", exc)
        follower.persist_state()
        time.sleep(settings.poll_interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())

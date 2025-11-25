"""Configuración compartida para que las pruebas importen el paquete local."""

import os
from pathlib import Path
import sys
from typing import Iterable, Sequence

import anyio
import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_env_file(env_path: Path) -> None:
    if not env_path.is_file():
        return

    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        if line.startswith("export "):
            line = line[len("export ") :].lstrip()

        key, value = line.split("=", 1)
        value = value.strip()
        if key and value and (key not in os.environ or not os.environ[key]):
            os.environ[key] = value


def ensure_test_env(
    required_vars: Iterable[str], *, env_paths: Sequence[Path] | None = None
) -> bool:
    def _vars_ready() -> bool:
        return all(os.getenv(var) for var in required_vars)

    if _vars_ready():
        return True

    env_paths = env_paths or [Path(__file__).with_name(".env"), ROOT / ".env"]
    for env_path in env_paths:
        _load_env_file(env_path)
    if _vars_ready():
        return True

    return False


# Compatibilidad con httpx 0.28+ para clientes síncronos usados en TestClient.
if not hasattr(httpx.ASGITransport, "handle_request"):
    def _handle_request(self, request: httpx.Request) -> httpx.Response:
        return anyio.from_thread.run(self.handle_async_request, request)

    httpx.ASGITransport.handle_request = _handle_request  # type: ignore[attr-defined]

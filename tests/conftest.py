"""Configuración compartida para que las pruebas importen el paquete local."""

import os
from pathlib import Path
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_testing_env() -> None:
    env_path = Path(__file__).with_name("testing.env")
    if not env_path.is_file():
        return

    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        if key and key not in os.environ:
            os.environ[key] = value


def ensure_test_env(required_vars: Iterable[str]) -> bool:
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        _load_testing_env()

    return all(os.getenv(var) for var in required_vars)

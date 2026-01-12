"""Genera secretos recomendados y los guarda en .env."""
from __future__ import annotations

from pathlib import Path
import secrets
from typing import Dict, List


ENV_PATH = Path(".env")
KEYS = ("MIMOSA_SESSION_SECRET", "MIMOSA_PASSWORD_PEPPER")
PLACEHOLDER_VALUES = {"", "change-me"}


def _load_env_lines() -> List[str]:
    if not ENV_PATH.exists():
        return []
    return ENV_PATH.read_text(encoding="utf-8").splitlines()


def _parse_env(lines: List[str]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def _write_env(lines: List[str], updates: Dict[str, str]) -> None:
    existing = _parse_env(lines)
    merged = {**existing, **updates}
    output_lines: List[str] = []
    seen = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            output_lines.append(line)
            continue
        key, _value = stripped.split("=", 1)
        key = key.strip()
        if key in updates:
            output_lines.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
        output_lines.append(line)
        seen.add(key)
    for key in KEYS:
        if key not in seen:
            output_lines.append(f"{key}={merged[key]}")
    ENV_PATH.write_text("\n".join(output_lines) + "\n", encoding="utf-8")


def main() -> None:
    lines = _load_env_lines()
    existing = _parse_env(lines)
    updates: Dict[str, str] = {}
    for key in KEYS:
        current = (existing.get(key) or "").strip()
        if current in PLACEHOLDER_VALUES:
            updates[key] = (
                secrets.token_urlsafe(48)
                if key == "MIMOSA_SESSION_SECRET"
                else secrets.token_urlsafe(32)
            )
    if not updates:
        print("Secrets ya configurados; no se realizaron cambios.")
        return
    _write_env(lines, updates)
    print("Secrets guardados en .env:")
    for key, value in updates.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()

"""Parsing de logs en formato de diccionario simple."""
from typing import Dict, Iterable, List


def parse_auth_logs(lines: Iterable[str]) -> List[Dict[str, str]]:
    """Transforma líneas de log en un diccionario básico."""

    parsed: List[Dict[str, str]] = []
    for line in lines:
        parsed.append({"raw": line})
    return parsed

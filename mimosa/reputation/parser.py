"""Parsing de listas de reputación."""
from typing import Iterable, Set


def parse_blacklist(lines: Iterable[str]) -> Set[str]:
    """Filtra líneas y devuelve un conjunto de IPs válidas."""

    return {line.strip() for line in lines if line and not line.startswith("#")}

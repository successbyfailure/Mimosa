"""Modelos de dominio para ofensas y perfiles de IPs."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional


@dataclass
class OffenseRecord:
    """Representa una ofensa registrada en el sistema.

    Una ofensa es un evento de seguridad detectado por algún plugin
    (ProxyTrap, PortDetector, MimosaNPM, etc.) que indica actividad
    sospechosa de una IP.
    """

    id: int
    source_ip: str
    description: str
    severity: str
    created_at: datetime
    host: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    context: Optional[Dict[str, str]] = None


@dataclass
class IpProfile:
    """Información enriquecida de una IP conocida.

    Contiene metadata acumulada sobre una IP: geolocalización,
    DNS inverso, estadísticas de ofensas y bloqueos.
    """

    ip: str
    geo: Optional[str]
    whois: Optional[str]
    reverse_dns: Optional[str]
    first_seen: datetime
    last_seen: datetime
    enriched_at: Optional[datetime] = None
    offenses: int = 0
    blocks: int = 0


@dataclass
class WhitelistEntry:
    """Entrada en la lista blanca local.

    Las IPs/CIDRs en whitelist no serán bloqueadas automáticamente,
    incluso si generan ofensas.
    """

    id: int
    cidr: str
    note: Optional[str]
    created_at: datetime


__all__ = ["OffenseRecord", "IpProfile", "WhitelistEntry"]

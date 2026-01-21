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
    context: Optional[Dict[str, object]] = None
    plugin: Optional[str] = None
    event_id: Optional[str] = None
    event_type: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[str] = None
    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    firewall_id: Optional[str] = None
    rule_id: Optional[str] = None
    tags: Optional[str] = None
    ingested_at: Optional[datetime] = None
    created_at_epoch: Optional[int] = None


@dataclass
class IpProfile:
    """Información enriquecida de una IP conocida.

    Contiene metadata acumulada sobre una IP: geolocalización,
    DNS inverso, clasificación por tipo y estadísticas de ofensas y bloqueos.
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
    # Campos de clasificación de IP
    ip_type: Optional[str] = None  # datacenter, residential, governmental, etc.
    ip_type_confidence: Optional[float] = None  # 0.0 - 1.0
    ip_type_source: Optional[str] = None  # Fuente que determinó la clasificación
    ip_type_provider: Optional[str] = None  # Cloud provider específico (aws, gcp, etc.)
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    is_proxy: bool = False
    is_mobile: bool = False
    is_hosting: bool = False
    last_offense_at: Optional[datetime] = None
    last_block_at: Optional[datetime] = None
    country_code: Optional[str] = None
    risk_score: Optional[float] = None
    labels: Optional[str] = None
    enriched_source: Optional[str] = None


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

"""Tipos y enums para clasificación de IPs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class IpType(str, Enum):
    """Tipos de IP según su origen/uso."""

    DATACENTER = "datacenter"
    RESIDENTIAL = "residential"
    GOVERNMENTAL = "governmental"
    EDUCATIONAL = "educational"
    CORPORATE = "corporate"
    MOBILE = "mobile"
    PROXY = "proxy"
    UNKNOWN = "unknown"


@dataclass
class IpClassification:
    """Resultado de la clasificación de una IP."""

    ip_type: IpType
    confidence: float  # 0.0 - 1.0
    source: str  # Fuente que determinó la clasificación
    provider: Optional[str] = None  # Cloud provider específico si aplica
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    is_proxy: bool = False
    is_mobile: bool = False
    is_hosting: bool = False

    def to_dict(self) -> dict:
        """Convierte a diccionario para almacenamiento."""
        return {
            "ip_type": self.ip_type.value,
            "ip_type_confidence": self.confidence,
            "ip_type_source": self.source,
            "ip_type_provider": self.provider,
            "isp": self.isp,
            "org": self.org,
            "asn": self.asn,
            "is_proxy": self.is_proxy,
            "is_mobile": self.is_mobile,
            "is_hosting": self.is_hosting,
        }

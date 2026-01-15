"""Módulo de clasificación de IPs por tipo.

Proporciona clasificación automática de IPs en categorías:
- datacenter: AWS, GCP, Azure, hosting providers
- residential: ISPs de usuarios finales
- governmental: .gov, .gob, .mil
- educational: .edu, universidades
- corporate: Grandes empresas conocidas
- mobile: Redes móviles/celulares
- proxy: VPN, Proxy, Tor
- unknown: Sin clasificar
"""

from mimosa.core.ip_classification.types import IpType, IpClassification
from mimosa.core.ip_classification.classifier import IpClassifier
from mimosa.core.ip_classification.cloud_ranges import CloudRangeChecker

__all__ = ["IpType", "IpClassification", "IpClassifier", "CloudRangeChecker"]

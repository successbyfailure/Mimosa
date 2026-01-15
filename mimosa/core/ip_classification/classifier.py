"""Clasificador principal de IPs.

Combina múltiples fuentes para determinar el tipo de IP:
1. Listas de cloud providers (más preciso)
2. Datos de ip-api.com (hosting, proxy, mobile)
3. Análisis de reverse DNS (patrones .gov, .edu, etc.)
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Optional

from mimosa.core.ip_classification.types import IpType, IpClassification
from mimosa.core.ip_classification.cloud_ranges import CloudRangeChecker
from mimosa.core.ip_classification.rdns_patterns import classify_by_rdns

logger = logging.getLogger(__name__)


class IpClassifier:
    """Clasificador de IPs por tipo."""

    def __init__(
        self,
        cloud_checker: Optional[CloudRangeChecker] = None,
        enabled: Optional[bool] = None,
    ):
        """Inicializa el clasificador.

        Args:
            cloud_checker: Instancia de CloudRangeChecker. Si no se proporciona,
                          se crea una nueva automáticamente.
            enabled: Si está habilitado. Por defecto lee MIMOSA_IP_CLASSIFICATION_ENABLED.
        """
        if enabled is None:
            enabled = os.getenv("MIMOSA_IP_CLASSIFICATION_ENABLED", "true").lower() == "true"

        self.enabled = enabled
        self._cloud_checker: Optional[CloudRangeChecker] = None

        if self.enabled:
            self._cloud_checker = cloud_checker or CloudRangeChecker()
            # Intentar refrescar si es necesario (en background idealmente)
            try:
                self._cloud_checker.refresh_if_needed()
            except Exception as e:
                logger.warning(f"Error refrescando rangos de cloud: {e}")

    @property
    def cloud_checker(self) -> Optional[CloudRangeChecker]:
        return self._cloud_checker

    def classify(
        self,
        ip: str,
        rdns: Optional[str] = None,
        api_data: Optional[Dict[str, object]] = None,
    ) -> IpClassification:
        """Clasifica una IP combinando múltiples fuentes.

        Args:
            ip: Dirección IP a clasificar
            rdns: Reverse DNS de la IP (opcional)
            api_data: Datos de ip-api.com con campos:
                     hosting, proxy, mobile, isp, org, as

        Returns:
            IpClassification con tipo, confianza y metadatos
        """
        if not self.enabled:
            return IpClassification(
                ip_type=IpType.UNKNOWN,
                confidence=0.0,
                source="disabled",
            )

        # Extraer datos de API si están disponibles
        isp = str(api_data.get("isp", "")) if api_data else None
        org = str(api_data.get("org", "")) if api_data else None
        asn = str(api_data.get("as", "")) if api_data else None
        is_hosting = bool(api_data.get("hosting", False)) if api_data else False
        is_proxy = bool(api_data.get("proxy", False)) if api_data else False
        is_mobile = bool(api_data.get("mobile", False)) if api_data else False

        # 1. Verificar rangos de cloud (más preciso, 99% confianza)
        if self._cloud_checker:
            cloud_provider = self._cloud_checker.check_ip(ip)
            if cloud_provider:
                return IpClassification(
                    ip_type=IpType.DATACENTER,
                    confidence=0.99,
                    source=f"cloud-ranges:{cloud_provider}",
                    provider=cloud_provider,
                    isp=isp,
                    org=org,
                    asn=asn,
                    is_proxy=is_proxy,
                    is_mobile=is_mobile,
                    is_hosting=True,
                )

        # 2. Analizar reverse DNS (75% confianza)
        if rdns:
            rdns_result = classify_by_rdns(rdns)
            if rdns_result:
                rdns_type, rdns_source = rdns_result
                return IpClassification(
                    ip_type=rdns_type,
                    confidence=0.75,
                    source=rdns_source,
                    isp=isp,
                    org=org,
                    asn=asn,
                    is_proxy=is_proxy,
                    is_mobile=is_mobile,
                    is_hosting=is_hosting,
                )

        # 3. Analizar flags de ip-api.com
        if api_data:
            # Proxy/VPN tiene alta prioridad
            if is_proxy:
                return IpClassification(
                    ip_type=IpType.PROXY,
                    confidence=0.80,
                    source="ip-api:proxy",
                    isp=isp,
                    org=org,
                    asn=asn,
                    is_proxy=True,
                    is_mobile=is_mobile,
                    is_hosting=is_hosting,
                )

            # Hosting/Datacenter
            if is_hosting:
                return IpClassification(
                    ip_type=IpType.DATACENTER,
                    confidence=0.85,
                    source="ip-api:hosting",
                    isp=isp,
                    org=org,
                    asn=asn,
                    is_proxy=is_proxy,
                    is_mobile=is_mobile,
                    is_hosting=True,
                )

            # Móvil
            if is_mobile:
                return IpClassification(
                    ip_type=IpType.MOBILE,
                    confidence=0.90,
                    source="ip-api:mobile",
                    isp=isp,
                    org=org,
                    asn=asn,
                    is_proxy=is_proxy,
                    is_mobile=True,
                    is_hosting=is_hosting,
                )

            # Tiene ISP conocido → probablemente residencial
            if isp and isp.strip():
                return IpClassification(
                    ip_type=IpType.RESIDENTIAL,
                    confidence=0.60,
                    source="ip-api:isp-default",
                    isp=isp,
                    org=org,
                    asn=asn,
                    is_proxy=is_proxy,
                    is_mobile=is_mobile,
                    is_hosting=is_hosting,
                )

        # 4. Fallback: desconocido
        return IpClassification(
            ip_type=IpType.UNKNOWN,
            confidence=0.0,
            source="none",
            isp=isp,
            org=org,
            asn=asn,
            is_proxy=is_proxy,
            is_mobile=is_mobile,
            is_hosting=is_hosting,
        )

    def refresh_cloud_ranges(self) -> Dict[str, int]:
        """Fuerza la actualización de rangos de cloud.

        Returns:
            Dict con conteo de prefijos por provider
        """
        if not self._cloud_checker:
            return {}
        return self._cloud_checker.refresh_all()

    def get_cloud_stats(self) -> Dict[str, int]:
        """Devuelve estadísticas de los rangos cargados."""
        if not self._cloud_checker:
            return {}
        return self._cloud_checker.get_stats()

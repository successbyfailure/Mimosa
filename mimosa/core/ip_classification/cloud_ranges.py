"""Gestión de rangos de IP de cloud providers.

Descarga y cachea listas públicas de rangos IP de:
- AWS
- Google Cloud
- Azure
- Cloudflare
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)

# URLs oficiales de rangos IP
CLOUD_RANGE_SOURCES = {
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
    "cloudflare_v4": "https://www.cloudflare.com/ips-v4",
    "cloudflare_v6": "https://www.cloudflare.com/ips-v6",
}

# Azure requiere descarga manual, usamos una lista estática de prefijos conocidos
AZURE_KNOWN_PREFIXES = [
    "13.64.0.0/11",
    "13.96.0.0/13",
    "13.104.0.0/14",
    "20.0.0.0/11",
    "20.32.0.0/11",
    "20.64.0.0/10",
    "20.128.0.0/16",
    "20.130.0.0/16",
    "20.135.0.0/16",
    "20.136.0.0/16",
    "20.140.0.0/15",
    "20.143.0.0/16",
    "20.144.0.0/14",
    "20.150.0.0/15",
    "20.152.0.0/15",
    "20.157.0.0/16",
    "20.160.0.0/12",
    "20.176.0.0/14",
    "20.180.0.0/14",
    "20.184.0.0/13",
    "20.192.0.0/10",
    "23.96.0.0/13",
    "40.64.0.0/10",
    "51.104.0.0/15",
    "51.120.0.0/16",
    "51.124.0.0/16",
    "51.132.0.0/16",
    "51.136.0.0/15",
    "51.138.0.0/16",
    "51.140.0.0/14",
    "52.96.0.0/12",
    "52.112.0.0/14",
    "52.120.0.0/14",
    "52.125.0.0/16",
    "52.136.0.0/13",
    "52.145.0.0/16",
    "52.146.0.0/15",
    "52.148.0.0/14",
    "52.152.0.0/13",
    "52.160.0.0/11",
    "52.224.0.0/11",
    "65.52.0.0/14",
    "70.37.0.0/17",
    "70.37.128.0/18",
    "104.40.0.0/13",
    "104.208.0.0/13",
    "137.116.0.0/15",
    "137.135.0.0/16",
    "138.91.0.0/16",
    "157.54.0.0/15",
    "157.56.0.0/14",
    "168.61.0.0/16",
    "168.62.0.0/15",
    "191.232.0.0/13",
    "204.79.180.0/24",
    "204.79.195.0/24",
]

# Otros hosting providers conocidos (prefijos estáticos)
OTHER_HOSTING_PREFIXES = {
    "digitalocean": [
        "104.131.0.0/16",
        "104.236.0.0/16",
        "107.170.0.0/16",
        "138.68.0.0/16",
        "138.197.0.0/16",
        "139.59.0.0/16",
        "142.93.0.0/16",
        "159.65.0.0/16",
        "159.89.0.0/16",
        "161.35.0.0/16",
        "162.243.0.0/16",
        "165.22.0.0/16",
        "165.227.0.0/16",
        "167.71.0.0/16",
        "167.99.0.0/16",
        "178.62.0.0/16",
        "178.128.0.0/16",
        "188.166.0.0/16",
        "206.189.0.0/16",
        "209.97.0.0/16",
    ],
    "linode": [
        "45.33.0.0/17",
        "45.56.64.0/18",
        "45.79.0.0/16",
        "50.116.0.0/17",
        "66.175.208.0/20",
        "69.164.192.0/18",
        "72.14.176.0/20",
        "74.207.224.0/19",
        "85.159.208.0/21",
        "96.126.96.0/19",
        "97.107.128.0/17",
        "139.144.0.0/16",
        "139.162.0.0/16",
        "143.42.0.0/16",
        "170.187.128.0/17",
        "172.104.0.0/15",
        "176.58.64.0/18",
        "178.79.128.0/17",
        "192.155.80.0/20",
        "194.195.192.0/18",
        "198.58.96.0/19",
        "212.71.224.0/19",
    ],
    "vultr": [
        "45.32.0.0/15",
        "45.63.0.0/16",
        "45.76.0.0/15",
        "64.156.0.0/16",
        "64.227.0.0/16",
        "66.42.32.0/19",
        "78.141.192.0/18",
        "95.179.128.0/17",
        "104.207.128.0/17",
        "108.61.0.0/16",
        "136.244.64.0/18",
        "140.82.0.0/16",
        "144.202.0.0/16",
        "149.28.0.0/16",
        "155.138.128.0/17",
        "207.148.64.0/18",
        "209.250.224.0/19",
        "216.128.128.0/17",
        "217.69.0.0/18",
    ],
    "hetzner": [
        "5.9.0.0/16",
        "23.88.0.0/15",
        "46.4.0.0/16",
        "78.46.0.0/15",
        "85.10.192.0/18",
        "88.198.0.0/16",
        "88.99.0.0/16",
        "91.107.128.0/17",
        "116.202.0.0/15",
        "128.140.0.0/17",
        "135.181.0.0/16",
        "136.243.0.0/16",
        "138.201.0.0/16",
        "142.132.128.0/17",
        "144.76.0.0/16",
        "148.251.0.0/16",
        "157.90.0.0/16",
        "159.69.0.0/16",
        "162.55.0.0/16",
        "167.233.0.0/16",
        "168.119.0.0/16",
        "176.9.0.0/16",
        "178.63.0.0/16",
        "188.40.0.0/16",
        "195.201.0.0/16",
        "213.133.96.0/19",
        "213.239.192.0/18",
    ],
    "ovh": [
        "5.39.0.0/17",
        "5.135.0.0/16",
        "5.196.0.0/16",
        "37.59.0.0/16",
        "37.187.0.0/16",
        "46.105.0.0/16",
        "51.38.0.0/16",
        "51.68.0.0/16",
        "51.75.0.0/16",
        "51.77.0.0/16",
        "51.79.0.0/16",
        "51.83.0.0/16",
        "51.89.0.0/16",
        "51.91.0.0/16",
        "51.195.0.0/16",
        "51.210.0.0/16",
        "51.254.0.0/16",
        "51.255.0.0/16",
        "54.36.0.0/15",
        "54.38.0.0/16",
        "57.128.0.0/12",
        "87.98.128.0/17",
        "91.121.0.0/16",
        "92.222.0.0/16",
        "135.125.0.0/16",
        "137.74.0.0/16",
        "141.94.0.0/16",
        "141.95.0.0/16",
        "144.217.0.0/16",
        "145.239.0.0/16",
        "147.135.0.0/16",
        "149.56.0.0/16",
        "151.80.0.0/16",
        "158.69.0.0/16",
        "162.19.0.0/16",
        "164.132.0.0/16",
        "167.114.0.0/16",
        "176.31.0.0/16",
        "178.32.0.0/16",
        "178.33.0.0/16",
        "185.12.32.0/22",
        "188.165.0.0/16",
        "192.95.0.0/16",
        "193.70.0.0/16",
        "198.27.64.0/18",
        "198.50.128.0/17",
        "198.100.144.0/20",
        "213.32.0.0/17",
        "213.186.32.0/19",
        "213.251.128.0/18",
    ],
}


class CloudRangeChecker:
    """Verifica si una IP pertenece a rangos de cloud providers."""

    def __init__(self, cache_dir: Optional[Path] = None, refresh_hours: int = 24):
        """Inicializa el checker.

        Args:
            cache_dir: Directorio para cache. Por defecto data/cloud_ranges/
            refresh_hours: Horas entre actualizaciones automáticas
        """
        default_cache = Path(os.getenv("MIMOSA_CLOUD_RANGES_CACHE_DIR", "data/cloud_ranges"))
        self.cache_dir = cache_dir or default_cache
        self.refresh_hours = int(os.getenv("MIMOSA_CLOUD_RANGES_REFRESH_HOURS", str(refresh_hours)))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Redes por proveedor (IPv4 y IPv6)
        self._networks: Dict[str, List[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
        self._last_refresh: Optional[datetime] = None
        self._lock = threading.Lock()

        # Cargar cache si existe
        self._load_from_cache()

    def check_ip(self, ip: str) -> Optional[str]:
        """Verifica si una IP pertenece a un cloud provider.

        Args:
            ip: Dirección IP a verificar

        Returns:
            Nombre del provider (aws, gcp, azure, etc.) o None
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        with self._lock:
            for provider, networks in self._networks.items():
                for network in networks:
                    try:
                        if addr in network:
                            return provider
                    except TypeError:
                        # IPv4 en red IPv6 o viceversa
                        continue

        return None

    def refresh_all(self) -> Dict[str, int]:
        """Actualiza todas las listas de rangos.

        Returns:
            Dict con conteo de prefijos por provider
        """
        counts: Dict[str, int] = {}

        # AWS
        try:
            aws_prefixes = self._fetch_aws()
            counts["aws"] = len(aws_prefixes)
        except Exception as e:
            logger.warning(f"Error actualizando rangos AWS: {e}")
            counts["aws"] = 0

        # GCP
        try:
            gcp_prefixes = self._fetch_gcp()
            counts["gcp"] = len(gcp_prefixes)
        except Exception as e:
            logger.warning(f"Error actualizando rangos GCP: {e}")
            counts["gcp"] = 0

        # Cloudflare
        try:
            cf_prefixes = self._fetch_cloudflare()
            counts["cloudflare"] = len(cf_prefixes)
        except Exception as e:
            logger.warning(f"Error actualizando rangos Cloudflare: {e}")
            counts["cloudflare"] = 0

        # Azure (estático)
        azure_networks = self._load_static_prefixes("azure", AZURE_KNOWN_PREFIXES)
        counts["azure"] = len(azure_networks)

        # Otros hosting providers (estáticos)
        for provider, prefixes in OTHER_HOSTING_PREFIXES.items():
            networks = self._load_static_prefixes(provider, prefixes)
            counts[provider] = len(networks)

        self._last_refresh = datetime.now(timezone.utc)
        self._save_to_cache()

        logger.info(f"Rangos de cloud actualizados: {counts}")
        return counts

    def refresh_if_needed(self) -> bool:
        """Actualiza los rangos si han pasado más de refresh_hours.

        Returns:
            True si se actualizó, False si no era necesario
        """
        if self._last_refresh is None:
            self.refresh_all()
            return True

        elapsed = datetime.now(timezone.utc) - self._last_refresh
        if elapsed.total_seconds() > self.refresh_hours * 3600:
            self.refresh_all()
            return True

        return False

    def get_stats(self) -> Dict[str, int]:
        """Devuelve estadísticas de los rangos cargados."""
        with self._lock:
            return {provider: len(networks) for provider, networks in self._networks.items()}

    def _fetch_aws(self) -> List[str]:
        """Descarga rangos de AWS."""
        url = CLOUD_RANGE_SOURCES["aws"]
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        data = response.json()

        prefixes: Set[str] = set()
        for prefix in data.get("prefixes", []):
            if "ip_prefix" in prefix:
                prefixes.add(prefix["ip_prefix"])
        for prefix in data.get("ipv6_prefixes", []):
            if "ipv6_prefix" in prefix:
                prefixes.add(prefix["ipv6_prefix"])

        networks = self._load_static_prefixes("aws", list(prefixes))
        return list(prefixes)

    def _fetch_gcp(self) -> List[str]:
        """Descarga rangos de Google Cloud."""
        url = CLOUD_RANGE_SOURCES["gcp"]
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        data = response.json()

        prefixes: Set[str] = set()
        for prefix in data.get("prefixes", []):
            if "ipv4Prefix" in prefix:
                prefixes.add(prefix["ipv4Prefix"])
            if "ipv6Prefix" in prefix:
                prefixes.add(prefix["ipv6Prefix"])

        networks = self._load_static_prefixes("gcp", list(prefixes))
        return list(prefixes)

    def _fetch_cloudflare(self) -> List[str]:
        """Descarga rangos de Cloudflare."""
        prefixes: Set[str] = set()

        # IPv4
        try:
            response = httpx.get(CLOUD_RANGE_SOURCES["cloudflare_v4"], timeout=30.0)
            response.raise_for_status()
            for line in response.text.strip().split("\n"):
                if line.strip():
                    prefixes.add(line.strip())
        except Exception as e:
            logger.warning(f"Error descargando Cloudflare IPv4: {e}")

        # IPv6
        try:
            response = httpx.get(CLOUD_RANGE_SOURCES["cloudflare_v6"], timeout=30.0)
            response.raise_for_status()
            for line in response.text.strip().split("\n"):
                if line.strip():
                    prefixes.add(line.strip())
        except Exception as e:
            logger.warning(f"Error descargando Cloudflare IPv6: {e}")

        networks = self._load_static_prefixes("cloudflare", list(prefixes))
        return list(prefixes)

    def _load_static_prefixes(
        self, provider: str, prefixes: List[str]
    ) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Carga una lista de prefijos CIDR en memoria."""
        networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
                networks.append(network)
            except ValueError as e:
                logger.debug(f"Prefijo inválido para {provider}: {prefix} - {e}")

        with self._lock:
            self._networks[provider] = networks

        return networks

    def _save_to_cache(self) -> None:
        """Guarda los rangos en disco."""
        cache_file = self.cache_dir / "ranges.json"
        data = {
            "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
            "providers": {},
        }

        with self._lock:
            for provider, networks in self._networks.items():
                data["providers"][provider] = [str(n) for n in networks]

        try:
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Cache de rangos guardada en {cache_file}")
        except Exception as e:
            logger.warning(f"Error guardando cache de rangos: {e}")

    def _load_from_cache(self) -> bool:
        """Carga rangos desde el disco si existe cache."""
        cache_file = self.cache_dir / "ranges.json"
        if not cache_file.exists():
            return False

        try:
            with open(cache_file) as f:
                data = json.load(f)

            if data.get("last_refresh"):
                self._last_refresh = datetime.fromisoformat(data["last_refresh"])

            for provider, prefixes in data.get("providers", {}).items():
                self._load_static_prefixes(provider, prefixes)

            logger.info(f"Rangos cargados desde cache: {self.get_stats()}")
            return True
        except Exception as e:
            logger.warning(f"Error cargando cache de rangos: {e}")
            return False

"""Patrones de reverse DNS para clasificación de IPs."""

from __future__ import annotations

import re
from typing import Optional

from mimosa.core.ip_classification.types import IpType

# Patrones compilados para mejor rendimiento
DATACENTER_PATTERNS = [
    re.compile(r"\.amazonaws\.com$", re.IGNORECASE),
    re.compile(r"\.compute\.amazonaws\.com$", re.IGNORECASE),
    re.compile(r"\.ec2\.internal$", re.IGNORECASE),
    re.compile(r"\.googleusercontent\.com$", re.IGNORECASE),
    re.compile(r"\.bc\.googleusercontent\.com$", re.IGNORECASE),
    re.compile(r"\.cloud\.google\.com$", re.IGNORECASE),
    re.compile(r"\.cloudapp\.azure\.com$", re.IGNORECASE),
    re.compile(r"\.azure\.com$", re.IGNORECASE),
    re.compile(r"\.digitalocean\.com$", re.IGNORECASE),
    re.compile(r"\.vultr\.com$", re.IGNORECASE),
    re.compile(r"\.linode\.com$", re.IGNORECASE),
    re.compile(r"\.linodeusercontent\.com$", re.IGNORECASE),
    re.compile(r"\.hetzner\.(de|com|cloud)$", re.IGNORECASE),
    re.compile(r"\.your-server\.de$", re.IGNORECASE),
    re.compile(r"\.contabo\.(de|com)$", re.IGNORECASE),
    re.compile(r"\.ovh\.(net|com|fr|es|de|uk)$", re.IGNORECASE),
    re.compile(r"\.kimsufi\.(com|net)$", re.IGNORECASE),
    re.compile(r"\.soyoustart\.(com|net)$", re.IGNORECASE),
    re.compile(r"\.scaleway\.com$", re.IGNORECASE),
    re.compile(r"\.oracle(cloud)?\.com$", re.IGNORECASE),
    re.compile(r"\.rackspace\.com$", re.IGNORECASE),
    re.compile(r"\.softlayer\.com$", re.IGNORECASE),
    re.compile(r"\.ibm\.com$", re.IGNORECASE),
    re.compile(r"\.cloudflare\.com$", re.IGNORECASE),
    re.compile(r"\.akamai(technologies)?\.com$", re.IGNORECASE),
    re.compile(r"\.fastly\.net$", re.IGNORECASE),
    re.compile(r"\.edgecastcdn\.net$", re.IGNORECASE),
    re.compile(r"\.leaseweb\.(com|net|de|nl)$", re.IGNORECASE),
    re.compile(r"\.serverspace\.(io|ru)$", re.IGNORECASE),
    re.compile(r"\.upcloud\.host$", re.IGNORECASE),
    re.compile(r"\.dedicated\.com$", re.IGNORECASE),
    re.compile(r"\.hostgator\.com$", re.IGNORECASE),
    re.compile(r"\.bluehost\.com$", re.IGNORECASE),
    re.compile(r"\.dreamhost\.com$", re.IGNORECASE),
    re.compile(r"\.hostinger\.(com|net)$", re.IGNORECASE),
    re.compile(r"\.ionos\.(com|de)$", re.IGNORECASE),
    re.compile(r"\.1und1\.(de|com)$", re.IGNORECASE),
]

GOVERNMENTAL_PATTERNS = [
    re.compile(r"\.gov$", re.IGNORECASE),
    re.compile(r"\.gov\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.gob\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.mil$", re.IGNORECASE),
    re.compile(r"\.mil\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.government\.", re.IGNORECASE),
    re.compile(r"\.gouv\.fr$", re.IGNORECASE),
    re.compile(r"\.bundeswehr\.de$", re.IGNORECASE),
    re.compile(r"\.admin\.ch$", re.IGNORECASE),
    re.compile(r"\.gc\.ca$", re.IGNORECASE),
    re.compile(r"\.parliament\.", re.IGNORECASE),
    re.compile(r"\.senate\.", re.IGNORECASE),
    re.compile(r"\.congreso\.", re.IGNORECASE),
    re.compile(r"\.defensa\.", re.IGNORECASE),
    re.compile(r"\.policia\.", re.IGNORECASE),
    re.compile(r"\.police\.", re.IGNORECASE),
    re.compile(r"\.ejercito\.", re.IGNORECASE),
    re.compile(r"\.army\.", re.IGNORECASE),
    re.compile(r"\.navy\.", re.IGNORECASE),
]

EDUCATIONAL_PATTERNS = [
    re.compile(r"\.edu$", re.IGNORECASE),
    re.compile(r"\.edu\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.ac\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.university\.", re.IGNORECASE),
    re.compile(r"\.uni-[a-z]+\.", re.IGNORECASE),
    re.compile(r"\.universidad\.", re.IGNORECASE),
    re.compile(r"\.college\.", re.IGNORECASE),
    re.compile(r"\.school\.", re.IGNORECASE),
    re.compile(r"\.escuela\.", re.IGNORECASE),
    re.compile(r"\.instituto\.", re.IGNORECASE),
    re.compile(r"\.campus\.", re.IGNORECASE),
    re.compile(r"\.unam\.mx$", re.IGNORECASE),
    re.compile(r"\.mit\.edu$", re.IGNORECASE),
    re.compile(r"\.stanford\.edu$", re.IGNORECASE),
    re.compile(r"\.harvard\.edu$", re.IGNORECASE),
    re.compile(r"\.ox\.ac\.uk$", re.IGNORECASE),
    re.compile(r"\.cam\.ac\.uk$", re.IGNORECASE),
]

CORPORATE_PATTERNS = [
    re.compile(r"\.google\.com$", re.IGNORECASE),
    re.compile(r"\.facebook\.com$", re.IGNORECASE),
    re.compile(r"\.meta\.com$", re.IGNORECASE),
    re.compile(r"\.apple\.com$", re.IGNORECASE),
    re.compile(r"\.microsoft\.com$", re.IGNORECASE),
    re.compile(r"\.amazon\.com$", re.IGNORECASE),
    re.compile(r"\.netflix\.com$", re.IGNORECASE),
    re.compile(r"\.twitter\.com$", re.IGNORECASE),
    re.compile(r"\.x\.com$", re.IGNORECASE),
    re.compile(r"\.linkedin\.com$", re.IGNORECASE),
    re.compile(r"\.salesforce\.com$", re.IGNORECASE),
    re.compile(r"\.adobe\.com$", re.IGNORECASE),
    re.compile(r"\.intel\.com$", re.IGNORECASE),
    re.compile(r"\.nvidia\.com$", re.IGNORECASE),
    re.compile(r"\.cisco\.com$", re.IGNORECASE),
    re.compile(r"\.hp\.com$", re.IGNORECASE),
    re.compile(r"\.dell\.com$", re.IGNORECASE),
    re.compile(r"\.vmware\.com$", re.IGNORECASE),
    re.compile(r"\.oracle\.com$", re.IGNORECASE),
    re.compile(r"\.sap\.com$", re.IGNORECASE),
]


def classify_by_rdns(rdns: str) -> Optional[tuple[IpType, str]]:
    """Clasifica una IP basándose en su reverse DNS.

    Args:
        rdns: Nombre de dominio del reverse DNS

    Returns:
        Tupla (IpType, fuente) o None si no hay match
    """
    if not rdns:
        return None

    rdns_lower = rdns.lower()

    # Orden de prioridad: gubernamental > educativo > datacenter > corporativo
    for pattern in GOVERNMENTAL_PATTERNS:
        if pattern.search(rdns_lower):
            return (IpType.GOVERNMENTAL, f"rdns:{rdns}")

    for pattern in EDUCATIONAL_PATTERNS:
        if pattern.search(rdns_lower):
            return (IpType.EDUCATIONAL, f"rdns:{rdns}")

    for pattern in DATACENTER_PATTERNS:
        if pattern.search(rdns_lower):
            return (IpType.DATACENTER, f"rdns:{rdns}")

    for pattern in CORPORATE_PATTERNS:
        if pattern.search(rdns_lower):
            return (IpType.CORPORATE, f"rdns:{rdns}")

    return None

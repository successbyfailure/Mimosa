"""Módulo de detección de patrones sospechosos.

Este archivo define estrategias de detección simplificadas que pueden
ser extendidas para incluir heurística, firmas o detección basada en ML.
"""
from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class Alert:
    """Resultado de una detección."""

    source_ip: str
    description: str
    severity: str


class Detector:
    """Detector base para eventos de red o autenticación."""

    def analyze_logs(self, log_lines: Iterable[str]) -> List[Alert]:
        """Ejemplo de análisis de logs para encontrar patrones básicos."""

        alerts: List[Alert] = []
        for line in log_lines:
            if "failed password" in line.lower():
                alerts.append(
                    Alert(
                        source_ip="desconocido",
                        description="Intento fallido detectado",
                        severity="medium",
                    )
                )
        return alerts

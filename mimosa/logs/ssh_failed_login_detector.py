"""Herramientas para descargar logs vía SSH y detectar intentos fallidos de autenticación."""
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence
import re

import paramiko


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)",
)


@dataclass
class SSHLogEndpoint:
    """Información de conexión y rutas de logs a descargar."""

    host: str
    username: str
    password: str
    log_paths: Sequence[str]
    port: int = 22


class SSHFailedLoginDetector:
    """Descarga logs remotos y detecta intentos de login fallidos usando regex."""

    def __init__(self, endpoint: SSHLogEndpoint, pattern: Optional[re.Pattern[str]] = None):
        self.endpoint = endpoint
        self.pattern = pattern or FAILED_LOGIN_PATTERN

    def _open_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self.endpoint.host,
            port=self.endpoint.port,
            username=self.endpoint.username,
            password=self.endpoint.password,
        )
        return client

    def fetch_logs(self) -> Dict[str, List[str]]:
        """Descarga las rutas indicadas y devuelve su contenido separado por líneas."""

        client = self._open_client()
        try:
            sftp = client.open_sftp()
            logs: Dict[str, List[str]] = {}
            for path in self.endpoint.log_paths:
                with sftp.file(path, "r") as log_file:
                    logs[path] = [line.rstrip("\n") for line in log_file.readlines()]
            return logs
        finally:
            client.close()

    def detect_failed_logins(self) -> List[Dict[str, object]]:
        """Ejecuta la expresión regular sobre los logs descargados y devuelve coincidencias."""

        failed_attempts: List[Dict[str, object]] = []
        logs = self.fetch_logs()
        for path, lines in logs.items():
            for index, line in enumerate(lines, start=1):
                match = self.pattern.search(line)
                if match:
                    failed_attempts.append(
                        {
                            "path": path,
                            "line": index,
                            "username": match.group("user"),
                            "ip": match.group("ip"),
                            "raw": line,
                        }
                    )
        return failed_attempts

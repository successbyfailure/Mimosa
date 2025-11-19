"""Recolección de logs vía SSH."""
from dataclasses import dataclass
from typing import Iterable

import paramiko


@dataclass
class SSHSource:
    host: str
    username: str
    password: str
    path: str = "/var/log/auth.log"


class SSHLogCollector:
    """Obtiene líneas de log desde un servidor remoto."""

    def __init__(self, source: SSHSource):
        self.source = source

    def collect(self) -> Iterable[str]:
        """Retorna un generador de líneas del archivo indicado."""

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.source.host, username=self.source.username, password=self.source.password)
        sftp = client.open_sftp()
        with sftp.file(self.source.path, "r") as log_file:
            for line in log_file:
                yield line.strip()
        client.close()

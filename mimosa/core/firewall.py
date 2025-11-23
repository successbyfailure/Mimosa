"""Integración simplificada con un firewall externo."""
from __future__ import annotations

import subprocess
from typing import Callable, List

from mimosa.core.api import FirewallGateway


class DummyFirewall(FirewallGateway):
    """Implementación de ejemplo para pruebas locales."""

    def __init__(self) -> None:
        self._blocked: List[str] = []

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:
        if ip not in self._blocked:
            self._blocked.append(ip)
        suffix = f" por {duration_minutes}m" if duration_minutes else ""
        print(f"[FIREWALL] Bloqueando {ip}: {reason}{suffix}")

    def list_blocks(self) -> List[str]:
        return list(self._blocked)

    def unblock_ip(self, ip: str) -> None:
        if ip in self._blocked:
            self._blocked.remove(ip)
        print(f"[FIREWALL] Desbloqueando {ip}")

    def check_connection(self) -> None:
        """Dummy siempre responde como disponible."""

        return None

    def ensure_ready(self) -> None:
        """No requiere preparación adicional en el modo dummy."""

        return None

    def ensure_port_forwards(
        self,
        *,
        target_ip: str,
        ports: List[int],
        protocol: str = "tcp",
        description: str | None = None,
        interface: str = "wan",
    ) -> dict:
        _ = target_ip, description, interface
        return {"created": ports, "conflicts": [], "already_present": []}

    def list_services(self) -> List[dict]:
        return []


class SSHIptablesFirewall(FirewallGateway):
    """Gestiona reglas básicas de iptables mediante SSH."""

    def __init__(
        self,
        host: str,
        *,
        user: str = "root",
        key_path: str | None = None,
        port: int = 22,
        chain: str = "MIMOSA",
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        if not host:
            raise ValueError("Se requiere un host para conectarse por SSH")
        self.host = host
        self.user = user or "root"
        self.key_path = key_path
        self.port = port
        self.chain = chain
        self._runner = runner or self._default_runner

    def block_ip(self, ip: str, reason: str, duration_minutes: int | None = None) -> None:
        _ = reason, duration_minutes
        cmd = (
            f"sudo iptables -C {self.chain} -s {ip} -j DROP 2>/dev/null || "
            f"sudo iptables -I {self.chain} -s {ip} -j DROP"
        )
        self._execute(cmd)

    def list_blocks(self) -> List[str]:
        output = self._execute(f"sudo iptables -nL {self.chain}")
        entries: List[str] = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit():
                entries.append(parts[4])
        return entries

    def unblock_ip(self, ip: str) -> None:
        cmd = (
            f"while sudo iptables -C {self.chain} -s {ip} -j DROP 2>/dev/null; "
            f"do sudo iptables -D {self.chain} -s {ip} -j DROP; done"
        )
        self._execute(cmd)

    def check_connection(self) -> None:
        self._execute("sudo iptables -L -n")

    def ensure_ready(self) -> None:
        setup = (
            f"sudo iptables -N {self.chain} 2>/dev/null || true; "
            f"sudo iptables -C INPUT -j {self.chain} 2>/dev/null || "
            f"sudo iptables -I INPUT 1 -j {self.chain}"
        )
        self._execute(setup)

    def ensure_port_forwards(
        self,
        *,
        target_ip: str,
        ports: List[int],
        protocol: str = "tcp",
        description: str | None = None,
        interface: str = "wan",
    ) -> dict:
        _ = target_ip, ports, protocol, description, interface
        raise NotImplementedError(
            "La gestión de NAT no está disponible para SSH + iptables"
        )

    def list_services(self) -> List[dict]:
        raise NotImplementedError(
            "La gestión de NAT no está disponible para SSH + iptables"
        )

    # --------------------------- utilidades ---------------------------------
    def _execute(self, remote_command: str) -> str:
        args = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-p",
            str(self.port),
        ]
        if self.key_path:
            args.extend(["-i", self.key_path])
        args.append(f"{self.user}@{self.host}")
        args.append(remote_command)

        result = self._runner(args, capture_output=True, text=True)
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "Comando SSH falló"
            raise RuntimeError(message)
        return result.stdout

    @staticmethod
    def _default_runner(
        args: List[str], *, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=capture_output, text=text)

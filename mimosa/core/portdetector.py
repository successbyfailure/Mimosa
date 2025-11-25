"""Abre puertos TCP/UDP y registra cada conexión detectada."""
from __future__ import annotations

import json
import select
import socket
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

from mimosa.core.blocking import BlockManager
from mimosa.core.offenses import OffenseStore
from mimosa.core.plugins import PortDetectorConfig, PortDetectorRule
from mimosa.core.rules import OffenseEvent, OffenseRule, OffenseRuleStore, RuleManager


def collect_ports_by_protocol(rules: Iterable[PortDetectorRule]) -> Dict[str, List[int]]:
    """Agrupa todos los puertos configurados por protocolo."""

    ports: Dict[str, set[int]] = {"tcp": set(), "udp": set()}
    for rule in rules:
        protocol = (rule.protocol or "tcp").lower()
        for port in PortDetectorService._iter_ports(rule):
            if 1 <= port <= 65535:
                ports.setdefault(protocol, set()).add(int(port))

    return {proto: sorted(values) for proto, values in ports.items() if values}


class PortBindingError(OSError):
    """Error al iniciar listeners de puertos.

    Incluye una lista de puertos que no pudieron abrirse junto con el
    protocolo y el error original.
    """

    def __init__(self, failures: List[Tuple[str, int, OSError]]):
        self.failures = failures
        ports = ", ".join(f"{proto}:{port}" for proto, port, _ in failures)
        super().__init__(f"No se pudieron abrir los puertos: {ports}")

    @property
    def failed_ports(self) -> List[Dict[str, object]]:
        return [
            {"protocol": proto, "port": port, "message": str(exc)}
            for proto, port, exc in self.failures
        ]


class PortDetectorService:
    """Gestiona listeners TCP/UDP y registra ofensas entrantes."""

    def __init__(
        self,
        offense_store: OffenseStore,
        block_manager: BlockManager,
        rule_store: OffenseRuleStore,
        gateway_factory: Callable[[], object],
        *,
        stats_path: str | Path | None = None,
    ) -> None:
        self.offense_store = offense_store
        self.block_manager = block_manager
        self.rule_store = rule_store
        self._gateway_factory = gateway_factory
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._sockets: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self.config = PortDetectorConfig()
        self._stats_path = Path(stats_path or Path("data/portdetector_stats.json"))
        self._stats_path.parent.mkdir(parents=True, exist_ok=True)
        self._port_hits = self._load_stats()

    # ---------------------------- configuración ----------------------------
    def apply_config(self, config: PortDetectorConfig) -> None:
        sanitized = PortDetectorConfig(
            enabled=config.enabled,
            default_severity=config.default_severity,
            rules=list(config.rules or []),
        )
        self.config = sanitized
        if config.enabled:
            self.start()
        else:
            self.stop()

    # ------------------------------- control --------------------------------
    def start(self) -> None:
        with self._lock:
            self.stop()
            self._stop_event.clear()
            errors: List[Tuple[str, int, OSError]] = []
            for protocol, port, severity in self._expand_rules(self.config.rules):
                try:
                    if protocol == "udp":
                        self._start_udp_listener(port, severity)
                    else:
                        self._start_tcp_listener(port, severity)
                except OSError as exc:  # pragma: no cover - dependiente del sistema
                    errors.append((protocol, port, exc))
            if errors:
                self.stop()
                raise PortBindingError(errors)

    def stop(self) -> None:
        self._stop_event.set()
        for sock in list(self._sockets):
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()
        for thread in list(self._threads):
            if thread.is_alive():
                thread.join(timeout=1)
        self._threads.clear()
        self._stop_event.clear()

    # ------------------------------- listeners ------------------------------
    def _start_tcp_listener(self, port: int, severity: str) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.setblocking(False)
        self._sockets.append(server)

        thread = threading.Thread(
            target=self._tcp_loop, args=(server, port, severity), daemon=True
        )
        thread.start()
        self._threads.append(thread)

    def _start_udp_listener(self, port: int, severity: str) -> None:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind(("0.0.0.0", port))
        udp_sock.settimeout(1.0)
        self._sockets.append(udp_sock)

        thread = threading.Thread(
            target=self._udp_loop, args=(udp_sock, port, severity), daemon=True
        )
        thread.start()
        self._threads.append(thread)

    def _tcp_loop(self, server: socket.socket, port: int, severity: str) -> None:
        while not self._stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 1.0)
            except (ValueError, OSError):  # pragma: no cover - cierre abrupto
                break
            if server not in readable:
                continue
            try:
                conn, addr = server.accept()
            except OSError:
                continue
            with conn:
                self._register_hit(addr[0], port, "tcp", severity)

    def _udp_loop(self, sock: socket.socket, port: int, severity: str) -> None:
        while not self._stop_event.is_set():
            try:
                data = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:  # pragma: no cover - cierre abrupto
                break
            if not data:
                continue
            _, addr = data
            self._register_hit(addr[0], port, "udp", severity)

    # ------------------------------ ofensas ---------------------------------
    def _register_hit(self, source_ip: str, port: int, protocol: str, severity: str) -> None:
        description = f"portdetector {protocol.upper()}:{port}"
        self._increment_stat(protocol, port)
        self.offense_store.record(
            source_ip=source_ip,
            description=description,
            severity=severity or self.config.default_severity,
            context={
                "plugin": "portdetector",
                "protocol": protocol,
                "port": port,
                "config": asdict(self.config),
            },
        )
        self._process_rules(source_ip, port, protocol, severity)

    def _process_rules(self, source_ip: str, port: int, protocol: str, severity: str) -> None:
        manager = RuleManager(
            self.offense_store,
            self.block_manager,
            self._gateway_factory(),
            rules=self.rule_store.list() or [OffenseRule()],
        )
        manager.process_offense(
            OffenseEvent(
                source_ip=source_ip,
                plugin="portdetector",
                event_id=f"{protocol}:{port}",
                severity=severity,
                description=f"portdetector {protocol}:{port}",
            )
        )

    # ------------------------------ utilidades ------------------------------
    def _expand_rules(
        self, rules: Iterable[PortDetectorRule]
    ) -> List[Tuple[str, int, str]]:
        expanded: Dict[Tuple[str, int], str] = {}
        for rule in rules:
            protocol = (rule.protocol or "tcp").lower()
            severity = rule.severity or self.config.default_severity
            for port in self._iter_ports(rule):
                if port < 1 or port > 65535:
                    continue
                expanded[(protocol, port)] = severity
        return [(proto, port, sev) for (proto, port), sev in expanded.items()]

    @staticmethod
    def _iter_ports(rule: PortDetectorRule) -> Iterable[int]:
        if rule.port:
            yield int(rule.port)
        if rule.ports:
            for entry in rule.ports:
                yield int(entry)
        if rule.start and rule.end:
            start, end = int(rule.start), int(rule.end)
            if end < start:
                start, end = end, start
            for port in range(start, end + 1):
                yield port

    # ----------------------------- estadísticas ----------------------------
    def _load_stats(self) -> Dict[str, int]:
        if not self._stats_path.exists():
            return {}
        try:
            with self._stats_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}
        if not isinstance(data, dict):
            return {}
        normalized: Dict[str, int] = {}
        for key, value in data.items():
            try:
                normalized[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        return normalized

    def _save_stats(self) -> None:
        with self._stats_path.open("w", encoding="utf-8") as fh:
            json.dump(self._port_hits, fh, indent=2)

    def _increment_stat(self, protocol: str, port: int) -> None:
        key = f"{protocol}:{port}"
        self._port_hits[key] = self._port_hits.get(key, 0) + 1
        self._save_stats()

    def stats(self, limit: int = 50) -> Dict[str, object]:
        ordered = sorted(
            self._port_hits.items(), key=lambda item: item[1], reverse=True
        )[:limit]
        entries: List[Dict[str, object]] = []
        for key, hits in ordered:
            parts = key.split(":", maxsplit=1)
            if len(parts) != 2:
                continue
            try:
                port = int(parts[1])
            except ValueError:
                continue
            entries.append({"protocol": parts[0], "port": port, "hits": hits})
        return {
            "config": asdict(self.config),
            "top_ports": entries,
        }

    def reset_stats(self) -> None:
        self._port_hits = {}
        if self._stats_path.exists():
            self._stats_path.unlink()


__all__ = ["PortBindingError", "PortDetectorService", "collect_ports_by_protocol"]

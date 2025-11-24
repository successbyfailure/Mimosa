"""Servidor ligero para el plugin ProxyTrap.

Arranca un servidor HTTP que registra una ofensa por cada conexión
entrante, reutilizando el almacenamiento central y las reglas
configurables para decidir bloqueos.
"""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from fnmatch import fnmatch
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from mimosa.core.offenses import OffenseStore
from mimosa.core.rules import OffenseEvent, OffenseRule, OffenseRuleStore, RuleManager
from mimosa.core.blocking import BlockManager
from mimosa.core.plugins import ProxyTrapConfig


class ProxyTrapService:
    """Gestiona el ciclo de vida del servidor ProxyTrap."""

    def __init__(
        self,
        offense_store: OffenseStore,
        block_manager: BlockManager,
        rule_store: OffenseRuleStore,
        gateway_factory: Callable[[], object],
        stats_path: Path | str = Path("data/proxytrap_stats.json"),
    ) -> None:
        self.offense_store = offense_store
        self.block_manager = block_manager
        self.rule_store = rule_store
        self._gateway_factory = gateway_factory
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stats_path = Path(stats_path)
        self._stats_path.parent.mkdir(parents=True, exist_ok=True)
        self._domain_hits: Dict[str, int] = self._load_stats()
        self.config = ProxyTrapConfig()

    # -------------------------- configuracion --------------------------
    def apply_config(self, config: ProxyTrapConfig) -> None:
        """Actualiza la configuración y reinicia el servidor si procede."""

        sanitized = config
        sanitized.domain_policies = list(config.domain_policies or [])
        sanitized.trap_hosts = list(config.trap_hosts or [])
        self.config = sanitized
        if config.enabled:
            self.start()
        else:
            self.stop()

    # ---------------------------- servidor -----------------------------
    def start(self) -> None:
        with self._lock:
            if self._server:
                if self._server.server_port == self.config.port:
                    return
                self.stop()

            handler = self._build_handler()
            server = HTTPServer(("0.0.0.0", self.config.port), handler)
            thread = threading.Thread(
                target=server.serve_forever, name="proxytrap-server", daemon=True
            )
            server.timeout = 1
            thread.start()
            self._server = server
            self._thread = thread

    def stop(self) -> None:
        with self._lock:
            if not self._server:
                return
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    def _build_handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # pragma: no cover - silencia stdout
                return

            def _respond(self) -> None:
                source_ip = self._extract_ip()
                service._handle_request(
                    source_ip=source_ip,
                    host=self.headers.get("Host", "desconocido"),
                    path=self.path,
                )

                response_type = service.config.response_type
                if response_type == "silence":
                    self.send_response(204)
                    self.end_headers()
                    return
                if response_type == "404":
                    body = b"Not Found"
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                body = (service.config.custom_html or "").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - nombre requerido por BaseHTTPRequestHandler
                self._respond()

            def do_HEAD(self):  # noqa: N802 - nombre requerido por BaseHTTPRequestHandler
                self._respond()

            def do_POST(self):  # noqa: N802 - nombre requerido por BaseHTTPRequestHandler
                self._respond()

            def _extract_ip(self) -> str:
                forwarded = self.headers.get("X-Forwarded-For")
                if forwarded:
                    return forwarded.split(",")[0].strip()
                forwarded_header = self.headers.get("Forwarded")
                if forwarded_header:
                    for part in forwarded_header.split(";"):
                        segment = part.strip()
                        if segment.lower().startswith("for="):
                            return segment.split("=", 1)[1].strip(" \"[]")
                return self.client_address[0]

        return Handler

    # ---------------------------- logica -------------------------------
    def _handle_request(self, *, source_ip: str, host: str, path: str) -> None:
        domain = host.split(":", 1)[0] if host else "desconocido"
        severity, matched = self._resolve_severity(domain)
        description = f"proxytrap: {domain}"
        self.offense_store.record(
            source_ip=source_ip,
            description=description,
            severity=severity,
            host=domain,
            path=path,
            context={
                "plugin": "proxytrap",
                "matched_policy": matched or "default",
            },
        )
        self._increment_stat(domain)
        self._process_rules(domain, source_ip, severity)

    def _process_rules(self, domain: str, source_ip: str, severity: str) -> None:
        manager = RuleManager(
            self.offense_store,
            self.block_manager,
            self._gateway_factory(),
            rules=self.rule_store.list() or [OffenseRule()],
        )
        manager.process_offense(
            OffenseEvent(
                source_ip=source_ip,
                plugin="proxytrap",
                event_id=domain,
                severity=severity,
                description=f"proxytrap: {domain}",
            )
        )

    def _resolve_severity(self, domain: str) -> Tuple[str, Optional[str]]:
        normalized = domain.lower()
        for policy in self.config.domain_policies:
            pattern = (policy.get("pattern") or "").lower()
            severity = policy.get("severity") or self.config.default_severity
            if pattern and fnmatch(normalized, pattern):
                return severity, pattern
        return (self.config.default_severity, None)

    # ----------------------------- stats -------------------------------
    def _load_stats(self) -> Dict[str, int]:
        if not self._stats_path.exists():
            return {}
        with self._stats_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _save_stats(self) -> None:
        with self._stats_path.open("w", encoding="utf-8") as fh:
            json.dump(self._domain_hits, fh, indent=2)

    def _increment_stat(self, domain: str) -> None:
        self._domain_hits[domain] = self._domain_hits.get(domain, 0) + 1
        self._save_stats()

    def stats(self, limit: int = 50) -> Dict[str, object]:
        ordered = sorted(
            self._domain_hits.items(), key=lambda item: item[1], reverse=True
        )[:limit]
        return {
            "config": asdict(self.config),
            "top_domains": [
                {"domain": domain, "hits": hits} for domain, hits in ordered
            ],
        }

    def reset_stats(self) -> None:
        """Limpia el fichero de hits acumulados."""

        self._domain_hits = {}
        if self._stats_path.exists():
            self._stats_path.unlink()


from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import Iterable, Iterator

LOGGER = logging.getLogger(__name__)

ACCESS_REGEX = re.compile(
    r"(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<path>[^\s]+) (?P<protocol>[^\"]+)\" "
    r"(?P<status>\d{3}) \S+ \"[^\"]*\" \"(?P<user_agent>[^\"]*)\"(?P<rest>.*)"
)
NPM_REGEX = re.compile(
    r"\[(?P<time>[^\]]+)\]\s+(?P<prefix>.*?)\s+(?P<method>\S+)\s+(?P<scheme>https?|http)\s+"
    r"(?P<host>\S+)\s+\"(?P<path>[^\"]*)\"\s+\[Client\s+(?P<remote_addr>[^\]]+)\].*?"
    r"\"(?P<user_agent>[^\"]*)\"(?:\s+\"(?P<referrer>[^\"]*)\")?"
)


@dataclass
class AccessLogEntry:
    """Línea parseada de un log de acceso."""

    source_ip: str
    host: str | None
    path: str
    status_code: int | None
    user_agent: str | None
    source_log: str | None = None
    alert_type: str | None = None
    alert_tags: list[str] | None = None

    def to_alert(self) -> dict[str, object]:
        payload = {
            "source_ip": self.source_ip,
            "host": self.host or "desconocido",
            "path": self.path,
            "user_agent": self.user_agent,
            "status_code": self.status_code,
            "alert_type": self.alert_type,
            "alert_tags": self.alert_tags,
            "log_source": self.source_log,
        }
        return {k: v for k, v in payload.items() if v is not None}


class LogFollower:
    """Lee incrementos de logs manteniendo el desplazamiento en disco."""

    def __init__(self, pattern: str, state_path: Path) -> None:
        self.pattern = pattern
        self.state_path = state_path
        self.offsets: dict[str, int] = self._load_state()

    def _load_state(self) -> dict[str, int]:
        if not self.state_path.exists():
            return {}
        try:
            data = json.loads(self.state_path.read_text())
            return {str(Path(k)): int(v) for k, v in data.items()}
        except Exception as exc:  # noqa: BLE001 - registro y reinicio seguro
            LOGGER.warning("No se pudo leer el estado de logs: %s", exc)
            return {}

    def persist_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self.offsets))

    def _parse_line(self, line: str, source_log: str) -> AccessLogEntry | None:
        match = ACCESS_REGEX.match(line)
        if not match:
            return self._parse_npm_line(line, source_log)
        status = int(match.group("status")) if match.group("status") else None
        rest = match.group("rest") or ""
        host = self._extract_host(rest)
        return AccessLogEntry(
            source_ip=match.group("remote_addr"),
            host=host,
            path=match.group("path"),
            status_code=status,
            user_agent=match.group("user_agent") or None,
            source_log=source_log,
        )

    def _parse_npm_line(self, line: str, source_log: str) -> AccessLogEntry | None:
        match = NPM_REGEX.match(line)
        if not match:
            return None
        status = self._extract_status(match.group("prefix"))
        return AccessLogEntry(
            source_ip=match.group("remote_addr"),
            host=match.group("host"),
            path=match.group("path"),
            status_code=status,
            user_agent=match.group("user_agent") or None,
            source_log=source_log,
        )

    @staticmethod
    def _extract_status(prefix: str) -> int | None:
        status_match = re.search(r"\b(\d{3})\b", prefix)
        if not status_match:
            return None
        return int(status_match.group(1))

    @staticmethod
    def _extract_host(rest: str) -> str | None:
        tokens = [token for token in rest.strip().split() if token and token != "-"]
        for token in tokens:
            if token.startswith("host="):
                return token.split("=", 1)[1]
        for token in tokens:
            if "." in token and not token.replace(".", "").isdigit():
                return token
        return None

    def _iter_new_lines(self, path: Path) -> Iterator[str]:
        offset = self.offsets.get(str(path), 0)
        size = path.stat().st_size
        if offset > size:
            offset = 0
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(offset)
            for line in handle:
                yield line
            self.offsets[str(path)] = handle.tell()

    def read_new(self) -> Iterable[AccessLogEntry]:
        for path_str in glob(self.pattern):
            path = Path(path_str)
            if not path.is_file():
                continue
            for line in self._iter_new_lines(path):
                parsed = self._parse_line(line, path.name)
                if parsed:
                    yield parsed


def filter_alert_entries(
    entries: Iterable[AccessLogEntry],
    known_domains: set[str],
    suspicious_paths: Iterable[str],
) -> Iterator[AccessLogEntry]:
    del known_domains
    suspicious = tuple(path.lower() for path in suspicious_paths if path)
    for entry in entries:
        path = (entry.path or "").lower()
        source_log = (entry.source_log or "").lower()
        tags: list[str] = []

        if source_log.startswith("fallback"):
            tags.append("fallback")
        if source_log.startswith("default-host"):
            tags.append("unregistered_domain")
        if path and any(path.startswith(pattern) for pattern in suspicious):
            tags.append("suspicious_path")

        if not tags:
            continue

        entry.alert_tags = tags
        if "suspicious_path" in tags:
            entry.alert_type = "suspicious_path"
        else:
            entry.alert_type = tags[0]
        yield entry

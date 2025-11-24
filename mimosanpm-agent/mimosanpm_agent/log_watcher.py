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


@dataclass
class AccessLogEntry:
    """Línea parseada de un log de acceso."""

    source_ip: str
    host: str | None
    path: str
    status_code: int | None
    user_agent: str | None

    def to_alert(self) -> dict[str, object]:
        return {
            "source_ip": self.source_ip,
            "requested_host": self.host or "desconocido",
            "path": self.path,
            "user_agent": self.user_agent,
            "status_code": self.status_code,
        }


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

    def _parse_line(self, line: str) -> AccessLogEntry | None:
        match = ACCESS_REGEX.match(line)
        if not match:
            return None
        status = int(match.group("status")) if match.group("status") else None
        rest = match.group("rest") or ""
        host = self._extract_host(rest)
        return AccessLogEntry(
            source_ip=match.group("remote_addr"),
            host=host,
            path=match.group("path"),
            status_code=status,
            user_agent=match.group("user_agent") or None,
        )

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
                parsed = self._parse_line(line)
                if parsed:
                    yield parsed


def filter_unknown_domains(
    entries: Iterable[AccessLogEntry], known_domains: set[str]
) -> Iterator[AccessLogEntry]:
    known = {domain.lower() for domain in known_domains}
    for entry in entries:
        host = (entry.host or "").lower()
        if known and host in known:
            continue
        if entry.status_code is not None and entry.status_code < 400:
            continue
        if not host:
            continue
        yield entry

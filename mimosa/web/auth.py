"""Gestión básica de usuarios y autenticación para la UI web."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, *, iterations: int = 120_000) -> str:
    salt = secrets.token_hex(16)
    pepper = os.environ.get("MIMOSA_PASSWORD_PEPPER", "")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        f"{password}{pepper}".encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iterations_raw, salt, digest = password_hash.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    try:
        iterations = int(iterations_raw)
    except ValueError:
        return False
    pepper = os.environ.get("MIMOSA_PASSWORD_PEPPER", "")
    for candidate_password in (f"{password}{pepper}", password):
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            candidate_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
        if secrets.compare_digest(candidate, digest):
            return True
    return False


@dataclass
class UserAccount:
    username: str
    password_hash: str
    role: str = "viewer"
    created_at: str = ""


class UserStore:
    """Persistencia simple de usuarios en JSON."""

    def __init__(self, path: Path | str = Path("data/users.json")) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._users: Dict[str, UserAccount] = {}
        self._load()
        if not self._users:
            self._seed_default()

    def _load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8") or "[]")
        for raw in data:
            username = (raw.get("username") or "").strip().lower()
            if not username:
                continue
            account = UserAccount(
                username=username,
                password_hash=raw.get("password_hash") or "",
                role=raw.get("role") or "viewer",
                created_at=raw.get("created_at") or "",
            )
            self._users[username] = account

    def _save(self) -> None:
        payload = [asdict(user) for user in self._users.values()]
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _seed_default(self) -> None:
        self.add_user("mimosa", "mimosa", role="admin")

    def list(self) -> List[UserAccount]:
        return sorted(self._users.values(), key=lambda user: user.username)

    def get(self, username: str) -> Optional[UserAccount]:
        return self._users.get(username.strip().lower())

    def add_user(self, username: str, password: str, *, role: str = "viewer") -> UserAccount:
        normalized = username.strip().lower()
        if not normalized:
            raise ValueError("Nombre de usuario inválido")
        if normalized in self._users:
            raise ValueError("Usuario ya existe")
        if not password:
            raise ValueError("Contraseña inválida")
        account = UserAccount(
            username=normalized,
            password_hash=_hash_password(password),
            role=role or "viewer",
            created_at=_now_iso(),
        )
        self._users[normalized] = account
        self._save()
        return account

    def update_user(
        self,
        username: str,
        *,
        password: Optional[str] = None,
        role: Optional[str] = None,
    ) -> UserAccount:
        normalized = username.strip().lower()
        account = self._users.get(normalized)
        if not account:
            raise ValueError("Usuario no encontrado")
        if password:
            account.password_hash = _hash_password(password)
        if role:
            account.role = role
        self._save()
        return account

    def delete_user(self, username: str) -> None:
        normalized = username.strip().lower()
        if normalized in self._users:
            self._users.pop(normalized)
            self._save()

    def authenticate(self, username: str, password: str) -> Optional[UserAccount]:
        account = self.get(username)
        if not account:
            return None
        if not _verify_password(password, account.password_hash):
            return None
        return account

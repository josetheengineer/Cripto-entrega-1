"""Gestion de usuarios con almacenamiento simple y contrasenas Argon2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class UserManager:
    """Encapsula el registro y autenticacion de usuarios."""

    def __init__(self, storage_path: Path) -> None:
        self.storage_path = storage_path
        self._password_hasher = PasswordHasher()
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.storage_path.exists():
            self.storage_path.write_text("{}", encoding="utf-8")

    def _load_users(self) -> Dict[str, str]:
        data = self.storage_path.read_text(encoding="utf-8")
        return json.loads(data)

    def _save_users(self, users: Dict[str, str]) -> None:
        serialized = json.dumps(users, indent=2, ensure_ascii=True)
        self.storage_path.write_text(serialized, encoding="utf-8")

    def create_user(self, username: str, password: str) -> bool:
        username = username.strip()
        if not username:
            return False

        users = self._load_users()
        if username in users:
            return False

        password_hash = self._password_hasher.hash(password)
        users[username] = password_hash
        self._save_users(users)
        return True

    def register_user(self, username: str, password: str) -> None:
        username = username.strip()
        if not username:
            raise ValueError("El nombre de usuario no puede estar vacio.")

        users = self._load_users()
        if username in users:
            raise ValueError("El usuario ya existe.")

        password_hash = self._password_hasher.hash(password)
        users[username] = password_hash
        self._save_users(users)

    def authenticate_user(self, username: str, password: str) -> bool:
        users = self._load_users()
        stored_hash = users.get(username)
        if not stored_hash:
            return False

        try:
            self._password_hasher.verify(stored_hash, password)
            return True
        except VerifyMismatchError:
            return False

    def user_exists(self, username: str) -> bool:
        users = self._load_users()
        return username in users

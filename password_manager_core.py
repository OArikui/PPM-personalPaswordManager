from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import string
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:
    raise SystemExit(
        "cryptography が必要です。`python -m pip install -r requirements.txt` を実行してください。"
    ) from exc

APP_NAME = "Personal Password Manager"
APP_VERSION = "1.3.0"
VAULT_FORMAT = 2
SUPPORTED_FORMATS = {1, 2}
KDF_N = 2**16
KDF_R = 8
KDF_P = 1
SALT_BYTES = 16
AUTO_LOCK_SECONDS = 15 * 60
CLIPBOARD_CLEAR_SECONDS = 20
BASE_FIELDS: tuple[tuple[str, str], ...] = (
    ("site", "サイト・サービス名"),
    ("email", "メールアドレス"),
    ("username", "ユーザー名"),
    ("password", "パスワード"),
)


def now_string() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def app_data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "PersonalPasswordManager"


def resource_path(filename: str) -> Path:
    """開発環境と PyInstaller で同梱リソースを探す。"""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / filename


def default_vault_path() -> Path:
    return app_data_dir() / "vault.pwm"


def settings_path() -> Path:
    return app_data_dir() / "settings.json"


def load_saved_vault_path() -> Path:
    path = settings_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        saved = str(payload.get("vault_path") or "").strip()
        if saved:
            return Path(saved).expanduser()
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return default_vault_path()


def save_saved_vault_path(vault_path: Path) -> None:
    target = settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"vault_path": str(vault_path.expanduser().resolve())}
    fd, tmp_name = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass


def derive_key(master_password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    raw = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def empty_vault() -> dict[str, Any]:
    return {"entries": []}


def empty_history() -> list[dict[str, Any]]:
    return []


def snapshot_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "site": str(entry.get("site") or ""),
        "email": str(entry.get("email") or ""),
        "username": str(entry.get("username") or ""),
        "password": str(entry.get("password") or ""),
        "custom": {
            str(k): str(v)
            for k, v in (entry.get("custom") or {}).items()
            if str(k).strip()
        },
    }


def normalize_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "site": str(raw.get("site") or ""),
        "email": str(raw.get("email") or ""),
        "username": str(raw.get("username") or ""),
        "password": str(raw.get("password") or ""),
        "custom": {
            str(k): str(v)
            for k, v in (raw.get("custom") or {}).items()
            if str(k).strip()
        },
    }


def normalize_history(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        snapshot = item.get("snapshot")
        if not isinstance(snapshot, dict):
            continue
        result.append(
            {
                "id": str(item.get("id") or uuid.uuid4()),
                "timestamp": str(item.get("timestamp") or ""),
                "action": str(item.get("action") or "編集前"),
                "snapshot": normalize_snapshot(snapshot),
            }
        )
    return result


def normalize_entry(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(raw.get("id") or uuid.uuid4()),
        "site": str(raw.get("site") or ""),
        "email": str(raw.get("email") or ""),
        "username": str(raw.get("username") or ""),
        "password": str(raw.get("password") or ""),
        "custom": {
            str(k): str(v)
            for k, v in (raw.get("custom") or {}).items()
            if str(k).strip()
        },
        "created_at": str(raw.get("created_at") or ""),
        "updated_at": str(raw.get("updated_at") or ""),
        "history": normalize_history(raw.get("history")),
    }


def entry_from_snapshot(entry_id: str, snapshot: dict[str, Any], created_at: str, updated_at: str, history: list[dict[str, Any]]) -> dict[str, Any]:
    data = normalize_snapshot(snapshot)
    return {
        "id": entry_id,
        **data,
        "created_at": created_at,
        "updated_at": updated_at,
        "history": history,
    }


def generate_password(length: int = 20, *, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    if length < 8:
        raise ValueError("パスワード長は8文字以上にしてください。")
    alphabets: list[str] = []
    pools: list[str] = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!#$%&()*+,-./:;<=>?@[]^_{|}~")
    if not pools:
        raise ValueError("少なくとも1種類の文字を選択してください。")
    for pool in pools:
        alphabets.append(secrets.choice(pool))
    all_chars = "".join(pools)
    alphabets.extend(secrets.choice(all_chars) for _ in range(max(0, length - len(alphabets))))
    secrets.SystemRandom().shuffle(alphabets)
    return "".join(alphabets)


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: Path):
        self.path = path.expanduser()
        self.fernet: Fernet | None = None
        self.kdf_info: dict[str, Any] | None = None
        self.data: dict[str, Any] = empty_vault()
        self.dirty = False
        self.loaded_format = VAULT_FORMAT

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def create(self, master_password: str) -> None:
        if not master_password:
            raise VaultError("マスターパスワードが空です。")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(SALT_BYTES)
        key = derive_key(master_password, salt, KDF_N, KDF_R, KDF_P)
        self.fernet = Fernet(key)
        self.kdf_info = {
            "name": "scrypt",
            "salt": base64.b64encode(salt).decode("ascii"),
            "n": KDF_N,
            "r": KDF_R,
            "p": KDF_P,
        }
        self.data = empty_vault()
        self.loaded_format = VAULT_FORMAT
        self.dirty = True
        self.save()

    def unlock(self, master_password: str) -> None:
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            fmt = int(envelope.get("format"))
            if fmt not in SUPPORTED_FORMATS:
                raise VaultError(f"未対応の保管庫バージョンです: {fmt}")
            kdf_info = envelope["kdf"]
            if str(kdf_info.get("name")) != "scrypt":
                raise VaultError("未対応の鍵導出方式です。")
            salt = base64.b64decode(kdf_info["salt"])
            key = derive_key(
                master_password,
                salt,
                int(kdf_info["n"]),
                int(kdf_info["r"]),
                int(kdf_info["p"]),
            )
            fernet = Fernet(key)
            plaintext = fernet.decrypt(envelope["data"].encode("ascii"))
            payload = json.loads(plaintext.decode("utf-8"))
            self.fernet = fernet
            self.kdf_info = kdf_info
            self.data = {"entries": [normalize_entry(x) for x in payload.get("entries", [])]}
            self.loaded_format = fmt
            # v1 は custom を維持したまま history=[] を補完できる。
            self.dirty = fmt != VAULT_FORMAT
        except VaultError:
            raise
        except (InvalidToken, ValueError, KeyError, TypeError, json.JSONDecodeError, OSError) as exc:
            self.fernet = None
            raise VaultError("マスターパスワードが正しくないか、保管庫が壊れています。") from exc

    def save(self) -> None:
        if not self.fernet or not self.kdf_info:
            raise VaultError("保管庫がロックされています。")
        plaintext = json.dumps(self.data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        token = self.fernet.encrypt(plaintext).decode("ascii")
        envelope = {
            "format": VAULT_FORMAT,
            "kdf": self.kdf_info,
            "cipher": "fernet",
            "data": token,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="vault-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(envelope, fh, ensure_ascii=False, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self.loaded_format = VAULT_FORMAT
            self.dirty = False
        finally:
            if os.path.exists(tmp_name):
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass

    def backup_to(self, destination: Path) -> Path:
        """暗号化された保管庫ファイルをそのままバックアップする。"""
        if not self.fernet:
            raise VaultError("保管庫がロックされています。")
        if self.dirty:
            self.save()

        source = self.path.expanduser().resolve()
        target = destination.expanduser().resolve()
        if source == target:
            raise VaultError("バックアップ先に現在の保管庫は指定できません。")
        if not source.is_file():
            raise VaultError("現在の保管庫ファイルが見つかりません。")
        if target.exists():
            raise VaultError("指定したファイルは既に存在します。別の名前を指定してください。")

        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix="backup-", suffix=target.suffix or ".pwm", dir=target.parent)
        os.close(fd)
        try:
            shutil.copy2(source, temporary_name)
            with open(temporary_name, "rb") as fh:
                os.fsync(fh.fileno())
            # コピー完了後に置換するため、途中までのバックアップが見えない。
            if target.exists():
                raise VaultError("指定したファイルは既に存在します。別の名前を指定してください。")
            os.replace(temporary_name, target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(temporary_name):
                try:
                    os.remove(temporary_name)
                except OSError:
                    pass
        return target

    def restore_backup(self, backup_path: Path) -> Path:
        """同じ保管庫から作成したバックアップを検証して復元する。

        復元直前のファイルは、現在の保管庫と同じフォルダーに自動退避する。
        """
        if not self.fernet or not self.kdf_info:
            raise VaultError("保管庫がロックされています。")

        source = backup_path.expanduser().resolve()
        target = self.path.expanduser().resolve()
        if source == target:
            raise VaultError("現在使用中の保管庫そのものは復元元に指定できません。")
        if not source.is_file():
            raise VaultError("バックアップファイルが見つかりません。")

        # 先に未保存の変更を現在の保管庫へ保存し、復元前の状態を確実に残す。
        if self.dirty:
            self.save()

        try:
            envelope = json.loads(source.read_text(encoding="utf-8"))
            fmt = int(envelope.get("format"))
            if fmt not in SUPPORTED_FORMATS:
                raise VaultError(f"未対応のバックアップ形式です: {fmt}")
            if envelope.get("cipher", "fernet") != "fernet":
                raise VaultError("未対応の暗号化方式です。")
            encrypted = envelope["data"]
            plaintext = self.fernet.decrypt(str(encrypted).encode("ascii"))
            payload = json.loads(plaintext.decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("entries", []), list):
                raise VaultError("バックアップ内のデータ形式が正しくありません。")
            raw_entries = payload.get("entries", [])
            if any(not isinstance(entry, dict) for entry in raw_entries):
                raise VaultError("バックアップ内のアカウントデータが正しくありません。")
            restored_entries = [normalize_entry(entry) for entry in raw_entries]
        except VaultError:
            raise
        except (InvalidToken, ValueError, KeyError, TypeError, AttributeError, UnicodeError, OSError, json.JSONDecodeError) as exc:
            raise VaultError(
                "バックアップを読み込めません。ファイルが壊れているか、現在開いている保管庫とは別の保管庫のバックアップです。"
            ) from exc

        stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000_000:09d}"
        suffix = target.suffix or ".pwm"
        safety_backup = target.with_name(f"{target.stem}.before-restore-{stamp}{suffix}")
        shutil.copy2(target, safety_backup)
        try:
            os.chmod(safety_backup, 0o600)
        except OSError:
            pass

        previous_data = self.data
        previous_format = self.loaded_format
        self.data = {"entries": restored_entries}
        self.dirty = True
        try:
            self.save()
        except Exception as exc:
            self.data = previous_data
            self.loaded_format = previous_format
            self.dirty = False
            # save() は置換方式だが、念のため退避ファイルから元へ戻す。
            try:
                shutil.copy2(safety_backup, target)
            except OSError as rollback_exc:
                raise VaultError(
                    f"復元に失敗し、元の保管庫への巻き戻しも失敗しました。退避ファイル: {safety_backup}\n{rollback_exc}"
                ) from exc
            raise VaultError(f"復元に失敗しました。元の保管庫は維持されています。\n{exc}") from exc
        return safety_backup

    def lock(self) -> None:
        self.fernet = None
        self.kdf_info = None
        self.data = empty_vault()
        self.dirty = False

    def find(self, entry_id: str | None) -> dict[str, Any] | None:
        if not entry_id:
            return None
        return next((e for e in self.data.get("entries", []) if e.get("id") == entry_id), None)

    def record_history(self, entry: dict[str, Any], action: str) -> None:
        history = entry.setdefault("history", [])
        history.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": now_string(),
                "action": action,
                "snapshot": snapshot_entry(entry),
            }
        )
        # 永遠に肥大化するのを防ぐため、1アカウントあたり最大200世代。
        if len(history) > 200:
            del history[:-200]

    def update_entry(self, entry_id: str, new_snapshot: dict[str, Any]) -> dict[str, Any]:
        entry = self.find(entry_id)
        if not entry:
            raise VaultError("対象アカウントが見つかりません。")
        self.record_history(entry, "編集前")
        data = normalize_snapshot(new_snapshot)
        entry.update(data)
        entry["updated_at"] = now_string()
        self.dirty = True
        return entry

    def append_entry(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        now = now_string()
        entry = {
            "id": str(uuid.uuid4()),
            **normalize_snapshot(snapshot),
            "created_at": now,
            "updated_at": now,
            "history": [],
        }
        self.data.setdefault("entries", []).append(entry)
        self.dirty = True
        return entry

    def restore_history(self, entry_id: str, history_id: str) -> dict[str, Any]:
        entry = self.find(entry_id)
        if not entry:
            raise VaultError("対象アカウントが見つかりません。")
        history = entry.get("history", [])
        target = next((h for h in history if h.get("id") == history_id), None)
        if not target:
            raise VaultError("対象の履歴が見つかりません。")
        self.record_history(entry, "復元前")
        restored = normalize_snapshot(target.get("snapshot") or {})
        entry.update(restored)
        entry["updated_at"] = now_string()
        self.dirty = True
        return entry



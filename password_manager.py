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
from typing import Any, Callable

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:
    raise SystemExit(
        "cryptography が必要です。`python -m pip install -r requirements.txt` を実行してください。"
    ) from exc

APP_NAME = "Personal Password Manager"
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


class PasswordGeneratorDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, on_apply: Callable[[str], None]):
        super().__init__(parent)
        self.title("パスワード生成")
        self.resizable(False, False)
        self.on_apply = on_apply
        self.length_var = tk.IntVar(value=20)
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.result_var = tk.StringVar()

        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="長さ").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Spinbox(frame, from_=8, to=128, textvariable=self.length_var, width=8).grid(row=0, column=1, sticky="w", pady=4)
        for row, (text, var) in enumerate(
            (("大文字", self.upper_var), ("小文字", self.lower_var), ("数字", self.digits_var), ("記号", self.symbols_var)), start=1
        ):
            ttk.Checkbutton(frame, text=text, variable=var).grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Entry(frame, textvariable=self.result_var, width=42).grid(row=5, column=0, columnspan=2, pady=(8, 4))
        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(buttons, text="再生成", command=self.generate).pack(side="left", padx=3)
        ttk.Button(buttons, text="この値を使う", command=self.apply).pack(side="left", padx=3)
        ttk.Button(buttons, text="閉じる", command=self.destroy).pack(side="left", padx=3)
        self.bind("<Escape>", lambda _e: self.destroy())
        self.generate()
        self.transient(parent)
        self.grab_set()

    def generate(self) -> None:
        try:
            value = generate_password(
                int(self.length_var.get()),
                use_upper=self.upper_var.get(),
                use_lower=self.lower_var.get(),
                use_digits=self.digits_var.get(),
                use_symbols=self.symbols_var.get(),
            )
            self.result_var.set(value)
        except (ValueError, tk.TclError) as exc:
            messagebox.showwarning(APP_NAME, str(exc), parent=self)

    def apply(self) -> None:
        value = self.result_var.get()
        if value:
            self.on_apply(value)
            self.destroy()


class HistoryDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, app: "PasswordManagerApp", entry: dict[str, Any]):
        super().__init__(parent)
        self.app = app
        self.entry = entry
        self.title(f"変更履歴 - {entry.get('site') or '(未設定)'}")
        self.geometry("900x560")
        self.minsize(760, 460)
        self.selected_history_id: str | None = None

        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="このアカウントの変更履歴（古い順）", font=("TkDefaultFont", 11, "bold")).pack(anchor="w", pady=(0, 8))
        paned = ttk.PanedWindow(outer, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned, padding=(0, 0, 8, 0))
        right = ttk.Frame(paned, padding=(8, 0, 0, 0))
        paned.add(left, weight=1)
        paned.add(right, weight=2)

        columns = ("timestamp", "action")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("timestamp", text="日時")
        self.tree.heading("action", text="操作")
        self.tree.column("timestamp", width=155)
        self.tree.column("action", width=90)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        self.preview = tk.Text(right, wrap="word", state="disabled", relief="solid", borderwidth=1)
        self.preview.pack(fill="both", expand=True)

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="選択した状態に復元", command=self.restore).pack(side="left")
        ttk.Button(buttons, text="閉じる", command=self.destroy).pack(side="right")
        self.refresh()
        self.transient(parent)

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for item in self.entry.get("history", []):
            self.tree.insert("", "end", iid=item["id"], values=(item.get("timestamp", ""), item.get("action", "")))
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.configure(state="disabled")

    def on_select(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        self.selected_history_id = selected[0]
        item = next((h for h in self.entry.get("history", []) if h.get("id") == self.selected_history_id), None)
        if item:
            snapshot = item.get("snapshot", {})
            self.preview.configure(state="normal")
            self.preview.delete("1.0", "end")
            self.preview.insert("1.0", self.app.format_snapshot(snapshot, reveal=True))
            self.preview.configure(state="disabled")

    def restore(self) -> None:
        if not self.selected_history_id:
            messagebox.showinfo(APP_NAME, "復元する履歴を選択してください。", parent=self)
            return
        if not messagebox.askyesno(
            APP_NAME,
            "この履歴の状態へ復元しますか？\n\n現在の状態も復元前の履歴として残ります。",
            parent=self,
        ):
            return
        try:
            restored = self.app.vault.restore_history(self.entry["id"], self.selected_history_id)
            self.app.vault.save()
            self.app.selected_id = restored["id"]
            self.app.refresh_tree()
            self.app.show_selected_details()
            self.entry = restored
            self.refresh()
            messagebox.showinfo(APP_NAME, "履歴を復元しました。", parent=self)
        except (VaultError, OSError) as exc:
            messagebox.showerror(APP_NAME, f"復元に失敗しました。\n{exc}", parent=self)


class PasswordManagerApp:
    def __init__(self, root: tk.Tk, vault: Vault):
        self.root = root
        self.vault = vault
        self.selected_id: str | None = None
        self.group_mode = tk.StringVar(value="site")
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="ロック中")
        self.clipboard_generation = 0
        self.auto_lock_after_id: str | None = None
        self.revealed_details = False
        self.editor: tk.Toplevel | None = None

        root.title(APP_NAME)
        root.geometry("1200x760")
        root.minsize(980, 620)
        self._set_window_icon()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._show_unlock_or_setup()

    def _set_window_icon(self) -> None:
        """ウィンドウ／タスクバーに同梱アイコンを設定する。"""
        ico_path = resource_path("favicon.ico")
        png_path = resource_path("favicon.png")
        if os.name == "nt" and ico_path.is_file():
            try:
                self.root.iconbitmap(default=str(ico_path))
            except tk.TclError:
                pass
        if png_path.is_file():
            try:
                self._icon_image = tk.PhotoImage(file=str(png_path))
                self.root.iconphoto(True, self._icon_image)
            except tk.TclError:
                self._icon_image = None

    def _show_unlock_or_setup(self) -> None:
        if self.vault.exists:
            self._ask_unlock()
        else:
            self._ask_create()

    def _ask_create(self) -> None:
        while True:
            pwd = simpledialog.askstring(APP_NAME, "新しいマスターパスワードを入力してください。\n（10文字以上を推奨）", show="*", parent=self.root)
            if pwd is None:
                self.root.destroy()
                return
            if len(pwd) < 10:
                messagebox.showwarning(APP_NAME, "マスターパスワードは10文字以上を推奨します。", parent=self.root)
                continue
            confirm = simpledialog.askstring(APP_NAME, "もう一度入力してください。", show="*", parent=self.root)
            if confirm != pwd:
                messagebox.showerror(APP_NAME, "確認用パスワードが一致しません。", parent=self.root)
                continue
            try:
                self.vault.create(pwd)
            except Exception as exc:
                messagebox.showerror(APP_NAME, f"保管庫の作成に失敗しました。\n{exc}", parent=self.root)
                self.root.destroy()
                return
            messagebox.showinfo(APP_NAME, "保管庫を作成しました。\nマスターパスワードは復元できません。", parent=self.root)
            self._build_ui()
            return

    def _ask_unlock(self) -> None:
        while True:
            pwd = simpledialog.askstring(APP_NAME, f"マスターパスワードを入力してください。\n\n保管庫:\n{self.vault.path}", show="*", parent=self.root)
            if pwd is None:
                self.root.destroy()
                return
            try:
                self.vault.unlock(pwd)
            except VaultError as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=self.root)
                continue
            if self.vault.loaded_format != VAULT_FORMAT:
                try:
                    self.vault.save()
                    messagebox.showinfo(APP_NAME, "旧形式の保管庫を最新版へ移行しました。", parent=self.root)
                except Exception as exc:
                    messagebox.showwarning(APP_NAME, f"旧形式の読み込みはできましたが、移行保存に失敗しました。\n{exc}", parent=self.root)
            self._build_ui()
            return

    def _build_ui(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()
        self.root.unbind_all("<Any-KeyPress>")
        self.root.unbind_all("<Any-Button>")
        self.root.bind_all("<Any-KeyPress>", self._touch)
        self.root.bind_all("<Any-Button>", self._touch)

        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        toolbar = ttk.Frame(outer)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="＋ 新規", command=self.new_entry).pack(side="left", padx=(0, 5))
        ttk.Button(toolbar, text="編集", command=self.edit_selected).pack(side="left", padx=5)
        ttk.Button(toolbar, text="削除", command=self.delete_selected).pack(side="left", padx=5)
        ttk.Button(toolbar, text="🕘 変更履歴", command=self.open_history).pack(side="left", padx=5)
        ttk.Button(toolbar, text="🔑 パスワードをコピー", command=self.copy_password).pack(side="left", padx=5)
        ttk.Button(toolbar, text="表示/非表示", command=self.toggle_detail_values).pack(side="left", padx=5)
        ttk.Button(toolbar, text="📁 保存先", command=self.change_vault_location).pack(side="left", padx=5)
        ttk.Button(toolbar, text="💾 バックアップ", command=self.backup_vault).pack(side="left", padx=5)
        ttk.Button(toolbar, text="↩ バックアップ復元", command=self.restore_vault_backup).pack(side="left", padx=5)
        ttk.Button(toolbar, text="🔒 ロック", command=self.lock).pack(side="right")

        search_frame = ttk.Frame(outer)
        search_frame.pack(fill="x", pady=(0, 8))
        ttk.Label(search_frame, text="検索").pack(side="left", padx=(0, 6))
        search = ttk.Entry(search_frame, textvariable=self.search_var)
        search.pack(side="left", fill="x", expand=True)
        self.search_var.trace_add("write", lambda *_: self.refresh_tree())
        ttk.Button(search_frame, text="クリア", command=lambda: self.search_var.set("")).pack(side="left", padx=(6, 0))

        mode_frame = ttk.Frame(outer)
        mode_frame.pack(fill="x", pady=(0, 8))
        ttk.Label(mode_frame, text="表示単位:").pack(side="left", padx=(0, 8))
        for label, value in (("サイト・サービス別", "site"), ("メールアドレス別", "email"), ("ユーザー名別", "username")):
            ttk.Radiobutton(mode_frame, text=label, variable=self.group_mode, value=value, command=self.refresh_tree).pack(side="left", padx=(0, 14))

        paned = ttk.PanedWindow(outer, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned, padding=(0, 0, 8, 0))
        right = ttk.Frame(paned, padding=(8, 0, 0, 0))
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        columns = ("site", "email", "username", "updated")
        self.tree = ttk.Treeview(left, columns=columns, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="グループ / アカウント")
        self.tree.heading("site", text="サイト・サービス")
        self.tree.heading("email", text="メールアドレス")
        self.tree.heading("username", text="ユーザー名")
        self.tree.heading("updated", text="最終更新")
        self.tree.column("#0", width=220, stretch=True)
        self.tree.column("site", width=190, stretch=True)
        self.tree.column("email", width=220, stretch=True)
        self.tree.column("username", width=180, stretch=True)
        self.tree.column("updated", width=145, stretch=False)
        self.tree.tag_configure("group", font=("TkDefaultFont", 10, "bold"))
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Double-1>", lambda _e: self.edit_selected())

        ttk.Label(right, text="詳細", font=("TkDefaultFont", 12, "bold")).pack(anchor="w", pady=(0, 8))
        self.detail_text = tk.Text(right, height=20, wrap="word", state="disabled", relief="solid", borderwidth=1)
        self.detail_text.pack(fill="both", expand=True)

        status = ttk.Label(outer, textvariable=self.status_var, anchor="w")
        status.pack(fill="x", pady=(8, 0))
        self.refresh_tree()
        self.schedule_auto_lock()

    def _touch(self, _event=None) -> None:
        if self.vault.fernet:
            self.schedule_auto_lock()

    def schedule_auto_lock(self) -> None:
        if not self.vault.fernet:
            return
        if self.auto_lock_after_id:
            try:
                self.root.after_cancel(self.auto_lock_after_id)
            except tk.TclError:
                pass
        self.auto_lock_after_id = self.root.after(AUTO_LOCK_SECONDS * 1000, self.lock)

    def filtered_entries(self) -> list[dict[str, Any]]:
        needle = self.search_var.get().strip().casefold() if hasattr(self, "search_var") else ""
        entries = self.vault.data.get("entries", [])
        if not needle:
            return list(entries)
        result = []
        for entry in entries:
            values = [entry.get("site", ""), entry.get("email", ""), entry.get("username", ""), entry.get("password", "")]
            values.extend(f"{k} {v}" for k, v in entry.get("custom", {}).items())
            haystack = "\n".join(values).casefold()
            if needle in haystack:
                result.append(entry)
        return result

    def refresh_tree(self) -> None:
        if not hasattr(self, "tree"):
            return
        self.tree.delete(*self.tree.get_children())
        entries = self.filtered_entries()
        groups: dict[str, list[dict[str, Any]]] = {}
        label_key = self.group_mode.get()
        for entry in entries:
            label = entry.get(label_key, "") or "(未設定)"
            groups.setdefault(label, []).append(entry)
        for group_label in sorted(groups, key=lambda x: x.casefold()):
            group_entries = groups[group_label]
            group_id = self.tree.insert("", "end", text=f"{group_label}  ({len(group_entries)})", tags=("group",), open=True)
            for entry in sorted(group_entries, key=lambda e: (e.get("site", "").casefold(), e.get("email", "").casefold(), e.get("username", "").casefold())):
                self.tree.insert(
                    group_id,
                    "end",
                    iid=entry["id"],
                    text=entry.get("site") or "(サイト未設定)",
                    values=(entry.get("site", ""), entry.get("email", ""), entry.get("username", ""), entry.get("updated_at", "")),
                )
        self.status_var.set(f"{len(entries)} 件 / 合計 {len(self.vault.data.get('entries', []))} 件    保存先: {self.vault.path}")
        self._clear_details_if_missing()

    def _clear_details_if_missing(self) -> None:
        if self.selected_id and not self.vault.find(self.selected_id):
            self.selected_id = None
            self._show_details(None)

    def on_tree_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        entry = self.vault.find(selection[0])
        if entry:
            self.selected_id = entry["id"]
            self._show_details(entry)

    @staticmethod
    def _looks_secret(field_name: str) -> bool:
        s = field_name.casefold().replace(" ", "")
        needles = ("password", "pass", "secret", "token", "apikey", "api_key", "パスワード", "秘密", "鍵")
        return any(n in s for n in needles)

    def format_snapshot(self, snapshot: dict[str, Any], reveal: bool = False) -> str:
        lines = [
            f"サイト・サービス: {snapshot.get('site', '')}",
            f"メールアドレス: {snapshot.get('email', '')}",
            f"ユーザー名: {snapshot.get('username', '')}",
        ]
        password = str(snapshot.get("password", ""))
        lines.append(f"パスワード: {password if reveal else '●' * max(8, min(16, len(password) or 8))}")
        custom = snapshot.get("custom", {}) or {}
        if custom:
            lines.append("")
            lines.append("カスタム項目:")
            for key in sorted(custom, key=str.casefold):
                value = str(custom[key])
                if reveal or not self._looks_secret(key):
                    shown = value
                else:
                    shown = "●" * max(8, min(16, len(value) or 8))
                lines.append(f"  {key}: {shown}")
        return "\n".join(lines)

    def _show_details(self, entry: dict[str, Any] | None) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        if entry:
            text = self.format_snapshot(entry, reveal=self.revealed_details)
            text += "\n\n"
            text += f"作成日時: {entry.get('created_at', '')}\n"
            text += f"最終更新: {entry.get('updated_at', '')}\n"
            text += f"変更履歴: {len(entry.get('history', []))} 件"
            self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def show_selected_details(self) -> None:
        self._show_details(self.vault.find(self.selected_id))

    def toggle_detail_values(self) -> None:
        self.revealed_details = not self.revealed_details
        self.show_selected_details()

    def _candidate_values(self, field: str, custom_name: str | None = None) -> list[str]:
        values: list[str] = []
        for entry in self.vault.data.get("entries", []):
            if field == "custom":
                values.append(str((entry.get("custom") or {}).get(custom_name or "", "")))
                for history in entry.get("history", []):
                    snap = history.get("snapshot", {}) or {}
                    values.append(str((snap.get("custom") or {}).get(custom_name or "", "")))
            else:
                values.append(str(entry.get(field, "")))
                for history in entry.get("history", []):
                    snap = history.get("snapshot", {}) or {}
                    values.append(str(snap.get(field, "")))
        return [v for v in unique_preserve_order(values) if v != ""]

    def custom_field_names(self) -> list[str]:
        names: list[str] = []
        for entry in self.vault.data.get("entries", []):
            names.extend((entry.get("custom") or {}).keys())
            for history in entry.get("history", []):
                names.extend((history.get("snapshot") or {}).get("custom", {}).keys())
        return sorted(unique_preserve_order([str(n).strip() for n in names if str(n).strip()]), key=str.casefold)

    def new_entry(self) -> None:
        if not self.vault.fernet:
            return
        self._open_entry_editor({"id": str(uuid.uuid4()), **normalize_snapshot({}), "created_at": now_string(), "updated_at": now_string(), "history": []}, is_new=True)

    def edit_selected(self) -> None:
        entry = self.vault.find(self.selected_id)
        if entry:
            self._open_entry_editor(entry, is_new=False)
        else:
            messagebox.showinfo(APP_NAME, "編集するアカウントを選択してください。", parent=self.root)

    def _open_entry_editor(self, entry: dict[str, Any], is_new: bool) -> None:
        if self.editor is not None and self.editor.winfo_exists():
            self.editor.lift()
            return
        win = tk.Toplevel(self.root)
        self.editor = win
        win.title("新規アカウント" if is_new else "アカウント編集")
        win.geometry("760x650")
        win.minsize(640, 520)
        win.transient(self.root)

        outer = ttk.Frame(win, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="基本項目", font=("TkDefaultFont", 11, "bold")).pack(anchor="w", pady=(0, 6))
        form = ttk.Frame(outer)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        entries: dict[str, ttk.Combobox] = {}
        variables: dict[str, tk.StringVar] = {}

        def make_combo(key: str, label: str, row: int, show: str | None = None) -> ttk.Combobox:
            var = tk.StringVar(value=str(entry.get(key, "")))
            variables[key] = var
            combo = ttk.Combobox(form, textvariable=var, values=self._candidate_values(key), state="normal", width=50)
            if show:
                # ttk.Combobox の show は EntryOption として働くため、候補の選択性を優先して表示する。
                pass
            ttk.Label(form, text=label, width=16).grid(row=row, column=0, sticky="w", pady=5)
            combo.grid(row=row, column=1, sticky="ew", padx=8, pady=5)
            entries[key] = combo
            return combo

        make_combo("site", "サイト・サービス名", 0)
        make_combo("email", "メールアドレス", 1)
        make_combo("username", "ユーザー名", 2)
        password_combo = make_combo("password", "パスワード", 3)

        password_buttons = ttk.Frame(form)
        password_buttons.grid(row=4, column=1, sticky="w", padx=8, pady=(0, 6))
        ttk.Button(password_buttons, text="生成", command=lambda: PasswordGeneratorDialog(win, lambda value: variables["password"].set(value))).pack(side="left")
        ttk.Label(password_buttons, text="候補には過去の現在値・変更履歴が含まれます。", foreground="#666").pack(side="left", padx=8)

        ttk.Separator(outer).pack(fill="x", pady=10)
        custom_header = ttk.Frame(outer)
        custom_header.pack(fill="x")
        ttk.Label(custom_header, text="カスタム項目", font=("TkDefaultFont", 11, "bold")).pack(side="left")
        ttk.Button(custom_header, text="＋ 項目を追加", command=lambda: add_custom_row()).pack(side="right")
        ttk.Label(outer, text="項目名も値も、過去の登録内容から候補表示されます。", foreground="#666").pack(anchor="w", pady=(3, 6))

        custom_container = ttk.Frame(outer)
        custom_container.pack(fill="both", expand=True)
        canvas = tk.Canvas(custom_container, highlightthickness=0)
        scroll = ttk.Scrollbar(custom_container, orient="vertical", command=canvas.yview)
        rows_frame = ttk.Frame(canvas)
        rows_frame.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=rows_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        custom_rows: list[dict[str, Any]] = []

        def add_custom_row(name: str = "", value: str = "") -> None:
            row_idx = len(custom_rows)
            name_var = tk.StringVar(value=name)
            value_var = tk.StringVar(value=value)
            name_combo = ttk.Combobox(rows_frame, textvariable=name_var, values=self.custom_field_names(), state="normal", width=24)
            value_combo = ttk.Combobox(rows_frame, textvariable=value_var, state="normal", width=44)
            remove = ttk.Button(rows_frame, text="削除", width=7, command=lambda rv=(name_var, value_var, name_combo, value_combo): remove_custom_row(rv))
            name_combo.grid(row=row_idx, column=0, sticky="ew", padx=(0, 6), pady=3)
            value_combo.grid(row=row_idx, column=1, sticky="ew", padx=(0, 6), pady=3)
            remove.grid(row=row_idx, column=2, pady=3)
            rows_frame.columnconfigure(0, weight=1)
            rows_frame.columnconfigure(1, weight=2)
            row_info = {"name": name_var, "value": value_var, "name_combo": name_combo, "value_combo": value_combo, "remove": remove}
            custom_rows.append(row_info)

            def update_values(_event=None, vi=value_var, nc=name_combo, vc=value_combo) -> None:
                vc.configure(values=self._candidate_values("custom", nc.get().strip()))
                if vi.get() == "":
                    vc.set("")

            name_combo.bind("<<ComboboxSelected>>", update_values)
            name_combo.bind("<FocusOut>", update_values)
            update_values()

        def remove_custom_row(row_info: tuple[Any, ...]) -> None:
            name_var, value_var, name_combo, value_combo = row_info
            for widget in (name_combo, value_combo, custom_rows[next(i for i, r in enumerate(custom_rows) if r["name"] is name_var)]["remove"]):
                widget.destroy()
            custom_rows[:] = [r for r in custom_rows if r["name"] is not name_var]
            # 行位置を詰める。
            for idx, row in enumerate(custom_rows):
                row["name_combo"].grid_configure(row=idx)
                row["value_combo"].grid_configure(row=idx)
                row["remove"].grid_configure(row=idx)
            rows_frame.update_idletasks()

        for name, value in sorted((entry.get("custom") or {}).items(), key=lambda kv: kv[0].casefold()):
            add_custom_row(name, value)
        if not custom_rows:
            add_custom_row()

        button_bar = ttk.Frame(outer)
        button_bar.pack(fill="x", pady=(10, 0))

        def save_entry() -> None:
            site = variables["site"].get().strip()
            email = variables["email"].get().strip()
            username = variables["username"].get().strip()
            password = variables["password"].get()
            custom: dict[str, str] = {}
            for row in custom_rows:
                name = row["name"].get().strip()
                value = row["value"].get()
                if not name and not value:
                    continue
                if not name:
                    messagebox.showwarning(APP_NAME, "カスタム項目の項目名を入力してください。", parent=win)
                    return
                if name in {label for _, label in BASE_FIELDS} or name in {key for key, _ in BASE_FIELDS}:
                    messagebox.showwarning(APP_NAME, f"基本項目と同名のカスタム項目は使えません: {name}", parent=win)
                    return
                if name in custom:
                    messagebox.showwarning(APP_NAME, f"カスタム項目「{name}」が重複しています。", parent=win)
                    return
                custom[name] = value

            snapshot = {"site": site, "email": email, "username": username, "password": password, "custom": custom}
            try:
                if is_new:
                    new_entry = self.vault.append_entry(snapshot)
                else:
                    new_entry = self.vault.update_entry(entry["id"], snapshot)
                self.vault.save()
            except (VaultError, OSError) as exc:
                messagebox.showerror(APP_NAME, f"保存に失敗しました。\n{exc}", parent=win)
                return
            self.selected_id = new_entry["id"]
            self.refresh_tree()
            self.show_selected_details()
            self.status_var.set(f"保存しました: {self.vault.path}")
            win.destroy()
            self.editor = None

        ttk.Button(button_bar, text="保存", command=save_entry).pack(side="right", padx=(6, 0))
        ttk.Button(button_bar, text="キャンセル", command=lambda: (win.destroy(), setattr(self, "editor", None))).pack(side="right")
        win.bind("<Escape>", lambda _e: (win.destroy(), setattr(self, "editor", None)))
        win.bind("<Control-Return>", lambda _e: save_entry())

    def delete_selected(self) -> None:
        entry = self.vault.find(self.selected_id)
        if not entry:
            messagebox.showinfo(APP_NAME, "削除するアカウントを選択してください。", parent=self.root)
            return
        label = entry.get("site") or entry.get("email") or entry.get("username") or "名称未設定"
        if not messagebox.askyesno(APP_NAME, f"「{label}」を削除しますか？\n\nこの操作は履歴からは復元できません。", parent=self.root):
            return
        self.vault.data["entries"] = [e for e in self.vault.data["entries"] if e.get("id") != entry["id"]]
        self.vault.dirty = True
        try:
            self.vault.save()
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"削除後の保存に失敗しました。\n{exc}", parent=self.root)
            return
        self.selected_id = None
        self._show_details(None)
        self.refresh_tree()

    def copy_password(self) -> None:
        entry = self.vault.find(self.selected_id)
        if not entry:
            messagebox.showinfo(APP_NAME, "パスワードをコピーするアカウントを選択してください。", parent=self.root)
            return
        password = entry.get("password", "")
        if not password:
            messagebox.showinfo(APP_NAME, "パスワードが空です。", parent=self.root)
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
            self.clipboard_generation += 1
            generation = self.clipboard_generation
            self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000, lambda: self._clear_clipboard(generation, password))
            self.status_var.set(f"パスワードをコピーしました（{CLIPBOARD_CLEAR_SECONDS}秒後に自動消去）")
        except tk.TclError:
            messagebox.showerror(APP_NAME, "クリップボードへのコピーに失敗しました。", parent=self.root)

    def _clear_clipboard(self, generation: int, expected: str) -> None:
        if generation != self.clipboard_generation:
            return
        try:
            current = self.root.clipboard_get()
        except tk.TclError:
            return
        if current == expected:
            try:
                self.root.clipboard_clear()
                self.root.update()
            except tk.TclError:
                pass

    def open_history(self) -> None:
        entry = self.vault.find(self.selected_id)
        if not entry:
            messagebox.showinfo(APP_NAME, "履歴を表示するアカウントを選択してください。", parent=self.root)
            return
        if not entry.get("history"):
            messagebox.showinfo(APP_NAME, "このアカウントにはまだ変更履歴がありません。\n編集すると、その直前の状態が履歴に保存されます。", parent=self.root)
            return
        HistoryDialog(self.root, self, entry)

    def backup_vault(self) -> None:
        if not self.vault.fernet:
            messagebox.showwarning(APP_NAME, "先に保管庫のロックを解除してください。", parent=self.root)
            return
        current = self.vault.path.expanduser().resolve()
        suggested = f"{current.stem}-backup-{time.strftime('%Y%m%d-%H%M%S')}.pwm"
        selected = filedialog.asksaveasfilename(
            parent=self.root,
            title="暗号化保管庫のバックアップ先を選択",
            initialdir=str(current.parent),
            initialfile=suggested,
            defaultextension=".pwm",
            filetypes=[("Password Manager 暗号化バックアップ", "*.pwm"), ("すべてのファイル", "*.*")],
        )
        if not selected:
            return
        try:
            destination = self.vault.backup_to(Path(selected))
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"バックアップに失敗しました。\n\n{exc}", parent=self.root)
            return
        messagebox.showinfo(
            APP_NAME,
            f"バックアップを作成しました。\n\n{destination}\n\nバックアップも暗号化されています。復元には同じ保管庫のマスターパスワードが必要です。",
            parent=self.root,
        )
        self.status_var.set(f"バックアップを作成しました: {destination}")

    def restore_vault_backup(self) -> None:
        if not self.vault.fernet:
            messagebox.showwarning(APP_NAME, "先に保管庫のロックを解除してください。", parent=self.root)
            return
        selected = filedialog.askopenfilename(
            parent=self.root,
            title="復元するバックアップを選択",
            initialdir=str(self.vault.path.expanduser().resolve().parent),
            filetypes=[("Password Manager バックアップ", "*.pwm"), ("すべてのファイル", "*.*")],
        )
        if not selected:
            return
        backup_path = Path(selected).expanduser().resolve()
        if backup_path == self.vault.path.expanduser().resolve():
            messagebox.showinfo(APP_NAME, "現在使用中の保管庫そのものは選択できません。", parent=self.root)
            return
        if not messagebox.askyesno(
            APP_NAME,
            "選択したバックアップの状態に置き換えます。\n現在のデータは復元後の保管庫からは見えなくなります。\n\n復元直前の保管庫ファイルは自動で別名保存されます。\n続行しますか？",
            icon="warning",
            parent=self.root,
        ):
            return
        try:
            safety_backup = self.vault.restore_backup(backup_path)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"バックアップの復元に失敗しました。\n\n{exc}", parent=self.root)
            return
        self.selected_id = None
        self._show_details(None)
        self.refresh_tree()
        self.status_var.set(f"バックアップを復元しました: {backup_path}")
        messagebox.showinfo(
            APP_NAME,
            f"バックアップを復元しました。\n\n復元前の保管庫は次のファイルへ退避しました。\n{safety_backup}",
            parent=self.root,
        )

    def change_vault_location(self) -> None:
        if not self.vault.fernet:
            return
        try:
            if self.vault.dirty:
                self.vault.save()
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"変更前の保存に失敗しました。\n{exc}", parent=self.root)
            return
        current = self.vault.path.expanduser().resolve()
        selected = filedialog.asksaveasfilename(
            parent=self.root,
            title="新しい保管庫の保存先を選択",
            initialdir=str(current.parent),
            initialfile=current.name,
            defaultextension=".pwm",
            filetypes=[("Password Manager 保管庫", "*.pwm"), ("すべてのファイル", "*.*")],
        )
        if not selected:
            return
        destination = Path(selected).expanduser().resolve()
        if destination == current:
            messagebox.showinfo(APP_NAME, "現在と同じ保存先です。", parent=self.root)
            return
        if destination.exists():
            messagebox.showwarning(APP_NAME, "指定先には既にファイルがあります。\n既存の保管庫を上書きしない設計です。", parent=self.root)
            return
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(current, destination)
            envelope = json.loads(destination.read_text(encoding="utf-8"))
            if int(envelope.get("format")) not in SUPPORTED_FORMATS:
                raise VaultError("新しい保管庫の形式を確認できませんでした。")
            self.vault.fernet.decrypt(envelope["data"].encode("ascii"))
            save_saved_vault_path(destination)
            self.vault.path = destination
            messagebox.showinfo(APP_NAME, f"保存先を変更しました。\n\n新しい保存先:\n{destination}\n\n旧ファイルは自動削除せず、バックアップとして残しています。", parent=self.root)
            self.refresh_tree()
        except Exception as exc:
            try:
                if destination.exists():
                    destination.unlink()
            except OSError:
                pass
            messagebox.showerror(APP_NAME, f"保存先の変更に失敗しました。\n\n{exc}", parent=self.root)

    def lock(self) -> None:
        if not self.vault.fernet:
            return
        if self.vault.dirty:
            try:
                self.vault.save()
            except Exception as exc:
                messagebox.showerror(APP_NAME, f"ロック前の保存に失敗しました。\n{exc}", parent=self.root)
                return
        self.vault.lock()
        self.selected_id = None
        self.root.unbind_all("<Any-KeyPress>")
        self.root.unbind_all("<Any-Button>")
        for child in self.root.winfo_children():
            child.destroy()
        self.status_var.set("ロック中")
        messagebox.showinfo(APP_NAME, "保管庫をロックしました。", parent=self.root)
        self._ask_unlock()

    def on_close(self) -> None:
        try:
            if self.vault.fernet and self.vault.dirty:
                self.vault.save()
        except Exception as exc:
            if not messagebox.askyesno(APP_NAME, f"保存に失敗しました。終了しますか？\n\n{exc}", parent=self.root):
                return
        try:
            self.root.clipboard_clear()
            self.root.update()
        except tk.TclError:
            pass
        self.root.destroy()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--vault", help="使用する保管庫ファイル (*.pwm)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    vault_path = Path(args.vault).expanduser() if args.vault else load_saved_vault_path()
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("clam")
    except tk.TclError:
        pass
    PasswordManagerApp(root, Vault(vault_path))
    root.mainloop()


if __name__ == "__main__":
    main()

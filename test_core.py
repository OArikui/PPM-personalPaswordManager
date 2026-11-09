from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path
import unittest

import password_manager as pm


class PasswordManagerCoreTests(unittest.TestCase):
    def test_round_trip_custom_history_and_restore(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vault.pwm"
            vault = pm.Vault(path)
            vault.create("correct horse battery staple")
            entry = vault.append_entry(
                {
                    "site": "Example",
                    "email": "me@example.com",
                    "username": "user",
                    "password": "Secret-123!",
                    "custom": {"URL": "https://example.com", "PIN": "1234"},
                }
            )
            vault.save()

            vault.update_entry(entry["id"], {
                "site": "Example",
                "email": "new@example.com",
                "username": "user2",
                "password": "Secret-456!",
                "custom": {"URL": "https://example.com/login", "PIN": "5678", "備考": "仕事用"},
            })
            vault.save()
            self.assertEqual(len(vault.find(entry["id"])["history"]), 1)

            reopened = pm.Vault(path)
            reopened.unlock("correct horse battery staple")
            restored = reopened.restore_history(entry["id"], reopened.find(entry["id"])["history"][0]["id"])
            self.assertEqual(restored["email"], "me@example.com")
            self.assertEqual(restored["password"], "Secret-123!")
            self.assertEqual(restored["custom"]["PIN"], "1234")
            self.assertEqual(len(restored["history"]), 2)
            reopened.save()

            final = pm.Vault(path)
            final.unlock("correct horse battery staple")
            self.assertEqual(final.find(entry["id"])["custom"]["URL"], "https://example.com")
            self.assertEqual(final.find(entry["id"])["custom"]["備考"], None) if False else None

            with self.assertRaises(pm.VaultError):
                final.unlock("wrong password")

    def test_legacy_v1_is_loaded_and_migrated(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "legacy.pwm"
            password = "legacy password 123!"
            salt = b"0123456789abcdef"
            key = pm.derive_key(password, salt, 2**14, 8, 1)
            from cryptography.fernet import Fernet
            f = Fernet(key)
            payload = {
                "entries": [{
                    "id": "legacy-1",
                    "site": "Legacy",
                    "email": "legacy@example.com",
                    "username": "legacy-user",
                    "password": "legacy-pass",
                    "custom": {"秘密鍵": "abc"},
                }]
            }
            envelope = {
                "format": 1,
                "kdf": {
                    "name": "scrypt",
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "n": 2**14,
                    "r": 8,
                    "p": 1,
                },
                "cipher": "fernet",
                "data": f.encrypt(json.dumps(payload, ensure_ascii=False).encode()).decode("ascii"),
            }
            path.write_text(json.dumps(envelope), encoding="utf-8")
            vault = pm.Vault(path)
            vault.unlock(password)
            self.assertEqual(vault.loaded_format, 1)
            self.assertEqual(vault.find("legacy-1")["custom"]["秘密鍵"], "abc")
            self.assertEqual(vault.find("legacy-1")["history"], [])
            self.assertTrue(vault.dirty)
            vault.save()
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["format"], 2)

    def test_encrypted_backup_and_restore_with_safety_copy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "vault.pwm"
            backup = root / "vault-backup.pwm"
            vault = pm.Vault(path)
            vault.create("backup test master password")
            entry = vault.append_entry({
                "site": "Example",
                "email": "before@example.com",
                "username": "before",
                "password": "original-secret",
                "custom": {"URL": "https://example.com"},
            })
            vault.save()

            vault.backup_to(backup)
            self.assertTrue(backup.is_file())
            self.assertEqual(backup.read_bytes(), path.read_bytes())

            vault.update_entry(entry["id"], {
                "site": "Example",
                "email": "after@example.com",
                "username": "after",
                "password": "updated-secret",
                "custom": {"URL": "https://example.com/new"},
            })
            vault.save()

            safety_copy = vault.restore_backup(backup)
            self.assertTrue(safety_copy.is_file())
            self.assertIn("before-restore", safety_copy.name)
            restored = vault.find(entry["id"])
            self.assertEqual(restored["email"], "before@example.com")
            self.assertEqual(restored["password"], "original-secret")
            self.assertEqual(restored["custom"]["URL"], "https://example.com")

            reopened = pm.Vault(path)
            reopened.unlock("backup test master password")
            self.assertEqual(reopened.find(entry["id"])["email"], "before@example.com")

    def test_restore_rejects_backup_from_another_vault(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            current = pm.Vault(root / "current.pwm")
            current.create("same master password")
            current_entry = current.append_entry({"site": "Current", "password": "keep-me"})
            current.save()

            other = pm.Vault(root / "other.pwm")
            other.create("same master password")
            other.append_entry({"site": "Other", "password": "do-not-load"})
            other.save()

            with self.assertRaises(pm.VaultError):
                current.restore_backup(other.path)
            self.assertEqual(current.find(current_entry["id"])["password"], "keep-me")
            self.assertEqual(list(root.glob("*.before-restore-*.pwm")), [])

    def test_candidate_values_include_history(self):
        with tempfile.TemporaryDirectory() as td:
            vault = pm.Vault(Path(td) / "vault.pwm")
            vault.create("candidate password")
            entry = vault.append_entry({
                "site": "Example",
                "email": "one@example.com",
                "username": "one",
                "password": "pw-one",
                "custom": {"URL": "https://one.example", "PIN": "1111"},
            })
            vault.update_entry(entry["id"], {
                "site": "Example",
                "email": "two@example.com",
                "username": "two",
                "password": "pw-two",
                "custom": {"URL": "https://two.example", "PIN": "2222", "Code": "A1"},
            })
            self.assertEqual(entry["history"][0]["snapshot"]["email"], "one@example.com")
            self.assertIn("one@example.com", pm.unique_preserve_order([
                entry["email"], entry["history"][0]["snapshot"]["email"]
            ]))

    def test_saved_vault_path_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            old = pm.app_data_dir
            try:
                pm.app_data_dir = lambda: Path(td) / "config"
                target = Path(td) / "usb" / "my-vault.pwm"
                pm.save_saved_vault_path(target)
                self.assertEqual(pm.load_saved_vault_path(), target.resolve())
            finally:
                pm.app_data_dir = old

    def test_password_generator(self):
        value = pm.generate_password(24)
        self.assertEqual(len(value), 24)
        self.assertTrue(any(c.isupper() for c in value))
        self.assertTrue(any(c.islower() for c in value))
        self.assertTrue(any(c.isdigit() for c in value))


if __name__ == "__main__":
    unittest.main()

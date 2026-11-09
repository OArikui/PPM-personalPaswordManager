from __future__ import annotations

import os
import tempfile
from pathlib import Path
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from password_manager import PasswordManagerWindow
from password_manager_core import AUTO_LOCK_SECONDS, Vault


class SystemTrayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault = Vault(Path(self.temp_dir.name) / "tray-test.pwm")
        self.vault.create("system tray test master password")
        self.window = PasswordManagerWindow(self.vault)

    def tearDown(self):
        if self.window:
            self.window.allow_exit = True
            self.window.close()
        self.temp_dir.cleanup()

    def test_context_menu_contains_quick_actions(self):
        labels = [
            action.text()
            for action in self.window.tray_menu.actions()
            if not action.isSeparator()
        ]
        self.assertEqual(
            labels,
            [
                "UIを表示",
                "アカウントを追加",
                "検索",
                "保管庫をロック",
                "終了",
            ],
        )

    def test_closing_window_hides_it_when_tray_mode_is_enabled(self):
        self.window.tray_available = True
        self.window.show()
        self.window.close()
        self.assertFalse(self.window.isVisible())
        self.assertIsNotNone(self.vault.fernet)

    def test_tray_show_action_restores_the_window(self):
        self.window.hide()
        self.assertTrue(self.window.show_window())
        self.assertTrue(self.window.isVisible())

    def test_auto_lock_timer_uses_configured_timeout(self):
        self.assertTrue(self.window.auto_lock_timer.isSingleShot())
        self.assertEqual(
            self.window.auto_lock_timer.interval(),
            AUTO_LOCK_SECONDS * 1000,
        )


if __name__ == "__main__":
    unittest.main()

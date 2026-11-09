from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QEvent, Qt, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from password_manager_core import (
    APP_NAME,
    APP_VERSION,
    AUTO_LOCK_SECONDS,
    BASE_FIELDS,
    app_data_dir,
    derive_key,
    CLIPBOARD_CLEAR_SECONDS,
    SUPPORTED_FORMATS,
    Vault,
    VaultError,
    generate_password,
    load_saved_vault_path,
    normalize_snapshot,
    resource_path,
    save_saved_vault_path,
    unique_preserve_order,
)

GROUP_MODES = (
    ("サイト・サービス別", "site"),
    ("メールアドレス別", "email"),
    ("ユーザー名別", "username"),
)


def configure_completer(combo: QComboBox, values: list[str]) -> None:
    combo.setEditable(True)
    combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
    combo.addItems(values)
    completer = QCompleter(values, combo)
    completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    completer.setFilterMode(Qt.MatchFlag.MatchContains)
    combo.setCompleter(completer)


class VaultAccessDialog(QDialog):
    """Create a new vault or unlock an existing one."""

    def __init__(self, vault: Vault, parent: QWidget | None = None):
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("保管庫のロック解除" if vault.exists else "保管庫の初期設定")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)
        description = QLabel(
            f"保管庫:\n{vault.path}\n\n"
            + ("マスターパスワードを入力してください。" if vault.exists else
               "新しいマスターパスワードを設定してください。\n10文字以上を推奨します。")
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        form = QFormLayout()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("マスターパスワード")
        form.addRow("マスターパスワード", self.password)
        self.confirm: QLineEdit | None = None
        if not vault.exists:
            self.confirm = QLineEdit()
            self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm.setPlaceholderText("確認のためもう一度入力")
            form.addRow("確認入力", self.confirm)
        layout.addLayout(form)

        self.show_password = QCheckBox("パスワードを表示")
        self.show_password.toggled.connect(self._toggle_password_visibility)
        layout.addWidget(self.show_password)

        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: #b42318;")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(
            "ロック解除" if vault.exists else "保管庫を作成"
        )
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("終了")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.password.returnPressed.connect(self.accept)
        if self.confirm:
            self.confirm.returnPressed.connect(self.accept)
        self.password.setFocus()

    def _toggle_password_visibility(self, visible: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        self.password.setEchoMode(mode)
        if self.confirm:
            self.confirm.setEchoMode(mode)

    def accept(self) -> None:
        password = self.password.text()
        if not password:
            self.error_label.setText("マスターパスワードを入力してください。")
            self.password.setFocus()
            return
        try:
            if self.vault.exists:
                self.vault.unlock(password)
                if self.vault.loaded_format != 2:
                    self.vault.save()
                    QMessageBox.information(
                        self,
                        APP_NAME,
                        "旧形式の保管庫を最新版へ移行しました。",
                    )
            else:
                if len(password) < 10:
                    self.error_label.setText("マスターパスワードは10文字以上を推奨します。")
                    self.password.setFocus()
                    return
                if self.confirm and password != self.confirm.text():
                    self.error_label.setText("確認用パスワードが一致しません。")
                    self.confirm.selectAll()
                    self.confirm.setFocus()
                    return
                self.vault.create(password)
        except (VaultError, OSError, ValueError) as exc:
            self.error_label.setText(str(exc))
            self.password.selectAll()
            self.password.setFocus()
            return
        super().accept()


class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent: QWidget, on_apply):
        super().__init__(parent)
        self.setWindowTitle("パスワード生成")
        self.setMinimumWidth(420)
        self.on_apply = on_apply

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.length = QSpinBox()
        self.length.setRange(8, 256)
        self.length.setValue(20)
        form.addRow("文字数", self.length)
        layout.addLayout(form)

        options = QHBoxLayout()
        self.upper = QCheckBox("英大文字")
        self.upper.setChecked(True)
        self.lower = QCheckBox("英小文字")
        self.lower.setChecked(True)
        self.digits = QCheckBox("数字")
        self.digits.setChecked(True)
        self.symbols = QCheckBox("記号")
        self.symbols.setChecked(True)
        for checkbox in (self.upper, self.lower, self.digits, self.symbols):
            options.addWidget(checkbox)
        layout.addLayout(options)

        self.result = QLineEdit()
        self.result.setReadOnly(True)
        self.result.setFont(self.font())
        layout.addWidget(self.result)

        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: #b42318;")
        layout.addWidget(self.error_label)

        buttons = QHBoxLayout()
        regenerate = QPushButton("再生成")
        use_value = QPushButton("この値を使う")
        close = QPushButton("閉じる")
        regenerate.clicked.connect(self.generate)
        use_value.clicked.connect(self.apply)
        close.clicked.connect(self.reject)
        buttons.addWidget(regenerate)
        buttons.addStretch(1)
        buttons.addWidget(use_value)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self.generate()

    def generate(self) -> None:
        try:
            value = generate_password(
                self.length.value(),
                use_upper=self.upper.isChecked(),
                use_lower=self.lower.isChecked(),
                use_digits=self.digits.isChecked(),
                use_symbols=self.symbols.isChecked(),
            )
            self.result.setText(value)
            self.error_label.clear()
        except ValueError as exc:
            self.error_label.setText(str(exc))

    def apply(self) -> None:
        if self.result.text():
            self.on_apply(self.result.text())
            self.accept()


class HistoryDialog(QDialog):
    def __init__(self, app: "PasswordManagerWindow", entry: dict[str, Any]):
        super().__init__(app)
        self.app = app
        self.entry = entry
        self.selected_history_id: str | None = None
        self.setWindowTitle(f"変更履歴 - {entry.get('site') or '(未設定)'}")
        self.resize(900, 560)

        layout = QVBoxLayout(self)
        heading = QLabel("このアカウントの変更履歴")
        heading.setStyleSheet("font-weight: 600;")
        layout.addWidget(heading)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.history_tree = QTreeWidget()
        self.history_tree.setHeaderLabels(["日時", "操作"])
        self.history_tree.setColumnWidth(0, 165)
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        splitter.addWidget(self.history_tree)
        splitter.addWidget(self.preview)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

        buttons = QHBoxLayout()
        restore = QPushButton("選択した状態に復元")
        close = QPushButton("閉じる")
        restore.clicked.connect(self.restore)
        close.clicked.connect(self.reject)
        buttons.addWidget(restore)
        buttons.addStretch(1)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self.history_tree.itemSelectionChanged.connect(self.on_select)
        self.refresh()

    def refresh(self) -> None:
        self.history_tree.clear()
        for item in self.entry.get("history", []):
            row = QTreeWidgetItem([item.get("timestamp", ""), item.get("action", "")])
            row.setData(0, Qt.ItemDataRole.UserRole, item.get("id"))
            self.history_tree.addTopLevelItem(row)
        self.preview.clear()
        self.selected_history_id = None

    def on_select(self) -> None:
        selected = self.history_tree.selectedItems()
        if not selected:
            return
        history_id = selected[0].data(0, Qt.ItemDataRole.UserRole)
        self.selected_history_id = history_id
        item = next(
            (h for h in self.entry.get("history", []) if h.get("id") == history_id),
            None,
        )
        if item:
            self.preview.setPlainText(
                self.app.format_snapshot(item.get("snapshot", {}), reveal=True)
            )

    def restore(self) -> None:
        if not self.selected_history_id:
            QMessageBox.information(self, APP_NAME, "復元する履歴を選択してください。")
            return
        answer = QMessageBox.question(
            self,
            APP_NAME,
            "この履歴の状態へ復元しますか？\n\n現在の状態も「復元前」として履歴に保存されます。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            restored = self.app.vault.restore_history(
                self.entry["id"], self.selected_history_id
            )
            self.app.vault.save()
        except (VaultError, OSError) as exc:
            QMessageBox.critical(self, APP_NAME, f"復元に失敗しました。\n{exc}")
            return
        self.app.selected_id = restored["id"]
        self.app.refresh_tree()
        self.app.show_selected_details()
        self.entry = restored
        self.refresh()
        QMessageBox.information(self, APP_NAME, "履歴を復元しました。")


class EntryEditorDialog(QDialog):
    def __init__(
        self,
        app: "PasswordManagerWindow",
        entry: dict[str, Any],
        is_new: bool,
    ):
        super().__init__(app)
        self.app = app
        self.entry = entry
        self.is_new = is_new
        self.custom_rows: list[dict[str, Any]] = []
        self.setWindowTitle("新規アカウント" if is_new else "アカウント編集")
        self.resize(760, 650)
        self.setMinimumSize(620, 500)

        outer = QVBoxLayout(self)
        tabs = QTabWidget()
        outer.addWidget(tabs, 1)

        basic_page = QWidget()
        basic_layout = QVBoxLayout(basic_page)
        basic_form = QFormLayout()
        self.fields: dict[str, QComboBox] = {}
        labels = {
            "site": "サイト・サービス名",
            "email": "メールアドレス",
            "username": "ユーザー名",
            "password": "パスワード",
        }
        for key in ("site", "email", "username", "password"):
            combo = QComboBox()
            configure_completer(combo, app.candidate_values(key))
            combo.setCurrentText(str(entry.get(key, "")))
            self.fields[key] = combo
            basic_form.addRow(labels[key], combo)
        basic_layout.addLayout(basic_form)

        password_buttons = QHBoxLayout()
        generate = QPushButton("パスワードを生成")
        generate.clicked.connect(self.open_generator)
        password_buttons.addWidget(generate)
        password_buttons.addWidget(
            QLabel("候補には過去の現在値・変更履歴が含まれます。")
        )
        password_buttons.addStretch(1)
        basic_layout.addLayout(password_buttons)
        basic_layout.addStretch(1)
        tabs.addTab(basic_page, "基本項目")

        custom_page = QWidget()
        custom_layout = QVBoxLayout(custom_page)
        custom_header = QHBoxLayout()
        custom_header.addWidget(QLabel("カスタム項目"))
        custom_header.addStretch(1)
        add_button = QPushButton("＋ 項目を追加")
        add_button.clicked.connect(lambda: self.add_custom_row())
        custom_header.addWidget(add_button)
        custom_layout.addLayout(custom_header)
        custom_layout.addWidget(
            QLabel("項目名と値は、過去の登録内容から候補を選択できます。")
        )

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        rows_widget = QWidget()
        self.rows_layout = QVBoxLayout(rows_widget)
        self.rows_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(rows_widget)
        custom_layout.addWidget(scroll, 1)
        tabs.addTab(custom_page, "カスタム項目")

        for name, value in sorted(
            (entry.get("custom") or {}).items(), key=lambda pair: pair[0].casefold()
        ):
            self.add_custom_row(name, value)
        if not self.custom_rows:
            self.add_custom_row()

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        cancel = QPushButton("キャンセル")
        save = QPushButton("保存")
        cancel.clicked.connect(self.reject)
        save.clicked.connect(self.save_entry)
        button_row.addWidget(cancel)
        button_row.addWidget(save)
        outer.addLayout(button_row)

    def open_generator(self) -> None:
        dialog = PasswordGeneratorDialog(
            self, lambda value: self.fields["password"].setCurrentText(value)
        )
        dialog.exec()

    def add_custom_row(self, name: str = "", value: str = "") -> None:
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        name_combo = QComboBox()
        configure_completer(name_combo, self.app.custom_field_names())
        name_combo.setCurrentText(name)
        name_combo.setMinimumWidth(180)

        value_combo = QComboBox()
        configure_completer(
            value_combo, self.app.candidate_values("custom", name.strip())
        )
        value_combo.setCurrentText(value)
        value_combo.setMinimumWidth(220)

        remove_button = QPushButton("削除")
        remove_button.setMaximumWidth(72)
        row_layout.addWidget(name_combo, 1)
        row_layout.addWidget(value_combo, 2)
        row_layout.addWidget(remove_button)

        row = {
            "widget": row_widget,
            "name": name_combo,
            "value": value_combo,
        }
        self.custom_rows.append(row)
        self.rows_layout.addWidget(row_widget)

        def refresh_values(field_name: str) -> None:
            current = value_combo.currentText()
            values = self.app.candidate_values("custom", field_name.strip())
            value_combo.clear()
            value_combo.addItems(values)
            configure = QCompleter(values, value_combo)
            configure.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
            configure.setFilterMode(Qt.MatchFlag.MatchContains)
            value_combo.setCompleter(configure)
            value_combo.setCurrentText(current)

        name_combo.currentTextChanged.connect(refresh_values)
        remove_button.clicked.connect(lambda: self.remove_custom_row(row))

    def remove_custom_row(self, row: dict[str, Any]) -> None:
        if row not in self.custom_rows:
            return
        self.custom_rows.remove(row)
        row["widget"].setParent(None)
        row["widget"].deleteLater()

    def save_entry(self) -> None:
        custom: dict[str, str] = {}
        reserved_names = {label for _, label in BASE_FIELDS} | {
            key for key, _ in BASE_FIELDS
        }
        for row in self.custom_rows:
            name = row["name"].currentText().strip()
            value = row["value"].currentText()
            if not name and not value:
                continue
            if not name:
                QMessageBox.warning(
                    self, APP_NAME, "カスタム項目の項目名を入力してください。"
                )
                return
            if name in reserved_names:
                QMessageBox.warning(
                    self, APP_NAME, f"基本項目と同名のカスタム項目は使えません: {name}"
                )
                return
            if name in custom:
                QMessageBox.warning(
                    self, APP_NAME, f"カスタム項目「{name}」が重複しています。"
                )
                return
            custom[name] = value

        snapshot = {
            key: self.fields[key].currentText().strip()
            if key != "password"
            else self.fields[key].currentText()
            for key in ("site", "email", "username", "password")
        }
        snapshot["custom"] = custom
        try:
            if self.is_new:
                updated = self.app.vault.append_entry(snapshot)
            else:
                updated = self.app.vault.update_entry(self.entry["id"], snapshot)
            self.app.vault.save()
        except (VaultError, OSError) as exc:
            QMessageBox.critical(self, APP_NAME, f"保存に失敗しました。\n{exc}")
            return

        self.app.selected_id = updated["id"]
        self.app.refresh_tree()
        self.app.show_selected_details()
        self.app.statusBar().showMessage(f"保存しました: {self.app.vault.path}", 5000)
        self.accept()


class PasswordManagerWindow(QMainWindow):
    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault
        self.selected_id: str | None = None
        self.revealed_details = False
        self.editor: EntryEditorDialog | None = None
        self.clipboard_generation = 0
        self.expected_clipboard_text: str | None = None

        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.resize(1220, 780)
        self.setMinimumSize(980, 620)
        self.setWindowIcon(QIcon(str(resource_path("favicon.ico"))))

        self.auto_lock_timer = QTimer(self)
        self.auto_lock_timer.setSingleShot(True)
        self.auto_lock_timer.timeout.connect(self.lock_vault)
        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self.clear_clipboard_if_unchanged)

        self._build_ui()
        QApplication.instance().installEventFilter(self)
        self.refresh_tree()
        self.reset_auto_lock_timer()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)

        toolbar = QToolBar("操作")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        actions = [
            ("＋ 新規", self.new_entry),
            ("編集", self.edit_selected),
            ("削除", self.delete_selected),
            ("🕘 変更履歴", self.open_history),
            ("🔑 パスワードをコピー", self.copy_password),
            ("表示/非表示", self.toggle_detail_values),
            ("📁 保存先", self.change_vault_location),
            ("💾 バックアップ", self.backup_vault),
            ("↩ バックアップ復元", self.restore_vault_backup),
            ("🔒 ロック", self.lock_vault),
        ]
        for label, callback in actions:
            button = QPushButton(label)
            button.clicked.connect(callback)
            toolbar.addWidget(button)

        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("検索"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("サイト・メールアドレス・ユーザー名・パスワード・カスタム項目を検索")
        self.search.textChanged.connect(self.refresh_tree)
        search_row.addWidget(self.search, 1)
        clear_search = QPushButton("クリア")
        clear_search.clicked.connect(self.search.clear)
        search_row.addWidget(clear_search)
        search_row.addSpacing(12)
        search_row.addWidget(QLabel("表示単位"))
        self.group_mode = QComboBox()
        for label, key in GROUP_MODES:
            self.group_mode.addItem(label, key)
        self.group_mode.currentIndexChanged.connect(self.refresh_tree)
        search_row.addWidget(self.group_mode)
        outer.addLayout(search_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(
            ["グループ / アカウント", "メールアドレス", "ユーザー名", "最終更新"]
        )
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.SingleSelection)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, 4):
            self.tree.header().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        self.tree.itemSelectionChanged.connect(self.on_tree_select)
        self.tree.itemDoubleClicked.connect(lambda *_: self.edit_selected())
        splitter.addWidget(self.tree)

        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_title = QLabel("アカウント詳細")
        detail_title.setStyleSheet("font-size: 14px; font-weight: 600;")
        detail_layout.addWidget(detail_title)
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        detail_layout.addWidget(self.detail_text, 1)
        splitter.addWidget(detail_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        outer.addWidget(splitter, 1)

        self.statusBar().showMessage(f"保存先: {self.vault.path}")

    def eventFilter(self, watched, event) -> bool:
        if event.type() in {
            QEvent.Type.KeyPress,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.Wheel,
        }:
            if self.vault.fernet:
                self.reset_auto_lock_timer()
        return super().eventFilter(watched, event)

    def reset_auto_lock_timer(self) -> None:
        if self.vault.fernet:
            self.auto_lock_timer.start(AUTO_LOCK_SECONDS * 1000)

    def filtered_entries(self) -> list[dict[str, Any]]:
        needle = self.search.text().strip().casefold()
        entries = self.vault.data.get("entries", [])
        if not needle:
            return list(entries)
        result = []
        for entry in entries:
            values = [
                entry.get("site", ""),
                entry.get("email", ""),
                entry.get("username", ""),
                entry.get("password", ""),
            ]
            values.extend(
                f"{key} {value}" for key, value in entry.get("custom", {}).items()
            )
            if needle in "\n".join(values).casefold():
                result.append(entry)
        return result

    def refresh_tree(self, *_args) -> None:
        if not hasattr(self, "tree"):
            return
        selected_id = self.selected_id
        self.tree.clear()
        entries = self.filtered_entries()
        groups: dict[str, list[dict[str, Any]]] = {}
        group_key = self.group_mode.currentData()
        for entry in entries:
            label = entry.get(group_key, "") or "(未設定)"
            groups.setdefault(label, []).append(entry)

        selected_item: QTreeWidgetItem | None = None
        for group_label in sorted(groups, key=str.casefold):
            group_entries = groups[group_label]
            group_item = QTreeWidgetItem(
                [f"{group_label}  ({len(group_entries)})", "", "", ""]
            )
            group_item.setFlags(
                group_item.flags() & ~Qt.ItemFlag.ItemIsSelectable
            )
            self.tree.addTopLevelItem(group_item)
            for entry in sorted(
                group_entries,
                key=lambda item: (
                    item.get("site", "").casefold(),
                    item.get("email", "").casefold(),
                    item.get("username", "").casefold(),
                ),
            ):
                item = QTreeWidgetItem(
                    [
                        entry.get("site") or "(サイト未設定)",
                        entry.get("email", ""),
                        entry.get("username", ""),
                        entry.get("updated_at", ""),
                    ]
                )
                item.setData(0, Qt.ItemDataRole.UserRole, entry["id"])
                group_item.addChild(item)
                if entry["id"] == selected_id:
                    selected_item = item
            group_item.setExpanded(True)

        if selected_item:
            self.tree.setCurrentItem(selected_item)
        else:
            self.selected_id = None
            self._show_details(None)

        self.statusBar().showMessage(
            f"{len(entries)} 件 / 合計 {len(self.vault.data.get('entries', []))} 件"
            f"    保存先: {self.vault.path}"
        )

    def on_tree_select(self) -> None:
        selected = self.tree.selectedItems()
        if not selected:
            return
        entry_id = selected[0].data(0, Qt.ItemDataRole.UserRole)
        if not entry_id:
            return
        entry = self.vault.find(str(entry_id))
        if entry:
            self.selected_id = entry["id"]
            self._show_details(entry)

    @staticmethod
    def looks_secret(field_name: str) -> bool:
        normalized = field_name.casefold().replace(" ", "")
        needles = (
            "password", "pass", "secret", "token", "apikey", "api_key",
            "パスワード", "秘密", "鍵",
        )
        return any(needle in normalized for needle in needles)

    def format_snapshot(self, snapshot: dict[str, Any], reveal: bool = False) -> str:
        lines = [
            f"サイト・サービス: {snapshot.get('site', '')}",
            f"メールアドレス: {snapshot.get('email', '')}",
            f"ユーザー名: {snapshot.get('username', '')}",
        ]
        password = str(snapshot.get("password", ""))
        lines.append(
            f"パスワード: {password if reveal else '●' * max(8, min(16, len(password) or 8))}"
        )
        custom = snapshot.get("custom", {}) or {}
        if custom:
            lines.extend(["", "カスタム項目:"])
            for key in sorted(custom, key=str.casefold):
                value = str(custom[key])
                if reveal or not self.looks_secret(key):
                    shown = value
                else:
                    shown = "●" * max(8, min(16, len(value) or 8))
                lines.append(f"  {key}: {shown}")
        return "\n".join(lines)

    def _show_details(self, entry: dict[str, Any] | None) -> None:
        if not entry:
            self.detail_text.clear()
            return
        text = self.format_snapshot(entry, reveal=self.revealed_details)
        text += (
            "\n\n"
            f"作成日時: {entry.get('created_at', '')}\n"
            f"最終更新: {entry.get('updated_at', '')}\n"
            f"変更履歴: {len(entry.get('history', []))} 件"
        )
        self.detail_text.setPlainText(text)

    def show_selected_details(self) -> None:
        self._show_details(self.vault.find(self.selected_id))

    def toggle_detail_values(self) -> None:
        self.revealed_details = not self.revealed_details
        self.show_selected_details()

    def candidate_values(self, field: str, custom_name: str | None = None) -> list[str]:
        values: list[str] = []
        for entry in self.vault.data.get("entries", []):
            if field == "custom":
                values.append(str((entry.get("custom") or {}).get(custom_name or "", "")))
                for history in entry.get("history", []):
                    snapshot = history.get("snapshot", {}) or {}
                    values.append(
                        str((snapshot.get("custom") or {}).get(custom_name or "", ""))
                    )
            else:
                values.append(str(entry.get(field, "")))
                for history in entry.get("history", []):
                    snapshot = history.get("snapshot", {}) or {}
                    values.append(str(snapshot.get(field, "")))
        return [value for value in unique_preserve_order(values) if value != ""]

    def custom_field_names(self) -> list[str]:
        names: list[str] = []
        for entry in self.vault.data.get("entries", []):
            names.extend((entry.get("custom") or {}).keys())
            for history in entry.get("history", []):
                names.extend((history.get("snapshot") or {}).get("custom", {}).keys())
        return sorted(
            unique_preserve_order([str(name).strip() for name in names if str(name).strip()]),
            key=str.casefold,
        )

    def new_entry(self) -> None:
        if not self.vault.fernet:
            return
        entry = {
            "id": str(uuid.uuid4()),
            **normalize_snapshot({}),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "history": [],
        }
        self.open_entry_editor(entry, is_new=True)

    def edit_selected(self) -> None:
        entry = self.vault.find(self.selected_id)
        if not entry:
            QMessageBox.information(self, APP_NAME, "編集するアカウントを選択してください。")
            return
        self.open_entry_editor(entry, is_new=False)

    def open_entry_editor(self, entry: dict[str, Any], is_new: bool) -> None:
        if self.editor and self.editor.isVisible():
            self.editor.raise_()
            self.editor.activateWindow()
            return
        self.editor = EntryEditorDialog(self, entry, is_new)
        self.editor.finished.connect(lambda _result: setattr(self, "editor", None))
        self.editor.exec()

    def delete_selected(self) -> None:
        entry = self.vault.find(self.selected_id)
        if not entry:
            QMessageBox.information(self, APP_NAME, "削除するアカウントを選択してください。")
            return
        label = entry.get("site") or entry.get("email") or entry.get("username") or "名称未設定"
        answer = QMessageBox.question(
            self,
            APP_NAME,
            f"「{label}」を削除しますか？\n\nこの操作は履歴からは復元できません。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.vault.data["entries"] = [
            item for item in self.vault.data["entries"] if item.get("id") != entry["id"]
        ]
        self.vault.dirty = True
        try:
            self.vault.save()
        except (VaultError, OSError) as exc:
            QMessageBox.critical(self, APP_NAME, f"削除後の保存に失敗しました。\n{exc}")
            return
        self.selected_id = None
        self._show_details(None)
        self.refresh_tree()

    def copy_password(self) -> None:
        entry = self.vault.find(self.selected_id)
        if not entry:
            QMessageBox.information(self, APP_NAME, "パスワードをコピーするアカウントを選択してください。")
            return
        password = entry.get("password", "")
        if not password:
            QMessageBox.information(self, APP_NAME, "パスワードが空です。")
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(password)
        self.clipboard_generation += 1
        self.expected_clipboard_text = password
        self.clipboard_timer.start(CLIPBOARD_CLEAR_SECONDS * 1000)
        self.statusBar().showMessage(
            f"パスワードをコピーしました（{CLIPBOARD_CLEAR_SECONDS}秒後に自動消去）",
            5000,
        )

    def clear_clipboard_if_unchanged(self) -> None:
        if self.expected_clipboard_text is None:
            return
        clipboard = QApplication.clipboard()
        if clipboard.text() == self.expected_clipboard_text:
            clipboard.clear()
        self.expected_clipboard_text = None

    def open_history(self) -> None:
        entry = self.vault.find(self.selected_id)
        if not entry:
            QMessageBox.information(self, APP_NAME, "履歴を表示するアカウントを選択してください。")
            return
        if not entry.get("history"):
            QMessageBox.information(
                self,
                APP_NAME,
                "このアカウントにはまだ変更履歴がありません。\n編集すると、その直前の状態が履歴に保存されます。",
            )
            return
        HistoryDialog(self, entry).exec()

    def backup_vault(self) -> None:
        if not self.vault.fernet:
            QMessageBox.warning(self, APP_NAME, "先に保管庫のロックを解除してください。")
            return
        current = self.vault.path.expanduser().resolve()
        suggested = f"{current.stem}-backup-{time.strftime('%Y%m%d-%H%M%S')}.pwm"
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "暗号化保管庫のバックアップ先を選択",
            str(current.parent / suggested),
            "Password Manager 暗号化バックアップ (*.pwm);;すべてのファイル (*)",
        )
        if not selected:
            return
        destination = Path(selected)
        if destination.suffix.lower() != ".pwm":
            destination = destination.with_suffix(".pwm")
        try:
            result = self.vault.backup_to(destination)
        except (VaultError, OSError) as exc:
            QMessageBox.critical(self, APP_NAME, f"バックアップに失敗しました。\n\n{exc}")
            return
        QMessageBox.information(
            self,
            APP_NAME,
            f"バックアップを作成しました。\n\n{result}\n\n"
            "バックアップも暗号化されています。復元には同じ保管庫のマスターパスワードが必要です。",
        )
        self.statusBar().showMessage(f"バックアップを作成しました: {result}", 7000)

    def restore_vault_backup(self) -> None:
        if not self.vault.fernet:
            QMessageBox.warning(self, APP_NAME, "先に保管庫のロックを解除してください。")
            return
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "復元するバックアップを選択",
            str(self.vault.path.expanduser().resolve().parent),
            "Password Manager バックアップ (*.pwm);;すべてのファイル (*)",
        )
        if not selected:
            return
        backup_path = Path(selected).expanduser().resolve()
        if backup_path == self.vault.path.expanduser().resolve():
            QMessageBox.information(self, APP_NAME, "現在使用中の保管庫そのものは選択できません。")
            return
        answer = QMessageBox.warning(
            self,
            APP_NAME,
            "選択したバックアップの状態に置き換えます。\n"
            "現在のデータは復元後の保管庫からは見えなくなります。\n\n"
            "復元直前の保管庫ファイルは自動で別名保存されます。\n続行しますか？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            safety_backup = self.vault.restore_backup(backup_path)
        except (VaultError, OSError) as exc:
            QMessageBox.critical(self, APP_NAME, f"バックアップの復元に失敗しました。\n\n{exc}")
            return
        self.selected_id = None
        self._show_details(None)
        self.refresh_tree()
        QMessageBox.information(
            self,
            APP_NAME,
            f"バックアップを復元しました。\n\n復元前の保管庫は次のファイルへ退避しました。\n{safety_backup}",
        )

    def change_vault_location(self) -> None:
        if not self.vault.fernet:
            return
        try:
            if self.vault.dirty:
                self.vault.save()
        except (VaultError, OSError) as exc:
            QMessageBox.critical(self, APP_NAME, f"変更前の保存に失敗しました。\n{exc}")
            return
        current = self.vault.path.expanduser().resolve()
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "新しい保管庫の保存先を選択",
            str(current),
            "Password Manager 保管庫 (*.pwm);;すべてのファイル (*)",
        )
        if not selected:
            return
        destination = Path(selected).expanduser().resolve()
        if destination.suffix.lower() != ".pwm":
            destination = destination.with_suffix(".pwm")
        if destination == current:
            QMessageBox.information(self, APP_NAME, "現在と同じ保存先です。")
            return
        if destination.exists():
            QMessageBox.warning(
                self,
                APP_NAME,
                "指定先には既にファイルがあります。\n既存の保管庫を上書きしない設計です。",
            )
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
        except Exception as exc:
            try:
                if destination.exists():
                    destination.unlink()
            except OSError:
                pass
            QMessageBox.critical(self, APP_NAME, f"保存先の変更に失敗しました。\n\n{exc}")
            return
        QMessageBox.information(
            self,
            APP_NAME,
            f"保存先を変更しました。\n\n新しい保存先:\n{destination}\n\n"
            "旧ファイルは自動削除せず、バックアップとして残しています。",
        )
        self.refresh_tree()

    def lock_vault(self) -> None:
        if not self.vault.fernet:
            return
        if self.vault.dirty:
            try:
                self.vault.save()
            except (VaultError, OSError) as exc:
                QMessageBox.critical(self, APP_NAME, f"ロック前の保存に失敗しました。\n{exc}")
                return
        self.auto_lock_timer.stop()
        self.clipboard_timer.stop()
        self.clear_clipboard_if_unchanged()
        self.vault.lock()
        self.selected_id = None
        self.tree.clear()
        self.detail_text.clear()
        if self.editor and self.editor.isVisible():
            self.editor.reject()
        QMessageBox.information(self, APP_NAME, "保管庫をロックしました。")
        access = VaultAccessDialog(self.vault, self)
        if access.exec() != QDialog.DialogCode.Accepted:
            self.close()
            return
        self.refresh_tree()
        self.reset_auto_lock_timer()

    def closeEvent(self, event) -> None:
        if self.vault.fernet and self.vault.dirty:
            try:
                self.vault.save()
            except (VaultError, OSError) as exc:
                answer = QMessageBox.question(
                    self,
                    APP_NAME,
                    f"保存に失敗しました。保存せずに終了しますか？\n\n{exc}",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    event.ignore()
                    return
        self.auto_lock_timer.stop()
        self.clipboard_timer.stop()
        self.clear_clipboard_if_unchanged()
        QApplication.instance().removeEventFilter(self)
        super().closeEvent(event)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--vault", help="使用する保管庫ファイル (*.pwm)")
    args = parser.parse_args(argv)

    app = QApplication([sys.argv[0]])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)

    vault_path = Path(args.vault).expanduser() if args.vault else load_saved_vault_path()
    vault = Vault(vault_path)
    access = VaultAccessDialog(vault)
    if access.exec() != QDialog.DialogCode.Accepted:
        return 0

    window = PasswordManagerWindow(vault)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

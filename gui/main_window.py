"""Главное окно WebNetCheck."""
from __future__ import annotations

import os
import time

from PySide6.QtCore import QEvent, QObject, QSettings, QStandardPaths, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QKeySequence, QShortcut
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox,
                               QFileDialog, QFormLayout, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QMainWindow, QMenu, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
                               QSizePolicy, QSpinBox, QSplitter, QTableWidget, QTabWidget, QTextBrowser, QToolButton,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from netcheck import __version__
from netcheck.engine import ALL_CHECKS, Engine, Options
from netcheck.model import LAYER_TITLES, LAYERS, Status
from netcheck.profiles import load_all
from netcheck.report import save_html, save_json, summary_text
from netcheck.util import fmt_ms, human_bytes

from .theme import DARK, LIGHT, MONO_FONT, qss, status_color
from .widgets import DiagCard, LayerStack, RttBarDelegate, SortItem, app_icon, status_icon

CHECK_NAMES = {
    "proxy": "Настройки прокси Windows",
    "extip": "Внешний IP и оператор",
    "dns": "DNS: системный, публичные, DoH",
    "icmp": "ICMP ping",
    "trace": "Traceroute",
    "pmtu": "Path MTU (DF)",
    "tcp": "TCP-порты",
    "tls": "TLS: сертификат, версии, SNI",
    "http": "HTTP: код, фазы, редиректы",
    "hosts": "Хосты сервиса и зависимости",
    "api": "API-пробы профиля",
    "content": "Целостность крупных объектов",
}
STAGE_LAYER = {0: "proxy", 1: "dns", 2: "icmp", 3: "tcp", 4: "tls", 5: "http", 6: "hosts", 7: "api", 8: "content"}
FAMILIES = [("auto", "IPv4 + IPv6"), ("v4", "Только IPv4"), ("v6", "Только IPv6")]
ROUTES = [("direct", "Напрямую"), ("system", "Через системный прокси"), ("manual", "Через указанный прокси"),
          ("both", "Сравнить: прокси и напрямую")]


class Bridge(QObject):
    event = Signal(str, object)


class Worker(QThread):
    def __init__(self, engine: Engine):
        super().__init__()
        self.engine = engine

    def run(self):
        self.engine.run()


class SettingsDialog(QDialog):
    def __init__(self, parent, values: dict):
        super().__init__(parent)
        self.setWindowTitle("Параметры проверки")
        self.setMinimumWidth(460)
        form = QFormLayout(self)
        form.setContentsMargins(18, 18, 18, 12)
        form.setSpacing(10)
        self.ports = QLineEdit(values["ports"])
        self.ports.setToolTip("Через запятую. Порт из URL проверяется всегда.")
        self.assets = QSpinBox(); self.assets.setRange(1, 20); self.assets.setValue(values["assets"])
        self.min_kib = QSpinBox(); self.min_kib.setRange(1, 102400); self.min_kib.setSuffix(" KiB")
        self.min_kib.setValue(values["min_kib"])
        self.min_kib.setToolTip("32 KiB — больше типичной границы обрыва 16 KiB")
        self.stall = QDoubleSpinBox(); self.stall.setRange(2, 120); self.stall.setSuffix(" s")
        self.stall.setValue(values["stall"])
        self.timeout = QDoubleSpinBox(); self.timeout.setRange(1, 60); self.timeout.setSuffix(" s")
        self.timeout.setValue(values["timeout"])
        self.pings = QSpinBox(); self.pings.setRange(1, 50); self.pings.setValue(values["pings"])
        self.public = QCheckBox("Опрашивать публичные DNS по UDP/53 (Google, Cloudflare, Яндекс)")
        self.public.setChecked(values["public"])
        self.doh = QCheckBox("Сверять с DNS-over-HTTPS")
        self.doh.setChecked(values["doh"])
        ca_row = QHBoxLayout()
        self.ca = QLineEdit(values["ca"])
        self.ca.setPlaceholderText("не обязательно — системное хранилище Windows используется всегда")
        pick = QPushButton("Выбрать…")
        pick.clicked.connect(self._pick)
        ca_row.addWidget(self.ca, 1)
        ca_row.addWidget(pick)
        form.addRow("TCP-порты", self.ports)
        form.addRow("Объектов на проверку", self.assets)
        form.addRow("Минимальный размер объекта", self.min_kib)
        form.addRow("Зависание передачи после", self.stall)
        form.addRow("Таймаут соединения", self.timeout)
        form.addRow("Пакетов ping", self.pings)
        form.addRow("", self.public)
        form.addRow("", self.doh)
        form.addRow("Доп. корневой CA (PEM)", ca_row)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("Сохранить")
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def _pick(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Корневой сертификат", "", "Сертификаты (*.pem *.crt *.cer);;Все файлы (*)")
        if path:
            self.ca.setText(path)

    def values(self) -> dict:
        return {"ports": self.ports.text(), "assets": self.assets.value(), "min_kib": self.min_kib.value(),
                "stall": self.stall.value(), "timeout": self.timeout.value(), "pings": self.pings.value(),
                "public": self.public.isChecked(), "doh": self.doh.isChecked(), "ca": self.ca.text().strip()}


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("WebNetCheck", "WebNetCheck")
        self.persist = True
        self.t = DARK if self.settings.value("theme", "dark") == "dark" else LIGHT
        self.profiles = load_all()
        self.engine: Engine | None = None
        self.worker: Worker | None = None
        self.report = None
        self.bridge = Bridge()
        self.bridge.event.connect(self._on_event, Qt.ConnectionType.QueuedConnection)
        self.opts = {
            "ports": self.settings.value("ports", "443,80"), "assets": int(self.settings.value("assets", 3)),
            "min_kib": int(self.settings.value("min_kib", 32)), "stall": float(self.settings.value("stall", 15)),
            "timeout": float(self.settings.value("timeout", 8)), "pings": int(self.settings.value("pings", 4)),
            "public": self.settings.value("public", "true") in (True, "true"),
            "doh": self.settings.value("doh", "true") in (True, "true"),
            "ca": self.settings.value("ca", ""),
        }
        saved_checks = self.settings.value("checks", ",".join(ALL_CHECKS))
        self.enabled_checks = set(c for c in str(saved_checks).split(",") if c in ALL_CHECKS) or set(ALL_CHECKS)

        self.setWindowTitle(f"WebNetCheck {__version__}")
        self.setWindowIcon(app_icon())
        self.resize(1360, 860)
        self._build()
        self._apply_theme()
        self._restore_inputs()
        self._reset_results()

        self.elapsed = QTimer(self)
        self.elapsed.setInterval(200)
        self.elapsed.timeout.connect(self._tick)
        QShortcut(QKeySequence("Ctrl+R"), self, activated=self.start)
        # Esc ловим фильтром приложения: поле адреса с фокусом иначе забирает клавишу себе
        QApplication.instance().installEventFilter(self)

    # --- построение интерфейса ---------------------------------------------------------
    def _build(self):
        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        top = QWidget(objectName="topbar")
        tv = QVBoxLayout(top)
        tv.setContentsMargins(16, 12, 16, 10)
        tv.setSpacing(8)
        r1 = QHBoxLayout()
        r1.setSpacing(8)
        name = QLabel("WebNetCheck", objectName="appname")
        self.target = QLineEdit(objectName="target")
        self.target.setPlaceholderText("https://example.com, хост или IP")
        self.target.returnPressed.connect(self.start)
        self.target.setClearButtonEnabled(True)
        self.profile = QComboBox()
        self.profile.addItem("Свой адрес", None)
        for k, p in self.profiles.items():
            self.profile.addItem(p.name, k)
        self.profile.setMinimumWidth(170)
        self.profile.currentIndexChanged.connect(self._profile_changed)
        self.run_btn = QPushButton("Проверить", objectName="run")
        self.run_btn.setToolTip("Запустить диагностику (Enter, Ctrl+R)")
        self.run_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Остановить", objectName="stop")
        self.stop_btn.setToolTip("Прервать (Esc)")
        self.stop_btn.clicked.connect(self.stop)
        self.stop_btn.setEnabled(False)
        self.theme_btn = QToolButton()
        self.theme_btn.setToolTip("Светлая / тёмная тема")
        self.theme_btn.clicked.connect(self._toggle_theme)
        self.settings_btn = QToolButton()
        self.settings_btn.setText("Параметры")
        self.settings_btn.clicked.connect(self._open_settings)
        r1.addWidget(name)
        r1.addSpacing(10)
        r1.addWidget(self.target, 1)
        r1.addWidget(self.profile)
        r1.addWidget(self.run_btn)
        r1.addWidget(self.stop_btn)
        r1.addSpacing(6)
        r1.addWidget(self.settings_btn)
        r1.addWidget(self.theme_btn)
        tv.addLayout(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(8)
        self.family = QComboBox()
        for k, label in FAMILIES:
            self.family.addItem(label, k)
        self.route = QComboBox()
        for k, label in ROUTES:
            self.route.addItem(label, k)
        self.route.currentIndexChanged.connect(self._route_changed)
        self.proxy = QLineEdit()
        self.proxy.setPlaceholderText("прокси host:port")
        self.proxy.setFixedWidth(190)
        self.forced_ip = QLineEdit()
        self.forced_ip.setPlaceholderText("IP вместо DNS")
        self.forced_ip.setToolTip("Подключаться к этому адресу, не спрашивая DNS (как curl --resolve).\n"
                                  "Полезно, чтобы проверить конкретный узел CDN или балансировщика.")
        self.forced_ip.setFixedWidth(150)
        self.checks_btn = QToolButton()
        self.checks_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(self.checks_btn)
        self.check_actions: dict[str, QAction] = {}
        for c in ALL_CHECKS:
            a = QAction(CHECK_NAMES[c], menu, checkable=True)
            a.setChecked(c in self.enabled_checks)
            a.toggled.connect(self._checks_changed)
            menu.addAction(a)
            self.check_actions[c] = a
        menu.addSeparator()
        menu.addAction("Включить все", lambda: [a.setChecked(True) for a in self.check_actions.values()])
        menu.addAction("Только быстрые (без трассировки и MTU)",
                       lambda: [a.setChecked(k not in ("trace", "pmtu")) for k, a in self.check_actions.items()])
        self.checks_btn.setMenu(menu)
        self.profile_desc = QLabel("", objectName="profileDesc")
        for w, lbl in ((self.family, "Адреса"), (self.route, "Маршрут")):
            l = QLabel(lbl)
            l.setProperty("role", "muted")
            r2.addWidget(l)
            r2.addWidget(w)
        r2.addWidget(self.proxy)
        r2.addWidget(self.forced_ip)
        r2.addWidget(self.checks_btn)
        r2.addSpacing(8)
        r2.addWidget(self.profile_desc, 1)
        self.extip_lbl = QLabel("")
        self.extip_lbl.setProperty("role", "muted")
        self.extip_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.extip_lbl.setToolTip("Внешний адрес и оператор, под которыми этот компьютер виден в интернете")
        r2.addWidget(self.extip_lbl)
        tv.addLayout(r2)
        v.addWidget(top)

        body = QSplitter(Qt.Orientation.Horizontal)
        body.setChildrenCollapsible(False)
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(10, 12, 0, 12)
        lv.setSpacing(4)
        self.stack = LayerStack(self.t)
        self.stack.layerClicked.connect(self._filter_layer)
        hint = QLabel("Слои снизу вверх. Нажмите на слой, чтобы оставить в списке только его проверки.")
        hint.setWordWrap(True)
        hint.setProperty("role", "muted")
        hint.setStyleSheet("font-size: 8.5pt; padding: 0 10px;")
        lv.addWidget(self.stack, 1)
        lv.addWidget(hint)
        body.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(12, 12, 16, 12)
        rv.setSpacing(10)
        self.verdict = QFrame(objectName="verdict")
        vh = QHBoxLayout(self.verdict)
        vh.setContentsMargins(14, 12, 14, 12)
        vh.setSpacing(14)
        self.verdict_badge = QLabel("—")
        self.verdict_badge.setFixedSize(84, 56)
        self.verdict_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vt = QVBoxLayout()
        vt.setSpacing(2)
        self.verdict_title = QLabel("", objectName="verdictTitle")
        self.verdict_title.setWordWrap(True)
        self.verdict_text = QLabel("", objectName="verdictText")
        self.verdict_text.setWordWrap(True)
        self.verdict_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        vt.addWidget(self.verdict_title)
        vt.addWidget(self.verdict_text)
        vh.addWidget(self.verdict_badge, 0, Qt.AlignmentFlag.AlignTop)
        vh.addLayout(vt, 1)
        rv.addWidget(self.verdict)

        self.diag_area = QScrollArea()
        self.diag_area.setWidgetResizable(True)
        self.diag_host = QWidget()
        self.diag_layout = QVBoxLayout(self.diag_host)
        self.diag_layout.setContentsMargins(0, 0, 4, 0)
        self.diag_layout.setSpacing(6)
        self.diag_area.setWidget(self.diag_host)
        self.diag_area.setFrameShape(QFrame.Shape.NoFrame)
        self.diag_area.viewport().setStyleSheet("background: transparent;")
        self.diag_host.setStyleSheet("QWidget#diagHost { background: transparent; }")
        self.diag_host.setObjectName("diagHost")
        self.diag_area.hide()
        rv.addWidget(self.diag_area)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        rv.addWidget(self.tabs, 1)
        body.addWidget(right)
        body.setStretchFactor(1, 1)
        body.setSizes([290, 1070])
        v.addWidget(body, 1)

        # вкладка: проверки
        checks = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["Проверка", "Цель", "Результат", "Время", "Семейство"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setStretchLastSection(False)
        hdr.setMinimumSectionSize(60)
        hdr.resizeSection(0, 290)
        hdr.resizeSection(1, 210)
        hdr.resizeSection(3, 80)
        hdr.resizeSection(4, 80)
        self.tree.currentItemChanged.connect(self._show_details)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(False)
        checks.addWidget(self.tree)
        checks.addWidget(self.details)
        checks.setStretchFactor(0, 5)
        checks.setStretchFactor(1, 2)
        checks.setSizes([520, 190])
        self.details.setPlaceholderText("Выберите проверку, чтобы увидеть подробности: адреса, тайминги фаз, "
                                        "сертификат, заголовки ответа.")
        self.tabs.addTab(checks, "Проверки")

        self.hosts = self._table(["", "Хост", "Источник", "IP", "DNS", "TCP", "TLS", "HTTP", "Всего", "Примечание"])
        self.hosts.cellDoubleClicked.connect(self._host_dbl)
        self.hosts.setToolTip("Двойной щелчок — подставить хост в поле адреса для отдельной проверки")
        self.tabs.addTab(self.hosts, "Хосты")
        self.hops = self._table(["Семейство", "TTL", "Адрес", "Имя", "RTT"])
        self.rtt_delegate = RttBarDelegate(self.t, self.hops)
        self.hops.setItemDelegateForColumn(4, self.rtt_delegate)
        self.hops.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.hops, "Маршрут")
        self.assets = self._table(["", "Объект", "Ожидалось", "Получено", "Полная", "Хвост", "Скорость", "Примечание"])
        ah = self.assets.horizontalHeader()
        ah.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        ah.setSectionResizeMode(7, QHeaderView.ResizeMode.Interactive)
        ah.resizeSection(7, 330)
        self.assets.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.tabs.addTab(self.assets, "Объекты")
        self.log = QPlainTextEdit(objectName="log")
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.tabs.addTab(self.log, "Журнал")

        bottom = QWidget(objectName="bottombar")
        bh = QHBoxLayout(bottom)
        bh.setContentsMargins(16, 6, 16, 6)
        bh.setSpacing(10)
        self.status = QLabel("Готово к проверке")
        self.status.setProperty("role", "muted")
        self.status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.status.setMinimumWidth(120)
        self.progress = QProgressBar()
        self.progress.setRange(0, 10)
        self.progress.setFixedWidth(220)
        self.progress.setTextVisible(False)
        self.elapsed_lbl = QLabel("")
        self.elapsed_lbl.setProperty("role", "muted")
        self.html_btn = QPushButton("Сохранить HTML")
        self.html_btn.clicked.connect(self._save_html)
        self.json_btn = QPushButton("Сохранить JSON")
        self.json_btn.clicked.connect(self._save_json)
        self.copy_btn = QPushButton("Копировать сводку")
        self.copy_btn.clicked.connect(self._copy)
        bh.addWidget(self.status, 1)
        bh.addWidget(self.elapsed_lbl)
        bh.addWidget(self.progress)
        bh.addSpacing(10)
        for b in (self.copy_btn, self.html_btn, self.json_btn):
            b.setEnabled(False)
            bh.addWidget(b)
        v.addWidget(bottom)
        self._checks_changed()
        self._route_changed()

    def _table(self, headers: list[str]) -> QTableWidget:
        tb = QTableWidget(0, len(headers))
        tb.setHorizontalHeaderLabels(headers)
        tb.verticalHeader().setVisible(False)
        tb.setAlternatingRowColors(True)
        tb.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tb.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tb.setShowGrid(False)
        tb.setWordWrap(False)
        h = tb.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(len(headers) - 1, QHeaderView.ResizeMode.Stretch)
        h.setHighlightSections(False)
        tb.setColumnWidth(0, 28)
        return tb

    # --- тема и ввод ---------------------------------------------------------------------
    def _apply_theme(self):
        QApplication.instance().setStyleSheet(qss(self.t))
        self.stack.set_tokens(self.t)
        self.rtt_delegate.t = self.t
        self.theme_btn.setText("Светлая" if self.t.name == "dark" else "Тёмная")
        self._paint_verdict(getattr(self, "_verdict_status", None))
        self.details.document().setDefaultStyleSheet(
            f"td {{ padding: 3px 10px 3px 0; vertical-align: top; }} td.k {{ color: {self.t.muted}; }}"
            f" .mono {{ font-family: {MONO_FONT}; }} h3 {{ margin: 0 0 6px 0; }}")
        if self.report is not None:
            self._show_diagnosis(self.report)

    def _toggle_theme(self, *_):
        self.t = LIGHT if self.t.name == "dark" else DARK
        self.settings.setValue("theme", self.t.name)
        self._apply_theme()
        self.tree.viewport().update()

    def _restore_inputs(self):
        self.target.setText(self.settings.value("target", ""))
        saved = self.settings.value("profile", None)
        idx = self.profile.findData(saved) if saved else -1
        if idx > 0:
            self.profile.setCurrentIndex(idx)
        self.family.setCurrentIndex(max(0, self.family.findData(self.settings.value("family", "auto"))))
        self.route.setCurrentIndex(max(0, self.route.findData(self.settings.value("route", "direct"))))
        self.proxy.setText(self.settings.value("proxy", ""))

    def _save_inputs(self):
        if not self.persist:   # служебный прогон не должен затирать адрес и настройки пользователя
            return
        s = self.settings
        s.setValue("target", self.target.text())
        s.setValue("profile", self.profile.currentData())
        s.setValue("family", self.family.currentData())
        s.setValue("route", self.route.currentData())
        s.setValue("proxy", self.proxy.text())
        s.setValue("checks", ",".join(sorted(self.enabled_checks)))
        for k, v in self.opts.items():
            s.setValue(k, v)

    def _profile_changed(self, *_):
        key = self.profile.currentData()
        p = self.profiles.get(key) if key else None
        if p:
            self.target.setPlaceholderText(f"{p.base_url}  (можно переопределить)")
            self.profile_desc.setText(p.description)
            self.profile_desc.setToolTip(p.path)
        else:
            self.target.setPlaceholderText("https://example.com, хост или IP")
            self.profile_desc.setText("")

    def _route_changed(self, *_):
        need = self.route.currentData() in ("manual", "both")
        self.proxy.setEnabled(need)
        self.proxy.setVisible(need)

    def _checks_changed(self, *_):
        self.enabled_checks = {k for k, a in self.check_actions.items() if a.isChecked()}
        self.checks_btn.setText(f"Проверки: {len(self.enabled_checks)} из {len(ALL_CHECKS)}")

    def _open_settings(self, *_):
        dlg = SettingsDialog(self, self.opts)
        if dlg.exec():
            self.opts = dlg.values()
            self._save_inputs()

    # --- запуск --------------------------------------------------------------------------
    def _reset_results(self):
        self.report = None
        self.tree.clear()
        self.groups: dict[str, QTreeWidgetItem] = {}
        self.group_worst: dict[str, int] = {}
        self.details.setHtml("")
        for tb in (self.hosts, self.hops, self.assets):
            tb.setSortingEnabled(False)
            tb.setRowCount(0)
        self.asset_rows: dict[str, int] = {}
        if hasattr(self, "extip_lbl"):
            self.extip_lbl.setText("")
        self.rtt_delegate.max_rtt = 1.0
        self.log.clear()
        self.stack.reset()
        self.stack.selected = None
        self._clear_diag()
        self._verdict_status = None
        self._paint_verdict(None)
        if not self.target.text() and not self.profile.currentData():
            self.verdict_title.setText("Что проверить?")
            self.verdict_text.setText("Введите адрес сайта или API либо выберите профиль сервиса и нажмите "
                                      "«Проверить». Инструмент пройдёт слои от DNS до доставки контента и "
                                      "покажет, на каком из них рвётся доступ.")
        else:
            self.verdict_title.setText("Готово к проверке")
            self.verdict_text.setText("Нажмите «Проверить» или Enter.")
        for b in (self.copy_btn, self.html_btn, self.json_btn):
            b.setEnabled(False)

    def _options(self) -> Options | None:
        try:
            ports = [int(p) for p in str(self.opts["ports"]).replace(" ", "").split(",") if p]
        except ValueError:
            self.status.setText("TCP-порты в параметрах указаны неверно — нужны числа через запятую")
            return None
        if self.route.currentData() == "manual" and not self.proxy.text().strip():
            self.status.setText("Укажите прокси в формате host:port или выберите другой маршрут")
            self.proxy.setFocus()
            return None
        if not self.target.text().strip() and not self.profile.currentData():
            self.status.setText("Введите адрес или выберите профиль")
            self.target.setFocus()
            return None
        if not self.enabled_checks:
            self.status.setText("Не выбрано ни одной проверки — откройте меню «Проверки»")
            return None
        return Options(
            target=self.target.text().strip(), profile=self.profile.currentData(),
            family=self.family.currentData(), route=self.route.currentData(), proxy=self.proxy.text().strip(),
            forced_ip=self.forced_ip.text().strip(), ports=ports or [443],
            checks=[c for c in ALL_CHECKS if c in self.enabled_checks],
            public_dns=self.opts["public"], doh=self.opts["doh"], asset_count=self.opts["assets"],
            min_asset_size=self.opts["min_kib"] * 1024, timeout=self.opts["timeout"],
            stall_timeout=self.opts["stall"], ca_file=self.opts["ca"] or None, ping_count=self.opts["pings"])

    def start(self, *_):
        if self.worker is not None and self.worker.isRunning():
            return
        o = self._options()
        if o is None:
            return
        self._save_inputs()
        self._reset_results()
        self.verdict_title.setText("Идёт проверка")
        self.verdict_text.setText(o.target or self.profiles[o.profile].base_url)
        self.engine = Engine(o, self.bridge.event.emit, self.profiles)
        self.worker = Worker(self.engine)
        self.worker.finished.connect(self._finished)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.t0 = time.time()
        self.elapsed.start()
        self.progress.setValue(0)
        self.worker.start()

    def stop(self, *_):
        if self.engine is not None and self.worker is not None and self.worker.isRunning():
            self.engine.stop()
            self.status.setText("Останавливаю: дожидаюсь текущих сетевых операций…")
            self.stop_btn.setEnabled(False)

    def _finished(self, *_):
        _trace("worker finished")
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.elapsed.stop()
        self._tick()
        self.stack.set_active(None)

    def eventFilter(self, obj, ev):
        if (ev.type() == QEvent.Type.KeyPress and ev.key() == Qt.Key.Key_Escape
                and self.worker is not None and self.worker.isRunning()
                and QApplication.activeModalWidget() is None and QApplication.activePopupWidget() is None):
            self.stop()
            return True
        return super().eventFilter(obj, ev)

    def _tick(self, *_):
        if hasattr(self, "t0"):
            self.elapsed_lbl.setText(f"{time.time() - self.t0:.1f} s")

    def closeEvent(self, e):
        self._save_inputs()
        if self.worker is not None and self.worker.isRunning():
            self.engine.stop()
            self.worker.wait(3000)
        super().closeEvent(e)

    # --- события движка --------------------------------------------------------------------
    def _on_event(self, kind: str, payload):
        _trace(f"event {kind} begin")
        try:
            getattr(self, f"_ev_{kind}", lambda p: None)(payload)
        except Exception as e:  # noqa: BLE001 — ошибка отображения не должна ронять окно
            self.log.appendPlainText(f"[gui] ошибка обработки события {kind}: {e}")
            _trace(f"event {kind} error {e!r}")
        _trace(f"event {kind} end")

    def _ev_stage(self, payload):
        idx, total, title = payload
        self.progress.setMaximum(total)
        self.progress.setValue(idx)
        self.status.setText(f"{title}…" if idx < total - 1 else "Строю диагноз…")
        self.stack.set_active(STAGE_LAYER.get(idx))
        self.log.appendPlainText(f"== {title}")

    def _ev_log(self, msg):
        self.log.appendPlainText(f"   {msg}")

    def _group(self, layer: str) -> QTreeWidgetItem:
        if layer in self.groups:
            return self.groups[layer]
        order = [k for k, _ in LAYERS]
        g = QTreeWidgetItem([LAYER_TITLES.get(layer, layer), "", "", "", ""])
        f = g.font(0)
        f.setBold(True)
        g.setFont(0, f)
        g.setData(0, Qt.ItemDataRole.UserRole, ("group", layer))
        pos = 0
        for i in range(self.tree.topLevelItemCount()):
            other = self.tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)[1]
            if order.index(other) < order.index(layer):
                pos = i + 1
        self.tree.insertTopLevelItem(pos, g)
        g.setExpanded(True)
        self.groups[layer] = g
        if self.stack.selected and self.stack.selected != layer:
            g.setHidden(True)
        return g

    def _ev_check(self, c):
        if "extip_direct" in c.tags or ("extip_proxy" in c.tags and not self.extip_lbl.text()):
            self.extip_lbl.setText("Внешний IP: " + c.summary)
        self.log.appendPlainText(f"   {c.status.value:<4} {c.title} [{c.target}]: {c.summary}"
                                 + (f" ({fmt_ms(c.duration_ms)})" if c.duration_ms is not None else ""))
        g = self._group(c.layer)
        it = QTreeWidgetItem([c.title, c.target, c.summary, fmt_ms(c.duration_ms) if c.duration_ms is not None
                              else "", c.family or ""])
        it.setIcon(0, status_icon(self.t, c.status.value))
        it.setToolTip(2, c.summary)
        it.setToolTip(1, c.target)
        it.setData(0, Qt.ItemDataRole.UserRole, ("check", c))
        if c.status == Status.FAIL:
            it.setForeground(2, QColor(self.t.fail))
        g.addChild(it)
        if c.status.rank > self.group_worst.get(c.layer, -1):
            self.group_worst[c.layer] = c.status.rank
            g.setIcon(0, status_icon(self.t, c.status.value))
        n = g.childCount()  # noqa
        g.setText(2, f"{n} провер{'ка' if n % 10 == 1 and n % 100 != 11 else 'ки' if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else 'ок'}")
        self.stack.add_check(c.layer, c.status.value, c.summary)

    def _row(self, tb: QTableWidget, values: list, status: str | None = None, row: int | None = None,
             sort_keys: dict | None = None, mono: tuple = ()) -> int:
        if row is None:
            row = tb.rowCount()
            tb.insertRow(row)
        start = 0
        if status is not None:
            si = SortItem("")
            si.setIcon(status_icon(self.t, status))
            si.setData(Qt.ItemDataRole.UserRole, {"FAIL": 0, "WARN": 1, "OK": 2, "INFO": 3, "SKIP": 4}.get(status, 5))
            si.setToolTip(status)
            tb.setItem(row, 0, si)
            start = 1
        for i, v in enumerate(values):
            col = start + i
            item = SortItem(str(v))
            if sort_keys and col in sort_keys:
                item.setData(Qt.ItemDataRole.UserRole, sort_keys[col])
            if col in mono:
                f = item.font()
                f.setFamilies(["Cascadia Mono", "Consolas", "DejaVu Sans Mono"])
                item.setFont(f)
            item.setToolTip(str(v))
            tb.setItem(row, col, item)
        return row

    def _ev_host(self, h):
        self.hosts.setSortingEnabled(False)  # иначе строка «уедет» посреди заполнения ячеек
        self._row(self.hosts, [h.host, h.source, h.ip, fmt_ms(h.dns_ms), fmt_ms(h.tcp_ms), h.tls, h.http,
                               fmt_ms(h.total_ms), h.note], h.status.value,
                  sort_keys={4: h.dns_ms or -1, 5: h.tcp_ms or -1, 8: h.total_ms or -1}, mono=(1, 3))
        self.hosts.setSortingEnabled(True)

    def _ev_hop(self, h):
        self.hops.setSortingEnabled(False)
        if h.rtt_ms is not None:
            self.rtt_delegate.max_rtt = max(self.rtt_delegate.max_rtt, h.rtt_ms)
        row = self._row(self.hops, [h.family, h.ttl, h.ip or "*", h.name or "", ""], None,
                        sort_keys={1: h.ttl}, mono=(2, 3))
        self.hops.item(row, 4).setData(Qt.ItemDataRole.UserRole, h.rtt_ms if h.rtt_ms is not None else -1)
        if h.reached:
            self.hops.item(row, 2).setForeground(QColor(self.t.ok))
        self.hops.viewport().update()

    def _ev_asset_progress(self, payload):
        idx, url, got, total = payload
        if url not in self.asset_rows:
            self.asset_rows[url] = self._row(self.assets, [url, human_bytes(total), human_bytes(got), "…", "", "", ""],
                                             "SKIP", mono=(1,))
            bar = QProgressBar()
            bar.setRange(0, 1000)
            bar.setTextVisible(False)
            bar.setFixedHeight(8)
            self.assets.setCellWidget(self.asset_rows[url], 7, bar)
        row = self.asset_rows[url]
        self.assets.item(row, 3).setText(human_bytes(got))
        bar = self.assets.cellWidget(row, 7)
        if isinstance(bar, QProgressBar) and total:
            bar.setValue(int(1000 * got / total))

    def _ev_asset(self, a):
        row = self.asset_rows.get(a.url)
        if row is not None:
            self.assets.removeCellWidget(row, 7)
        self.asset_rows[a.url] = self._row(
            self.assets, [a.url, human_bytes(a.expected), human_bytes(a.received), a.full, a.tail,
                          f"{a.speed_kbps:.0f} KiB/s" if a.speed_kbps else "-", a.note], a.status.value, row=row,
            sort_keys={2: a.expected or 0, 3: a.received}, mono=(1,))

    def _ev_done(self, report):
        self.report = report
        self.stack.set_active(None)
        self.progress.setValue(self.progress.maximum())
        n_fail = sum(1 for c in report.checks if c.status == Status.FAIL)
        n_warn = sum(1 for c in report.checks if c.status == Status.WARN)
        self.status.setText(("Прервано. " if report.cancelled else "Готово. ")
                            + f"Проверок: {len(report.checks)}, сбоев: {n_fail}, замечаний: {n_warn}")
        self._show_diagnosis(report)
        for b in (self.copy_btn, self.html_btn, self.json_btn):
            b.setEnabled(True)
        # открыть вкладку, где виден корень проблемы
        if any(a.status == Status.FAIL for a in report.assets):
            self.tabs.setCurrentWidget(self.assets)
        else:
            self.tabs.setCurrentIndex(0)
        first_fail = None
        for i in range(self.tree.topLevelItemCount()):
            g = self.tree.topLevelItem(i)
            for j in range(g.childCount()):
                kind, c = g.child(j).data(0, Qt.ItemDataRole.UserRole)
                if c.status == Status.FAIL and first_fail is None:
                    first_fail = g.child(j)
        if first_fail is not None:
            self.tree.setCurrentItem(first_fail)

    # --- вывод ---------------------------------------------------------------------------------
    def _paint_verdict(self, status: str | None):
        t = self.t
        col = status_color(t, status) if status else t.line
        fg = "#FFFFFF" if status in ("OK", "FAIL", "INFO") or (status == "WARN" and t.name == "light") else t.bg
        if not status:
            fg = t.muted
        self.verdict_badge.setText({"INFO": "СТОП"}.get(status, status) if status else "—")
        self.verdict_badge.setStyleSheet(f"background: {col}; color: {fg}; border-radius: 8px; "
                                         f"font-size: 17pt; font-weight: 700;")

    def _clear_diag(self):
        while self.diag_layout.count():
            w = self.diag_layout.takeAt(0).widget()
            if w is not None:
                w.deleteLater()
        self.diag_area.hide()

    def _show_diagnosis(self, r):
        shown = r.overall.value
        if r.cancelled and shown == "OK":
            shown = "INFO"   # прервано: зелёный «OK» был бы неправдой
        self._verdict_status = shown
        self._paint_verdict(shown)
        main = r.diagnosis[0] if r.diagnosis else None
        if main:
            self.verdict_title.setText(main.title)
            self.verdict_text.setText(main.explanation)
        self._clear_diag()
        rest = r.diagnosis[1:]
        if main and main.next_steps:
            rest = [main.__class__(main.severity, "Что сделать в первую очередь", "", main.next_steps)] + rest
        for d in rest:
            self.diag_layout.addWidget(DiagCard(self.t, d.severity.value, d.title, d.explanation, d.next_steps))
        self.diag_layout.addStretch(1)
        if rest:
            self.diag_area.show()
            QTimer.singleShot(30, self._fit_diag)

    def _fit_diag(self):
        """Высота блока выводов — по содержимому, но не больше трети окна (дальше прокрутка)."""
        width = max(200, self.diag_area.viewport().width() - 4)
        lay = self.diag_layout
        want = lay.contentsMargins().top() + lay.contentsMargins().bottom()
        cards = [lay.itemAt(i).widget() for i in range(lay.count()) if lay.itemAt(i).widget() is not None]
        for w in cards:
            h = w.heightForWidth(width) if w.hasHeightForWidth() else -1
            want += h if h > 0 else w.sizeHint().height()
        want += lay.spacing() * max(0, len(cards) - 1) + 2
        self.diag_area.setFixedHeight(max(48, min(want, self.height() // 3)))

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.diag_area.isVisible():
            self._fit_diag()

    def _show_details(self, cur, _prev=None):
        if cur is None:
            self.details.setHtml("")
            return
        kind, obj = cur.data(0, Qt.ItemDataRole.UserRole)
        if kind == "group":
            layer = obj
            items = [cur.child(i).data(0, Qt.ItemDataRole.UserRole)[1] for i in range(cur.childCount())]
            rows = "".join(f"<tr><td class='k'>{_e(c.status.value)}</td><td>{_e(c.title)}: {_e(c.summary)}</td></tr>"
                           for c in items)
            self.details.setHtml(f"<h3>{_e(LAYER_TITLES.get(layer, layer))}</h3><table>{rows}</table>")
            return
        c = obj
        col = status_color(self.t, c.status.value)
        rows = []
        for k, v in c.details.items():
            if isinstance(v, (list, tuple)):
                val = "<br>".join(_e(x) for x in v) or "—"
            elif isinstance(v, dict):
                val = "<br>".join(f"{_e(a)}: {_e(b)}" for a, b in v.items()) or "—"
            else:
                val = _e(v)
            rows.append(f"<tr><td class='k'>{_e(k)}</td><td class='mono'>{val}</td></tr>")
        self.details.setHtml(
            f"<h3><span style='color:{col}'>{c.status.value}</span>&nbsp; {_e(c.title)}</h3>"
            f"<p>{_e(c.summary)}</p><p class='mono' style='color:{self.t.muted}'>{_e(c.target)}"
            f"{' · ' + _e(c.family) if c.family else ''}{' · ' + fmt_ms(c.duration_ms) if c.duration_ms else ''}</p>"
            f"<table>{''.join(rows)}</table>")

    def _filter_layer(self, layer: str):
        for k, g in self.groups.items():
            g.setHidden(bool(layer) and k != layer)
        self.tabs.setCurrentIndex(0)
        if layer and layer in self.groups:
            self.tree.setCurrentItem(self.groups[layer])

    def _host_dbl(self, row, _col):
        item = self.hosts.item(row, 1)
        if item:
            self.target.setText(f"https://{item.text()}/")
            self.profile.setCurrentIndex(0)
            self.status.setText(f"Адрес подставлен: {item.text()} — нажмите «Проверить»")

    # --- экспорт -------------------------------------------------------------------------------
    def _default_name(self, ext: str) -> str:
        host = (self.report.target.split("//")[-1].split("/")[0] or "report").replace(":", "_")
        name = f"webnetcheck_{host}_{time.strftime('%Y%m%d_%H%M%S')}.{ext}"
        folder = self.settings.value("save_dir", "") or QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DocumentsLocation)
        return os.path.join(folder, name) if folder and os.path.isdir(folder) else name

    def _save_html(self, *_):
        if not self.report:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", self._default_name("html"), "HTML (*.html)")
        if path:
            self.settings.setValue("save_dir", os.path.dirname(path))
            save_html(self.report, path)
            self.status.setText(f"Отчёт сохранён: {path}")
            self.status.setToolTip(path)

    def _save_json(self, *_):
        if not self.report:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить JSON", self._default_name("json"), "JSON (*.json)")
        if path:
            self.settings.setValue("save_dir", os.path.dirname(path))
            save_json(self.report, path)
            self.status.setText(f"JSON сохранён: {path}")
            self.status.setToolTip(path)

    def _copy(self, *_):
        if self.report:
            QApplication.clipboard().setText(summary_text(self.report))
            self.status.setText("Сводка скопирована в буфер обмена")


_TRACE_PATH = os.environ.get("WEBNETCHECK_TRACE")


def _trace(msg: str) -> None:
    """Отладочная трассировка в файл (включается переменной WEBNETCHECK_TRACE=путь)."""
    if not _TRACE_PATH:
        return
    try:
        with open(_TRACE_PATH, "a", encoding="utf-8") as f:
            f.write(f"{time.time():.3f} {msg}\n")
    except OSError:
        pass


def _e(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

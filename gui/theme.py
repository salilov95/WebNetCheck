"""Цветовые токены и QSS. Две темы: «приборная» тёмная и светлая офисная."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tokens:
    name: str
    bg: str
    panel: str
    panel2: str
    line: str
    text: str
    muted: str
    accent: str
    accent_text: str
    ok: str
    warn: str
    fail: str
    info: str
    skip: str
    select: str


DARK = Tokens(
    name="dark", bg="#1B2129", panel="#232B36", panel2="#2A3340", line="#34404F", text="#DCE2EA",
    muted="#8A97A8", accent="#5FA8D3", accent_text="#0F1720", ok="#4DB27F", warn="#DDA23B",
    fail="#E2584F", info="#6E9BD0", skip="#5E6A7A", select="#2F4458",
)
LIGHT = Tokens(
    name="light", bg="#EEF1F4", panel="#FFFFFF", panel2="#F5F7F9", line="#D5DBE2", text="#1E2630",
    muted="#5F6B7A", accent="#1F6FA3", accent_text="#FFFFFF", ok="#22844F", warn="#A86B00",
    fail="#C53A31", info="#2F6DB0", skip="#8A94A0", select="#D6E6F3",
)

UI_FONT = '"Segoe UI Variable Text", "Segoe UI", "Noto Sans", "DejaVu Sans", sans-serif'
MONO_FONT = '"Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace'


def status_color(t: Tokens, status: str) -> str:
    return {"OK": t.ok, "WARN": t.warn, "FAIL": t.fail, "INFO": t.info, "SKIP": t.skip}.get(status, t.skip)


def qss(t: Tokens) -> str:
    return f"""
* {{ font-family: {UI_FONT}; font-size: 10pt; color: {t.text}; }}
QMainWindow, QWidget#root {{ background: {t.bg}; }}
QWidget#topbar {{ background: {t.panel}; border-bottom: 1px solid {t.line}; }}
QWidget#bottombar {{ background: {t.panel}; border-top: 1px solid {t.line}; }}
QLabel#muted, QLabel[role="muted"] {{ color: {t.muted}; }}
QLabel#appname {{ font-size: 12pt; font-weight: 600; }}
QLabel#verdictTitle {{ font-size: 15pt; font-weight: 600; }}
QLabel#verdictText {{ color: {t.text}; }}
QLabel#profileDesc {{ color: {t.muted}; font-size: 9pt; }}

QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {t.panel2}; border: 1px solid {t.line}; border-radius: 6px; padding: 5px 8px;
    selection-background-color: {t.select};
}}
QLineEdit#target {{ font-family: {MONO_FONT}; font-size: 11pt; padding: 7px 10px; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {t.accent}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{ background: {t.panel}; border: 1px solid {t.line}; selection-background-color: {t.select}; }}

QPushButton, QToolButton {{
    background: {t.panel2}; border: 1px solid {t.line}; border-radius: 6px; padding: 6px 12px;
}}
QPushButton:hover, QToolButton:hover {{ border-color: {t.accent}; }}
QPushButton:focus, QToolButton:focus {{ border: 1px solid {t.accent}; }}
QPushButton:disabled, QToolButton:disabled {{ color: {t.muted}; }}
QPushButton#run {{ background: {t.accent}; color: {t.accent_text}; border: 1px solid {t.accent};
    font-weight: 600; padding: 7px 22px; }}
QPushButton#run:hover {{ border-color: {t.text}; }}
QPushButton#stop {{ color: {t.fail}; }}
QToolButton::menu-indicator {{ image: none; width: 0; }}

QMenu {{ background: {t.panel}; border: 1px solid {t.line}; padding: 4px; }}
QMenu::item {{ padding: 5px 22px 5px 8px; border-radius: 4px; }}
QMenu::item:selected {{ background: {t.select}; }}

QTabWidget::pane {{ border: 1px solid {t.line}; border-radius: 8px; background: {t.panel}; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {t.muted}; padding: 7px 14px; border: none;
    border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {t.text}; border-bottom: 2px solid {t.accent}; }}
QTabBar::tab:hover {{ color: {t.text}; }}

QTreeWidget, QTableWidget, QTextBrowser, QPlainTextEdit {{
    background: {t.panel}; border: none; alternate-background-color: {t.panel2};
    selection-background-color: {t.select}; selection-color: {t.text}; gridline-color: {t.line};
}}
QPlainTextEdit#log {{ font-family: {MONO_FONT}; font-size: 9pt; }}
QHeaderView::section {{ background: {t.panel2}; color: {t.muted}; border: none;
    border-bottom: 1px solid {t.line}; padding: 5px 8px; font-size: 9pt; }}
QTreeWidget::item, QTableWidget::item {{ padding: 3px 2px; }}

QSplitter::handle {{ background: {t.line}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

QProgressBar {{ background: {t.panel2}; border: 1px solid {t.line}; border-radius: 4px; height: 8px;
    text-align: center; font-size: 8pt; color: {t.muted}; }}
QProgressBar::chunk {{ background: {t.accent}; border-radius: 3px; }}

QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t.line}; border-radius: 4px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {t.line}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}

QFrame#diagCard {{ background: {t.panel}; border: 1px solid {t.line}; border-radius: 8px; }}
QFrame#verdict {{ background: {t.panel}; border: 1px solid {t.line}; border-radius: 10px; }}
QCheckBox {{ spacing: 6px; }}
QToolTip {{ background: {t.panel}; color: {t.text}; border: 1px solid {t.line}; padding: 4px; }}
QDialog {{ background: {t.bg}; }}
"""

"""Где хранить настройки и crash.log.

Обычная сборка (папка с exe, установщик, запуск из исходников) хранит настройки
в реестре HKCU\\Software\\WebNetCheck, а crash.log — в %LOCALAPPDATA%\\WebNetCheck.

Переносная сборка (один exe) держит всё рядом с собой: WebNetCheck.ini и
WebNetCheck-crash.log. Так её можно носить на флешке и не оставлять следов в
системе. Если папка с exe только для чтения, используются обычные места.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

INI_NAME = "WebNetCheck.ini"
CRASH_NAME = "WebNetCheck-crash.log"


def is_onefile(executable: str | None = None, meipass: str | None = None) -> bool:
    """Собрано ли приложение в один exe (PyInstaller --onefile).

    Onefile распаковывается во временную папку %TEMP%\\_MEIxxxx, а onedir держит
    файлы в _internal рядом с exe. Поэтому признак — временная папка лежит вне папки exe.
    """
    if executable is None:
        if not getattr(sys, "frozen", False):
            return False
        executable, meipass = sys.executable, getattr(sys, "_MEIPASS", None)
    if not meipass:
        return False
    exe_dir = Path(executable).resolve().parent
    try:
        return not Path(meipass).resolve().is_relative_to(exe_dir)
    except (OSError, ValueError):
        return False


def portable_dir() -> Path | None:
    """Папка для настроек переносной сборки или None, если сборка не переносная/папка не пишется."""
    if not is_onefile():
        return None
    folder = Path(sys.executable).resolve().parent
    probe = folder / INI_NAME
    try:
        with open(probe, "a", encoding="utf-8"):
            pass
    except OSError:
        return None
    return folder


def crash_log_path() -> str:
    folder = portable_dir()
    if folder is not None:
        return str(folder / CRASH_NAME)
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = Path(base) / "WebNetCheck"
    path.mkdir(parents=True, exist_ok=True)
    return str(path / "crash.log")


def make_settings():
    """QSettings: INI рядом с exe для переносной сборки, иначе реестр."""
    from PySide6.QtCore import QSettings
    folder = portable_dir()
    if folder is not None:
        return QSettings(str(folder / INI_NAME), QSettings.Format.IniFormat)
    return QSettings("WebNetCheck", "WebNetCheck")

"""WebNetCheck — графический интерфейс. Запуск: python app.py (или WebNetCheck.exe).

Служебный режим для проверки сборки:
    WebNetCheck.exe --selftest https://ya.ru/ --screenshot shot.png
окно само запускает проверку, сохраняет скриншот и закрывается.
"""
import os
import sys
import traceback


def _crash_log_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    folder = os.path.join(base, "WebNetCheck")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, "crash.log")


def _excepthook(exc_type, exc, tb):
    text = "".join(traceback.format_exception(exc_type, exc, tb))
    try:
        with open(_crash_log_path(), "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass
    if sys.stderr:
        sys.stderr.write(text)
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        if QApplication.instance():
            QMessageBox.critical(None, "WebNetCheck — ошибка",
                                 f"{exc_type.__name__}: {exc}\n\nПодробности: {_crash_log_path()}")
    except Exception:  # noqa: BLE001
        pass


_FAULT_FILE = None


def main() -> int:
    global _FAULT_FILE
    sys.excepthook = _excepthook
    try:  # нативные падения (access violation) тоже попадут в crash.log со стеком Python
        import faulthandler
        _FAULT_FILE = open(_crash_log_path(), "a", encoding="utf-8")
        faulthandler.enable(file=_FAULT_FILE, all_threads=True)
    except Exception:  # noqa: BLE001
        pass
    if sys.platform == "win32":
        try:  # своя иконка на панели задач, а не иконка python.exe
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WebNetCheck.Diagnostics")
        except Exception:  # noqa: BLE001
            pass
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from gui.main_window import MainWindow
    from gui.widgets import app_icon

    args = sys.argv[1:]
    selftest = args[args.index("--selftest") + 1] if "--selftest" in args else None
    shot = args[args.index("--screenshot") + 1] if "--screenshot" in args else None

    # Сборщик мусора Python может сработать в любом потоке. Если он в рабочем потоке движка
    # разрушит объект Qt, процесс падает с access violation. Поэтому автоматический сбор
    # выключен, а циклы собираются по таймеру в потоке интерфейса.
    import gc
    gc.disable()

    app = QApplication(sys.argv[:1])
    app.setApplicationName("WebNetCheck")
    app.setOrganizationName("WebNetCheck")
    app.setStyle("Fusion")
    app.setWindowIcon(app_icon())
    w = MainWindow()
    w.show()
    gc_timer = QTimer()
    gc_timer.setInterval(3000)
    gc_timer.timeout.connect(lambda: gc.collect())
    gc_timer.start()

    if selftest:
        w.persist = False
        w.profile.setCurrentIndex(0)
        w.target.setText(selftest)

        def save_and_quit():
            from gui.main_window import _trace
            _trace("save_and_quit")
            print("SELFTEST finishing", flush=True)
            if shot:
                ok = w.grab().save(os.path.abspath(shot))
                print(f"SELFTEST screenshot saved={ok}", flush=True)
            if w.report is not None:
                print(f"SELFTEST overall={w.report.overall.value} checks={len(w.report.checks)} "
                      f"diag={w.report.diagnosis[0].title if w.report.diagnosis else '-'}", flush=True)
            app.quit()

        def finished():
            QTimer.singleShot(1200, save_and_quit)

        def go():
            w.start()
            if w.worker is not None:
                w.worker.finished.connect(finished)
            else:  # ввод не прошёл проверку — сохранить то, что видно, и выйти
                QTimer.singleShot(500, save_and_quit)

        QTimer.singleShot(500, go)
        QTimer.singleShot(240_000, save_and_quit)  # страховка
    code = app.exec()
    from gui.main_window import _trace
    _trace("exec returned")
    w.close()
    _trace("window closed")
    return code


if __name__ == "__main__":
    sys.exit(main())

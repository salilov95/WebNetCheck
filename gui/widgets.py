"""Собственные виджеты: стек слоёв, карточка вывода, делегат RTT-полосы, значки статусов."""
from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (QFrame, QLabel, QSizePolicy, QStyle, QStyledItemDelegate, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from netcheck.model import LAYERS

from .theme import Tokens, status_color

_ICON_CACHE: dict[tuple[str, str], QIcon] = {}


def status_icon(t: Tokens, status: str, size: int = 12) -> QIcon:
    key = (t.name, status)
    if key not in _ICON_CACHE:
        pm = QPixmap(size * 2, size * 2)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QColor(status_color(t, status))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(c)
        if status == "FAIL":
            p.drawRoundedRect(QRectF(3, 3, size * 2 - 6, size * 2 - 6), 4, 4)  # квадрат — различим без цвета
        elif status == "WARN":
            from PySide6.QtGui import QPolygonF
            from PySide6.QtCore import QPointF
            s = size * 2
            p.drawPolygon(QPolygonF([QPointF(s / 2, 2), QPointF(s - 2, s - 3), QPointF(2, s - 3)]))
        elif status in ("SKIP", "RUN"):
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(c, 3))
            p.drawEllipse(QRectF(5, 5, size * 2 - 10, size * 2 - 10))
        else:
            p.drawEllipse(QRectF(3, 3, size * 2 - 6, size * 2 - 6))
        p.end()
        _ICON_CACHE[key] = QIcon(pm)
    return _ICON_CACHE[key]


def app_icon() -> QIcon:
    """Иконка приложения: три полосы стека, верхняя «оборвана»."""
    icon = QIcon()
    for s in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(s, s)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#232B36"))
        p.drawRoundedRect(QRectF(0, 0, s, s), s * 0.2, s * 0.2)
        h = s * 0.14
        x0, w = s * 0.18, s * 0.64
        for i, col in enumerate(("#4DB27F", "#4DB27F", "#5FA8D3")):
            y = s * 0.766 - i * h * 1.6
            p.setBrush(QColor(col))
            p.drawRoundedRect(QRectF(x0, y, w, h), h / 2, h / 2)
        y = s * 0.766 - 3 * h * 1.6
        p.setBrush(QColor("#E2584F"))
        p.drawRoundedRect(QRectF(x0, y, w * 0.42, h), h / 2, h / 2)
        p.drawRoundedRect(QRectF(x0 + w * 0.58, y, w * 0.42, h), h / 2, h / 2)
        p.end()
        icon.addPixmap(pm)
    return icon


class LayerStack(QWidget):
    """Стек слоёв снизу вверх. Слой с худшим статусом и активный слой видны сразу."""

    layerClicked = Signal(str)
    ROW = 50

    def __init__(self, tokens: Tokens, parent=None):
        super().__init__(parent)
        self.t = tokens
        # снизу вверх: прокси/DNS внизу, контент наверху → рисуем в обратном порядке
        self.layers = [k for k, _ in LAYERS]
        self.titles = dict(LAYERS)
        self.state: dict[str, dict] = {}
        self.active: str | None = None
        self.selected: str | None = None
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._tick)
        self.setMouseTracking(True)
        self.setMinimumWidth(250)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.reset()

    def sizeHint(self) -> QSize:
        return QSize(270, self.ROW * len(self.layers) + 16)

    def set_tokens(self, t: Tokens):
        self.t = t
        self.update()

    def reset(self):
        self.state = {k: {"status": "SKIP", "ok": 0, "warn": 0, "fail": 0, "note": "", "rank": -1}
                      for k in self.layers}
        self.active = None
        self.update()

    def set_active(self, layer: str | None):
        self.active = layer
        if layer and not self._timer.isActive():
            self._timer.start()
        if not layer:
            self._timer.stop()
        self.update()

    def add_check(self, layer: str, status: str, note: str):
        st = self.state.get(layer)
        if st is None:
            return
        key = {"OK": "ok", "WARN": "warn", "FAIL": "fail"}.get(status)
        if key:
            st[key] += 1
        rank = {"FAIL": 4, "WARN": 3, "OK": 2, "INFO": 1, "SKIP": 0}[status]
        if rank > st["rank"]:
            st["rank"] = rank
            st["status"] = status
            st["note"] = note
        self.update()

    def _tick(self):
        self._phase = (self._phase + 0.08) % 1.0
        self.update()

    def _rows(self):
        order = list(reversed(self.layers))
        for i, key in enumerate(order):
            yield key, QRectF(8, 8 + i * self.ROW, self.width() - 16, self.ROW - 6)

    def mousePressEvent(self, e):
        for key, r in self._rows():
            if r.contains(e.position()):
                self.selected = None if self.selected == key else key
                self.layerClicked.emit(self.selected or "")
                self.update()
                return

    def keyPressEvent(self, e):
        if e.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down):
            order = list(reversed(self.layers))
            idx = order.index(self.selected) if self.selected in order else -1
            idx = max(0, idx - 1) if e.key() == Qt.Key.Key_Up else min(len(order) - 1, idx + 1)
            self.selected = order[idx]
            self.layerClicked.emit(self.selected)
            self.update()
        elif e.key() == Qt.Key.Key_Escape:
            self.selected = None
            self.layerClicked.emit("")
            self.update()
        else:
            super().keyPressEvent(e)

    def paintEvent(self, _):
        t = self.t
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f_name = QFont(self.font())
        f_name.setPointSizeF(10.5)
        f_name.setWeight(QFont.Weight.DemiBold)
        f_note = QFont(self.font())
        f_note.setPointSizeF(8.5)
        fm_note = QFontMetrics(f_note)
        rows = list(self._rows())
        # «магистраль» — вертикальная линия через центры индикаторов
        if rows:
            x = rows[0][1].left() + 22
            p.setPen(QPen(QColor(t.line), 2))
            p.drawLine(int(x), int(rows[0][1].center().y()), int(x), int(rows[-1][1].center().y()))
        for key, r in rows:
            st = self.state[key]
            status = st["status"]
            col = QColor(status_color(t, status))
            used = st["rank"] >= 0
            is_active = key == self.active
            # фон строки
            bg = QColor(t.panel)
            if self.selected == key:
                bg = QColor(t.select)
            p.setPen(QPen(QColor(t.line if not (used and status == "FAIL") else t.fail), 1))
            p.setBrush(bg)
            p.drawRoundedRect(r, 7, 7)
            # индикатор на «магистрали»
            cx, cy = r.left() + 22, r.center().y()
            if is_active:
                pulse = 0.35 + 0.65 * abs(1 - 2 * self._phase)
                ac = QColor(t.accent)
                ac.setAlphaF(pulse)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(ac)
                p.drawEllipse(QRectF(cx - 8, cy - 8, 16, 16))
            elif used and status not in ("SKIP",):
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(col)
                if status == "FAIL":
                    p.drawRoundedRect(QRectF(cx - 7, cy - 7, 14, 14), 3, 3)
                else:
                    p.drawEllipse(QRectF(cx - 7, cy - 7, 14, 14))
            else:
                p.setPen(QPen(QColor(t.skip), 2))
                p.setBrush(QColor(t.panel))
                p.drawEllipse(QRectF(cx - 6, cy - 6, 12, 12))
            # название и заметка
            tx = r.left() + 42
            tw = r.width() - 42 - 10
            p.setFont(f_name)
            p.setPen(QColor(t.text if used or is_active else t.muted))
            p.drawText(QRectF(tx, r.top() + 5, tw, 20), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       self.titles[key])
            counts = []
            if st["fail"]:
                counts.append((f"{st['fail']} сбой", t.fail))
            if st["warn"]:
                counts.append((f"{st['warn']} замеч.", t.warn))
            if st["ok"]:
                counts.append((f"{st['ok']} ok", t.ok))
            p.setFont(f_note)
            xr = r.right() - 10
            for txt, c in reversed(counts):
                w = fm_note.horizontalAdvance(txt)
                p.setPen(QColor(c))
                p.drawText(QRectF(xr - w, r.top() + 7, w, 16), Qt.AlignmentFlag.AlignRight, txt)
                xr -= w + 8
            note = "идёт проверка…" if is_active and not st["note"] else (st["note"] or ("не проверялось" if not used else ""))
            p.setPen(QColor(t.muted))
            p.drawText(QRectF(tx, r.top() + 25, tw, 16), Qt.AlignmentFlag.AlignLeft,
                       fm_note.elidedText(note, Qt.TextElideMode.ElideRight, int(tw)))
        p.end()


class DiagCard(QFrame):
    def __init__(self, t: Tokens, severity: str, title: str, text: str, steps: list[str], parent=None):
        super().__init__(parent)
        self.setObjectName("diagCard")
        col = status_color(t, severity)
        self.setStyleSheet(f"QFrame#diagCard {{ border-left: 4px solid {col}; }}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 12, 10)
        lay.setSpacing(4)
        head = QLabel(f'<span style="color:{col}; font-weight:700">{severity}</span>&nbsp;&nbsp;'
                      f'<span style="font-weight:600">{_esc(title)}</span>')
        head.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(head)
        body = QLabel(_esc(text))
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(body)
        if steps:
            st = QLabel(f"<span style='color:{t.muted}'>Что сделать</span><br>"
                        + "<br>".join(f"•&nbsp;{_esc(s)}" for s in steps))
            st.setTextFormat(Qt.TextFormat.RichText)
            st.setWordWrap(True)
            st.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lay.addWidget(st)


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class SortItem(QTableWidgetItem):
    """Ячейка таблицы, сортирующаяся по числу (UserRole), а не по тексту."""

    def __lt__(self, other):
        a = self.data(Qt.ItemDataRole.UserRole)
        b = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a < b
        if isinstance(a, (int, float)):
            return True
        if isinstance(b, (int, float)):
            return False
        return super().__lt__(other)


class RttBarDelegate(QStyledItemDelegate):
    """Рисует RTT хопа полосой: видно, на каком участке растёт задержка."""

    def __init__(self, tokens: Tokens, parent=None):
        super().__init__(parent)
        self.t = tokens
        self.max_rtt = 1.0

    def paint(self, painter, option, index):
        rtt = index.data(Qt.ItemDataRole.UserRole)
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor(self.t.select))
        if not isinstance(rtt, (int, float)) or rtt < 0:
            painter.setPen(QColor(self.t.muted))
            painter.drawText(option.rect.adjusted(8, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter, "*  нет ответа")
            return
        r = option.rect.adjusted(70, 6, -10, -6)
        frac = min(1.0, rtt / self.max_rtt) if self.max_rtt else 0
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(self.t.panel2)))
        painter.drawRoundedRect(QRectF(r), 3, 3)
        col = self.t.ok if rtt < 50 else (self.t.warn if rtt < 150 else self.t.fail)
        painter.setBrush(QColor(col))
        painter.drawRoundedRect(QRectF(r.left(), r.top(), max(3, r.width() * frac), r.height()), 3, 3)
        painter.setPen(QColor(self.t.text))
        painter.drawText(option.rect.adjusted(8, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter,
                         f"{rtt:.0f} ms" if rtt >= 1 else "<1 ms")

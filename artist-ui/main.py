# -*- coding: utf-8 -*-
"""ModelLock 画师端 demo（PySide6）：发码 / 打包 / 密钥 / 台账。"""

import base64
import csv
import datetime
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from packager.ledger import Ledger
from packager.vkit import load_vreq, pack_model

from PySide6.QtCore import QDate, Qt, QSharedMemory
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QComboBox,
    QGroupBox, QHeaderView, QSpinBox, QCheckBox, QDateEdit,
)

def _expires_from_term(years: int, months: int, perpetual: bool) -> str | None:
    """把「N 年 M 月」换算成到期日(yyyy-MM-dd);永久返回 None。

    月份叠加进位,日期超出当月天数时截断到月末(如 2/29 + 1 年 → 2/28)。
    """
    if perpetual:
        return None
    if years < 0 or months < 0:
        raise ValueError("期限不能为负数")
    if years == 0 and months == 0:
        raise ValueError("期限至少为 1 个月")
    import calendar
    today = datetime.date.today()
    total_months = today.year * 12 + (today.month - 1) + years * 12 + months
    year = total_months // 12
    month = total_months % 12 + 1
    day = min(today.day, calendar.monthrange(year, month)[1])
    return datetime.date(year, month, day).strftime("%Y-%m-%d")


def _default_ledger_path() -> Path:
    """台账数据库:工作目录可写则用 ./license_records.db(开发时与仓库一致),
    否则(如装在 Program Files)落到 %LOCALAPPDATA%\\ModelLockArtist。"""
    try:
        probe = Path.cwd() / ".ml_write_probe"
        probe.write_bytes(b"")
        probe.unlink()
        return Path("license_records.db")
    except OSError:
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
        d = base / "ModelLockArtist"
        d.mkdir(parents=True, exist_ok=True)
        return d / "license_records.db"


QSS = """
QWidget { background-color: #fff7fa; color: #463c50; font-size: 14px; }
QMainWindow { background-color: #fff7fa; }
QTabWidget::pane { border: 1px solid #f2d5e0; border-radius: 10px; background: #ffffff; }
QTabBar::tab { background: #ffe9f1; padding: 8px 18px; border-top-left-radius: 10px;
               border-top-right-radius: 10px; margin-right: 4px; }
QTabBar::tab:selected { background: #ffcddc; font-weight: bold; }
QLineEdit, QComboBox, QDateEdit {
    border: 1px solid #f0c6d6; border-radius: 8px; padding: 5px 8px; background: #ffffff;
}
QPushButton {
    background: #ffcddc; color: #463c50; border: none; border-radius: 10px;
    padding: 7px 14px; font-weight: bold;
}
QPushButton:hover { background: #ffb9cf; }
QPushButton:pressed { background: #f7a7c0; }
QTableWidget { background: #ffffff; border: 1px solid #f2d5e0; border-radius: 8px; }
QHeaderView::section { background: #ffe9f1; border: none; padding: 6px; }
QTextEdit { background: #fffdfe; border: 1px solid #f2d5e0; border-radius: 8px; }
QGroupBox { border: 1px solid #f2d5e0; border-radius: 10px; margin-top: 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #beaaf0; }
"""


class ArtistApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ModelLock 画师端 · demo")
        self.resize(960, 680)
        self.author_key: rsa.RSAPrivateKey | None = None
        self.ledger_path = _default_ledger_path()
        self.ledger = Ledger(self.ledger_path)
        self.current_vreq = None

        tabs = QTabWidget()
        tabs.addTab(self._tab_keys(), "🔑 作者密钥")
        tabs.addTab(self._tab_codes(), "🎫 授权码")
        tabs.addTab(self._tab_pack(), "📦 打包模型")
        tabs.addTab(self._tab_ledger(), "📒 台账")

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(130)

        central = QWidget()
        lay = QVBoxLayout(central)
        lay.addWidget(tabs)
        lay.addWidget(QLabel("日志"))
        lay.addWidget(self.log_box)
        self.setCentralWidget(central)
        self.log("欢迎使用 ModelLock 画师端 demo（完全离线）")
        self.log(f"台账: {self.ledger_path}")

    # ---------- helpers ----------
    def log(self, msg):
        self.log_box.append(f"[{datetime.datetime.now():%H:%M:%S}] {msg}")

    def info(self, title, msg):
        QMessageBox.information(self, title, msg)

    def warn(self, title, msg):
        QMessageBox.warning(self, title, msg)

    def gen_author_key(self):
        try:
            path, _ = QFileDialog.getSaveFileName(self, "保存作者私钥", "author.pem", "PEM (*.pem)")
            if not path:
                return
            self.author_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            Path(path).write_bytes(self.author_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            self.author_key_path.setText(path)
            self.log(f"已生成作者密钥 -> {path}")
        except Exception as e:
            self.warn("失败", str(e))

    def load_author_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择作者私钥", "", "PEM (*.pem)")
        if not path:
            return
        try:
            self.author_key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
            self.author_key_path.setText(path)
            kid = self.author_pub_key_id()
            self.log(f"已加载作者密钥 {kid}")
        except Exception as e:
            self.warn("失败", str(e))

    def author_pub_key_id(self):
        if self.author_key is None:
            return ""
        spki = self.author_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        import hashlib
        return hashlib.sha256(spki).hexdigest()[:16]

    def export_author_spki(self):
        if self.author_key is None:
            self.warn("提示", "先生成或加载作者密钥")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出作者公钥", "author.spki", "SPKI (*.spki)")
        if not path:
            return
        spki = self.author_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        Path(path).write_text(base64.b64encode(spki).decode() + "\n")
        self.log(f"已导出 author.spki -> {path}")

    # ---------- tabs ----------
    def _tab_keys(self):
        box = QGroupBox("作者密钥（签名许可用，勿发给买家）")
        lay = QVBoxLayout(box)
        row = QHBoxLayout()
        self.author_key_path = QLineEdit()
        self.author_key_path.setReadOnly(True)
        self.author_key_path.setPlaceholderText("未加载作者密钥")
        gen = QPushButton("生成新密钥")
        gen.clicked.connect(self.gen_author_key)
        load = QPushButton("加载已有密钥")
        load.clicked.connect(self.load_author_key)
        exp = QPushButton("导出 author.spki")
        exp.clicked.connect(self.export_author_spki)
        row.addWidget(self.author_key_path)
        row.addWidget(gen)
        row.addWidget(load)
        row.addWidget(exp)
        lay.addLayout(row)
        tip = QLabel("买家首次使用需「信任作者」：把 author.spki 发给买家导入即可。")
        tip.setStyleSheet("color:#8a7f96;")
        lay.addWidget(tip)
        return box

    def _tab_codes(self):
        box = QGroupBox("生成授权码（绑定 模型 + 买家 key_id，一次性使用）")
        lay = QVBoxLayout(box)
        row = QHBoxLayout()
        self.code_model = QLineEdit()
        self.code_model.setPlaceholderText("模型ID，如 小樱")
        self.code_keyid = QLineEdit()
        self.code_keyid.setPlaceholderText("买家 key_id（可点右侧按钮从 .vreq 读取）")
        pick = QPushButton("读取 .vreq")
        pick.clicked.connect(self.pick_vreq_for_code)
        self.code_note = QLineEdit()
        self.code_note.setPlaceholderText("买家备注，如 阿花")
        self.code_count = QLineEdit()
        self.code_count.setPlaceholderText("数量")
        self.code_count.setText("1")
        gen = QPushButton("生成")
        gen.clicked.connect(self.gen_codes)
        row.addWidget(self.code_model)
        row.addWidget(self.code_keyid)
        row.addWidget(pick)
        row.addWidget(self.code_note)
        row.addWidget(self.code_count)
        row.addWidget(gen)
        lay.addLayout(row)
        return box

    def pick_vreq_for_code(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择买家 .vreq", "", "VREQ (*.vreq)")
        if not path:
            return
        try:
            v = load_vreq(Path(path))
            self.code_keyid.setText(v["key_id"])
            self.log(f"已读取 .vreq key_id={v['key_id']}")
        except Exception as e:
            self.warn("读取失败", str(e))

    def gen_codes(self):
        try:
            model = self.code_model.text().strip()
            kid = self.code_keyid.text().strip()
            note = self.code_note.text().strip()
            count = max(1, int(self.code_count.text() or "1"))
            if not model or not kid:
                self.warn("提示", "模型ID 和 买家 key_id 必填")
                return
            codes = self.ledger.gen_codes(model, kid, note=note, count=count)
            self.log(f"已生成 {len(codes)} 个授权码: " + ", ".join(codes))
            self.info("生成成功", "\n".join(codes))
        except Exception as e:
            self.warn("失败", str(e))

    def _tab_pack(self):
        box = QGroupBox("打包 .vkit（需要：作者密钥 + 买家 .vreq + 激活码）")
        lay = QVBoxLayout(box)

        r1 = QHBoxLayout()
        self.pack_vreq = QLineEdit()
        self.pack_vreq.setPlaceholderText("买家 .vreq 路径")
        b1 = QPushButton("选择")
        b1.clicked.connect(lambda: self.pick_pack_vreq())
        self.pack_model_dir = QLineEdit()
        self.pack_model_dir.setPlaceholderText("模型目录")
        b2 = QPushButton("选择")
        b2.clicked.connect(self.pick_model_dir)
        r1.addWidget(QLabel("vreq"))
        r1.addWidget(self.pack_vreq)
        r1.addWidget(b1)
        r1.addWidget(QLabel("模型"))
        r1.addWidget(self.pack_model_dir)
        r1.addWidget(b2)
        lay.addLayout(r1)

        r2 = QHBoxLayout()
        self.pack_code = QLineEdit()
        self.pack_code.setPlaceholderText("激活码（gen 时生成的 ML-XXXX）")
        self.pack_perpetual = QCheckBox("永久")
        self.pack_years = QSpinBox()
        self.pack_years.setRange(0, 99)
        self.pack_years.setValue(10)  # 默认 10 年
        self.pack_months = QSpinBox()
        self.pack_months.setRange(0, 11)
        self.pack_months.setValue(0)
        self.pack_perpetual.toggled.connect(
            lambda on: (self.pack_years.setDisabled(on), self.pack_months.setDisabled(on)))
        self.pack_out = QLineEdit()
        self.pack_out.setPlaceholderText("输出 .vkit 路径")
        b3 = QPushButton("选择")
        b3.clicked.connect(self.pick_output)
        go = QPushButton("🚀 打包")
        go.clicked.connect(self.do_pack)
        r2.addWidget(QLabel("激活码"))
        r2.addWidget(self.pack_code)
        r2.addWidget(QLabel("期限"))
        r2.addWidget(self.pack_perpetual)
        r2.addWidget(self.pack_years)
        r2.addWidget(QLabel("年"))
        r2.addWidget(self.pack_months)
        r2.addWidget(QLabel("月"))
        r2.addWidget(QLabel("输出"))
        r2.addWidget(self.pack_out)
        r2.addWidget(b3)
        r2.addWidget(go)
        lay.addLayout(r2)
        return box

    def pick_pack_vreq(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择买家 .vreq", "", "VREQ (*.vreq)")
        if path:
            self.pack_vreq.setText(path)
            try:
                self.current_vreq = load_vreq(Path(path))
                self.log(f"vreq key_id={self.current_vreq['key_id']}")
            except Exception as e:
                self.warn("读取失败", str(e))

    def pick_model_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择模型目录")
        if path:
            self.pack_model_dir.setText(path)

    def pick_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存 .vkit", "model.vkit", "VKIT (*.vkit)")
        if path:
            self.pack_out.setText(path)

    def do_pack(self):
        try:
            if self.author_key is None:
                self.warn("提示", "请先在「作者密钥」页加载密钥")
                return
            vreq_path = Path(self.pack_vreq.text().strip())
            model_dir = Path(self.pack_model_dir.text().strip())
            out = Path(self.pack_out.text().strip())
            code = self.pack_code.text().strip()
            try:
                expires = _expires_from_term(
                    self.pack_years.value(), self.pack_months.value(),
                    self.pack_perpetual.isChecked())
            except ValueError as e:
                self.warn("提示", str(e))
                return
            if not vreq_path.exists() or not model_dir.is_dir() or not out:
                self.warn("提示", "vreq / 模型目录 / 输出路径 必填")
                return
            if not code:
                self.warn("提示", "请输入激活码")
                return
            vreq = load_vreq(vreq_path)
            pack_model(
                model_dir, [vreq], model_id=self.code_model.text().strip() or model_dir.name,
                output=out, note=self.code_note.text().strip() or "",
                author_private_key=self.author_key, code=code, expires_at=expires,
                ledger_path=self.ledger_path,
            )
            term = "永久" if expires is None else f"至 {expires}"
            self.log(f"打包成功 -> {out}（买家 {vreq['key_id']}，{term}）")
            self.info("打包成功", f"已生成 {out}\n请连同激活码 {code} 一起发给买家。\n期限: {term}")
        except Exception as e:
            self.warn("打包失败", str(e))

    def _tab_ledger(self):
        box = QGroupBox("授权台账")
        lay = QVBoxLayout(box)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["激活码", "模型", "买家key_id", "状态", "备注"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        row = QHBoxLayout()
        self.ledger_filter_check = QCheckBox("按时间范围导出")
        today = QDate.currentDate()
        self.ledger_from = QDateEdit(today.addYears(-1))
        self.ledger_from.setCalendarPopup(True)
        self.ledger_to = QDateEdit(today)
        self.ledger_to.setCalendarPopup(True)
        self.ledger_filter_check.toggled.connect(
            lambda on: (self.ledger_from.setEnabled(on), self.ledger_to.setEnabled(on)))
        self.ledger_from.setEnabled(False)
        self.ledger_to.setEnabled(False)
        export_btn = QPushButton("📤 导出 CSV")
        export_btn.clicked.connect(self.export_ledger)
        refresh = QPushButton("刷新")
        refresh.clicked.connect(self.refresh_ledger)
        row.addWidget(self.ledger_filter_check)
        row.addWidget(QLabel("从"))
        row.addWidget(self.ledger_from)
        row.addWidget(QLabel("到"))
        row.addWidget(self.ledger_to)
        row.addStretch(1)
        row.addWidget(export_btn)
        row.addWidget(refresh)
        lay.addLayout(row)
        lay.addWidget(self.table)
        self.refresh_ledger()
        return box

    def refresh_ledger(self):
        rows = self.ledger.list_codes()
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, val in enumerate([r["code"], r["model_id"], r["key_id"], r["status"], r["note"]]):
                self.table.setItem(i, j, QTableWidgetItem(str(val)))

    def export_ledger(self):
        """导出台账为 CSV(UTF-8 BOM,Excel 直接打开),可选按生成时间范围过滤。"""
        start = end = None
        if self.ledger_filter_check.isChecked():
            start = self.ledger_from.date().toString("yyyy-MM-dd")
            end = self.ledger_to.date().toString("yyyy-MM-dd")
            if start > end:
                self.warn("提示", "开始日期不能晚于结束日期")
                return
        rows = self.ledger.list_codes(start=start, end=end)
        default_name = f"台账_{datetime.date.today():%Y%m%d}" + ("" if start is None else f"_{start}_{end}") + ".csv"
        path, _ = QFileDialog.getSaveFileName(self, "导出台账", default_name, "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(["激活码", "模型", "买家key_id", "状态", "备注", "生成时间(UTC)"])
                for r in rows:
                    w.writerow([r["code"], r["model_id"], r["key_id"],
                                r["status"], r["note"], r["created_at"]])
            self.log(f"已导出台账 {len(rows)} 条 -> {path}")
            self.info("导出成功", f"共 {len(rows)} 条记录\n已保存到:\n{path}")
        except Exception as e:
            self.warn("导出失败", str(e))


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)

    # 单实例:第二个实例直接提示并退出(进程退出时系统自动释放锁)。
    lock = QSharedMemory("ModelLockArtistSingleton")
    if not lock.create(1):
        QMessageBox.critical(None, "ModelLock 画师端", "ModelLock 画师端已经在运行中。")
        return 1

    win = ArtistApp()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

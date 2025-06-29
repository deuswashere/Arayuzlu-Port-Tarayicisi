import sys
import io
import contextlib
import getpass
import os
import tempfile

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox,
    QFileDialog, QMessageBox, QCheckBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QThread

# ————— XDG_RUNTIME_DIR tanımı (cross-platform) —————
try:
    uid = os.getuid()
except AttributeError:
    user = getpass.getuser()
    uid = abs(hash(user))
rt_unix = f"/run/user/{uid}"
if os.name != "nt" and os.path.isdir(rt_unix):
    rt = rt_unix
else:
    rt = os.path.join(tempfile.gettempdir(), f"runtime-{uid}")
os.makedirs(rt, exist_ok=True)
if os.name != "nt":
    os.chmod(rt, 0o700)
os.environ["XDG_RUNTIME_DIR"] = rt

try:
    import portarama as core
except ModuleNotFoundError:
    QMessageBox.critical(None, "Eksik Modül", "portarama.py bulunamadı. Aynı klasöre koyun.")
    sys.exit(1)

class ScanWorker(QObject):
    output_ready = pyqtSignal(str)
    finished     = pyqtSignal()

    def __init__(self, argv):
        super().__init__()
        self.argv = argv

    def run(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            backup = sys.argv
            sys.argv = ["portarama.py"] + self.argv
            try:
                core.main()
            except Exception as e:
                print(f"Hata: {e}")
            finally:
                sys.argv = backup

        self.output_ready.emit(buf.getvalue())
        self.finished.emit()


class PortScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Tarayıcısı")
        self.resize(950, 700)
        self._init_ui()

    def _init_ui(self):
        main = QWidget()
        layout = QVBoxLayout()

        # → Komut özeti
        self.summary = QLabel("Komut: ")
        self.summary.setWordWrap(True)
        self.summary.setToolTip("Oluşturulan CLI komutunu gösterir.")
        layout.addWidget(self.summary)

        # 1) Hedef girişi
        row1 = QHBoxLayout()
        lbl_targets = QLabel("Hedefler (IP/aralık, CSV):")
        lbl_targets.setToolTip("Tarama yapılacak IP adreslerini veya aralıkları girin.")
        row1.addWidget(lbl_targets)
        self.target_input = QLineEdit()
        self.target_input.setToolTip("Örnek: 192.168.1.1 veya 192.168.1.1-10 veya 10.0.0.0/24")
        self.target_input.textChanged.connect(self.update_summary)
        row1.addWidget(self.target_input)
        self.ip_file_btn = QPushButton("IP Listesi Yükle (.txt)")
        self.ip_file_btn.setToolTip("Bir dosyadan IP listesi yükler.")
        self.ip_file_btn.clicked.connect(self.load_ip_file)
        row1.addWidget(self.ip_file_btn)
        layout.addLayout(row1)

        # Hariç IP
        row_ex1 = QHBoxLayout()
        lbl_exclude = QLabel("Hariç IP/aralık (CSV):")
        lbl_exclude.setToolTip("Belirtilen IP veya aralıkları taramadan hariç tutar.")
        row_ex1.addWidget(lbl_exclude)
        self.exclude_input = QLineEdit()
        self.exclude_input.setToolTip("Ör: 192.168.1.5 veya 10.0.0.1-5")
        self.exclude_input.textChanged.connect(self.update_summary)
        row_ex1.addWidget(self.exclude_input)
        self.exclude_file_btn = QPushButton("Hariç Liste Yükle (.txt)")
        self.exclude_file_btn.setToolTip("Hariç listeyi dosyadan yükler.")
        self.exclude_file_btn.clicked.connect(self.load_exclude_file)
        row_ex1.addWidget(self.exclude_file_btn)
        layout.addLayout(row_ex1)

        # 2) Port ayarları
        row2 = QHBoxLayout()
        self.use_default_ports = QCheckBox("Popüler portları tara")
        self.use_default_ports.setToolTip("popularport.txt içindeki yaygın portları tarar.")
        self.use_default_ports.setChecked(True)
        self.use_default_ports.stateChanged.connect(self.on_default_ports_toggled)
        row2.addWidget(self.use_default_ports)

        lbl_custom = QLabel("Özel port aralığı:")
        lbl_custom.setToolTip("Taranacak özel portları veya aralıkları girin.")
        row2.addWidget(lbl_custom)
        self.port_input = QLineEdit("1-1024")
        self.port_input.setToolTip("Ör: 22,80,443 veya 1000-2000")
        self.port_input.textChanged.connect(self.update_summary)
        row2.addWidget(self.port_input)

        self.port_file_btn = QPushButton("Port Listesi Yükle (.txt)")
        self.port_file_btn.setToolTip("Dosyadan port listesi yükler.")
        self.port_file_btn.clicked.connect(self.load_port_file)
        row2.addWidget(self.port_file_btn)
        layout.addLayout(row2)

        # Hariç portlar
        row_ex2 = QHBoxLayout()
        lbl_ex_ports = QLabel("Hariç port aralıkları:")
        lbl_ex_ports.setToolTip("Tarama dışı bırakılacak port aralıklarını girin.")
        row_ex2.addWidget(lbl_ex_ports)
        self.exclude_ports_input = QLineEdit()
        self.exclude_ports_input.setToolTip("Ör: 80,443 veya 1000-1100")
        self.exclude_ports_input.textChanged.connect(self.update_summary)
        row_ex2.addWidget(self.exclude_ports_input)
        layout.addLayout(row_ex2)

        # 3) Tarama seçenekleri
        row3 = QHBoxLayout()
        for name, tip in [("ICMP Ping", "Bilgisayarın açık olup olmadığını anlamak için klasik ping yöntemi kullanılır."),
                  ("TCP ACK Ping", "Hedefe TCP ACK paketi göndererek, güvenlik duvarı arkasındaki cihazın açık olup olmadığını tespit etmeye yarar."),
                  ("UDP Ping", "UDP mesajları göndererek cihazın açık olup olmadığını kontrol eder, ama her zaman cevap gelmeyebilir.")]:

            cb = QCheckBox(name)
            cb.setToolTip(tip)
            cb.stateChanged.connect(self.update_summary)
            row3.addWidget(cb)
            setattr(self, name.lower().replace(" ","_") + "_chk", cb)

        lbl_scan = QLabel("Tarama tipi:")
        lbl_scan.setToolTip("Tarama metodunu seçin.")
        row3.addWidget(lbl_scan)
        self.scan_type = QComboBox()
        methods = ["syn", "fin", "null", "ack", "connect", "udp", "xmas"]
        self.scan_type.addItems(methods)
        # Metodlara açıklama eklemek için tool tip belirleme
        tips = {
        "syn": "Portun açık olup olmadığını görmek için sadece ilk adım (SYN) gönderilir, bağlantı tamamlanmaz. Hızlı ve gizli bir tarama yöntemidir.",
        "fin": "FIN bayrağı göndererek bazı sistemlerde kapalı portlar belirlenmeye çalışılır.",
        "null": "Hiç bayrak içermeyen paketle portlara istek gönderilir, cevap yoksa port açık olabilir.",
        "ack": "ACK bayrağı ile güvenlik duvarı arkasındaki filtreleme durumu anlaşılmaya çalışılır.",
        "connect": "Standart bağlantı kurularak (3 yönlü el sıkışma) portun açık mı kapalı mı olduğu net olarak belirlenir.",
        "udp": "UDP paketleri gönderilerek o portta çalışan bir servis var mı kontrol edilir, ama cevap gelmeyebilir.",
        "xmas": "Birden fazla bayrak (FIN, PSH, URG) içeren özel bir paket gönderilir, bazı sistemlerde gizli port taraması yapılır."
        }   

        for method, tip in tips.items():
            idx = self.scan_type.findText(method)
            if idx >= 0:
                self.scan_type.setItemData(idx, tip, Qt.ToolTipRole)
        self.scan_type.currentTextChanged.connect(self.update_summary)
        row3.addWidget(self.scan_type)

        self.os_detect = QCheckBox("OS Detect")
        self.os_detect.setToolTip("İşletim sistemi tespiti yapar.")
        self.os_detect.stateChanged.connect(self.update_summary)
        row3.addWidget(self.os_detect)
        self.service_detect = QCheckBox("Service Detect")
        self.service_detect.setToolTip("Servis versiyon tespiti yapar.")
        self.service_detect.stateChanged.connect(self.update_summary)
        row3.addWidget(self.service_detect)

        # Script seçenekleri
        lbl_scripts = QLabel("Scripts:")
        lbl_scripts.setToolTip("Taramaya ekstra özellik eklemek için kullanılır. Hazır script seçebilir ya da kendi komutunu yazabilirsin.")

        row3.addWidget(lbl_scripts)
        self.script_combo = QComboBox()
        categories = ["", "safe", "intrusive", "vuln", "exploit", "auth", "brute", "discovery", "default"]
        self.script_combo.addItems(categories)
        # Script kategorilerine açıklama ekle
        script_tips = {
        "safe": "Zararsız olarak kabul edilen scriptler.",
        "intrusive": "Sisteme zarar verebilecek agresif scriptler.",
        "vuln": "Bilinen güvenlik açıklarını test eden scriptler.",
        "exploit": "Açıklardan yararlanan (exploit) scriptler.",
        "auth": "Kimlik doğrulama ile ilgili scriptler.",
        "brute": "Brute-force saldırılarını gerçekleştiren scriptler.",
        "discovery": "Ağdaki servisleri ve cihazları keşfetmeye yönelik scriptler.",
        "default": "Varsayılan olarak çalışan temel script seti."
        }
        for i in range(self.script_combo.count()):
            text = self.script_combo.itemText(i)
            if text in script_tips:
                self.script_combo.setItemData(i, script_tips[text], Qt.ToolTipRole)

        self.script_combo.setToolTip("Script kategorisi seçin.")
        self.script_combo.currentTextChanged.connect(self.on_script_combo_changed)
        row3.addWidget(self.script_combo)
        self.script_input = QLineEdit()
        self.script_input.setPlaceholderText("Özel NSE script girin...")
        self.script_input.setToolTip("Kendi script adınızı girin.")
        self.script_input.textChanged.connect(self.on_script_input_changed)
        row3.addWidget(self.script_input)

        layout.addLayout(row3)

         # Çıktı bölümü
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setToolTip("CLI çıktısını burada görebilirsiniz.")
        layout.addWidget(self.output)

        # Başlat butonu
        self.start_btn = QPushButton("Taramayı Başlat")
        self.start_btn.setToolTip("Taramayı başlatır ve CLI modülünü çalıştırır.")
        self.start_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.start_btn)

        main.setLayout(layout)
        self.setCentralWidget(main)

        # İlk durum
        self.on_default_ports_toggled()
        self.update_summary()

    def on_default_ports_toggled(self):
        enabled = not self.use_default_ports.isChecked()
        self.port_input.setEnabled(enabled)
        self.port_file_btn.setEnabled(enabled)
        self.update_summary()

    def on_script_combo_changed(self, text):
        # Eğer combo’dan bir şey seçilmişse custom script girişi kapat
        self.script_input.setEnabled(text == "")
        self.update_summary()

    def on_script_input_changed(self, text):
        # Eğer custom script yazılıyorsa combo’yu kapat
        self.script_combo.setEnabled(text == "")
        self.update_summary()

    def update_summary(self):
        args = []
        if self.target_input.text():
            args += self.target_input.text().split(',')
        if not self.use_default_ports.isChecked():
            args += ["-p", self.port_input.text()]
        if self.exclude_input.text():
            args += ["--exclude"] + self.exclude_input.text().split(',')
        if self.exclude_ports_input.text():
            args += ["--exclude-ports", self.exclude_ports_input.text()]
        if self.icmp_ping_chk.isChecked():    args.append("--ping")
        if self.tcp_ack_ping_chk.isChecked(): args.append("--PA")
        if self.udp_ping_chk.isChecked():     args.append("--PU")
        args += ["--scan-type", self.scan_type.currentText()]
        if self.os_detect.isChecked():       args.append("--os-detect")
        if self.service_detect.isChecked():  args.append("--service-detect")
        script_val = self.script_combo.currentText() or self.script_input.text()
        if script_val:
            args += ["--scripts", script_val]
        self.summary.setText("Komut: portarama.py " + " ".join(args))

    def load_ip_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "IP Listesi Seç", "", "Metin Dosyaları (*.txt)")
        if path:
            with open(path) as f:
                lines = [l.strip() for l in f if l.strip()]
            self.target_input.setText(",".join(lines))

    def load_exclude_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Hariç Liste Seç", "", "Metin Dosyaları (*.txt)")
        if path:
            with open(path) as f:
                lines = [l.strip() for l in f if l.strip()]
            self.exclude_input.setText(",".join(lines))

    def load_port_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Port Listesi Seç", "", "Metin Dosyaları (*.txt)")
        if path:
            with open(path) as f:
                ports = [l.strip() for l in f if l.strip()]
            self.port_input.setText(",".join(ports))
            self.use_default_ports.setChecked(False)
            self.update_summary()

    def toggle_controls(self, enabled):
        controls = [
            self.target_input, self.ip_file_btn,
            self.exclude_input, self.exclude_file_btn,
            self.use_default_ports, self.port_input,
            self.port_file_btn, self.exclude_ports_input,
            self.icmp_ping_chk, self.tcp_ack_ping_chk, self.udp_ping_chk,
            self.scan_type, self.os_detect,
            self.service_detect, self.script_combo,
            self.script_input, self.start_btn
        ]
        for w in controls:
            w.setEnabled(enabled)

    def start_scan(self):
        # Parametreleri topla
        argv = []
        if self.target_input.text():
            argv += self.target_input.text().split(',')
        if not self.use_default_ports.isChecked():
            argv += ["-p", self.port_input.text()]
        if self.exclude_input.text():
            argv += ["--exclude"] + self.exclude_input.text().split(',')
        if self.exclude_ports_input.text():
            argv += ["--exclude-ports", self.exclude_ports_input.text()]
        if self.icmp_ping_chk.isChecked():    argv.append("--ping")
        if self.tcp_ack_ping_chk.isChecked(): argv.append("--PA")
        if self.udp_ping_chk.isChecked():     argv.append("--PU")
        argv += ["--scan-type", self.scan_type.currentText()]
        if self.os_detect.isChecked():       argv.append("--os-detect")
        if self.service_detect.isChecked():  argv.append("--service-detect")
        script_val = self.script_combo.currentText() or self.script_input.text()
        if script_val:
            argv += ["--scripts", script_val]

        # Kontrolleri kapat ve çıktı temizle
        self.toggle_controls(False)
        self.output.clear()

        # Worker + Thread
        self.worker = ScanWorker(argv)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)

        # Sinyal-slot bağlantıları
        self.worker.output_ready.connect(self.output.append)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(lambda: self.toggle_controls(True))
        self.thread.started.connect(self.worker.run)
        self.thread.finished.connect(self.thread.deleteLater)

        # Başlat
        self.thread.start()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PortScannerGUI()
    window.show()
    sys.exit(app.exec_())

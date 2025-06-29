Arayüzlü Port Tarayıcısı

**Port Tarayıcısı** ağ güvenliği uzmanları ve sistem yöneticileri için hem grafiksel hem de komut satırı arayüzü sunan, Python + Scapy tabanlı esnek bir port tarama aracıdır.

---

##  İçerik

- [Özellikler](#özellikler)
- [Teknolojiler ve Gereksinimler](#teknolojiler-ve-gereksinimler)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
  - [Komut Satırı (CLI)](#komut-satırı-cli)
  - [Grafiksel Arayüz (GUI)](#grafiksel-arayüz-gui)
- [Ekran Görüntüleri](#ekran-görüntüleri)
- [Katkıda Bulunanlar](#katkıda-bulunanlar)
- [Lisans](#lisans)

---

##  Özellikler

- **Çoklu Tarama Yöntemleri**:
  - TCP Connect, SYN, FIN, NULL, Xmas, ACK
  - UDP ve SCTP destekli
- **Hedef Spesifikasyonu**:
  - Tekli IP, IP aralığı (CIDR veya kısa form), alan adı
  - Dosyadan toplu IP yükleme ve hariç tutma
- **Port Spesifikasyonu**:
  - Belirli portlar (virgülle ayrılmış), aralık, tüm portlar (1–65535)
  - Hariç tutulacak portlar
  - Servis adına göre filtreleme (`http???`, `ssh`, vb.)
- **Host Discovery**:
  - ICMP Echo (ping), TCP-ACK, UDP (port unreachable) yöntemleri
- **Servis ve Versiyon Bilgisi**:
  - Scapy ile paket bazlı tespit
  - `python-nmap` ile OS tespiti, `-sV`, NSE script’leri
- **Optimizasyon Opsiyonları**:
  - “Popüler portlar” modu (Nmap verilerine göre ilk 1.000 yaygın port)
  - Sadece açık portları tarama ve gösterme
- **Kullanıcı Dostu GUI**:
  - PyQt5 tabanlı arayüz
  - Asenkron tarama (iş parçacıklarıyla arayüz kilitlenmez)

---

##  Teknolojiler ve Gereksinimler

- Python 3.7+
- [Scapy](https://scapy.net/)
- PyQt5
- python-nmap
- requests (popüler port listesi güncelleme için)
- ipaddress, argparse, socket, subprocess, os, tempfile

---

##  Kurulum

1. Depoyu klonlayın:

   ```bash
   git clone https://github.com/deuswashere/Arayuzlu-Port-Tarayicisi.git
   cd Arayuzlu-Port-Tarayicisi
   ```

2. Sanal ortam oluşturun ve etkinleştirin (önerilir):

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Gerekli paketleri yükleyin:

   ```bash
   pip install -r requirements.txt
   ```

4. `portlist.txt` ve `popularport.txt` dosyalarını oluşturmak için (opsiyonel):

   ```bash
   python generate_portlists.py
   ```

---

## 💡 Kullanım

### Komut Satırı (CLI)

```bash
python portarama.py \
  --target 192.168.1.1-50 \
  --scan-type syn \
  --ports 22,80,443 \
  --exclude 192.168.1.10 \
  --exclude-ports 135-139 \
  --os-detect \
  --service-detect \
  --scripts vuln
```

- `--target`, `-t`: Hedef IP / aralık / dosya
- `--scan-type`: `connect`, `syn`, `fin`, `null`, `xmas`, `ack`, `udp`
- `--ports`, `-p`: Port listesi (virgül/aralık) veya `-p -` (tüm portlar)
- `--exclude`, `--excludefile`: Hariç IP’ler
- `--exclude-ports`: Hariç portlar
- `--os-detect`, `--service-detect`, `--scripts`: Nmap entegrasyonu

### Grafiksel Arayüz (GUI)

```bash
python gui.py
```

1. **Hedef** kutusuna IP/aralık veya `.txt` dosya seçin.
2. **Hariç IP** ve **Port Ayarları**’ndan filtreleri yapılandırın.
3. “Taramayı Başlat” butonuna tıklayın.
4. Çıktılar anlık olarak alt pencereye aktarılacak, işlem sonunda durumu görebilirsiniz.

---

## 🖼️ Ekran Görüntüleri



---

![image](https://github.com/user-attachments/assets/d152b9dd-33c8-4119-9b68-4b15bf1333c2)





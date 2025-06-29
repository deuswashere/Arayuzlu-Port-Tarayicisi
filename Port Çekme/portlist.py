import requests

# Nmap'in port hizmetleri listesi URL'si
NMAP_SERVICES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"

# Veri çekme ve dosyayı oluşturma fonksiyonu
def fetch_and_save_ports():
    try:
        # Nmap'in hizmet listesini çek
        response = requests.get(NMAP_SERVICES_URL)
        response.raise_for_status()  # HTTP hatalarını kontrol et

        # Veriyi satırlara böl
        lines = response.text.splitlines()

        # Port verisini saklamak için liste
        port_list = []

        # Her satırı işle ve gerekli bilgileri al
        for line in lines:
            if not line.startswith("#") and line.strip():  # Yorumları ve boş satırları atla
                parts = line.split()
                if len(parts) >= 2:
                    service_name = parts[0]
                    port_proto = parts[1]
                    if "/" in port_proto:
                        port_number, protocol = port_proto.split("/")
                        port_list.append(f"{port_number}\t{protocol}\t{service_name}")

        # Veriyi portlist.txt dosyasına yaz
        with open("portlist.txt", "w") as file:
            file.write("Sayısı\tProtokol\tServis Adı\n")
            file.write("-" * 40 + "\n")
            file.write("\n".join(port_list))

        print("Port listesi 'portlist.txt' dosyasına yazıldı.")
    except requests.RequestException as e:
        print(f"Veri çekilirken hata meydana geldi: {e}")

# Fonksiyonu çalıştır
fetch_and_save_ports()

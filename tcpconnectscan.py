from scapy.all import *

def tcp_connect_scan_port(ip, port):
    syn = IP(dst=ip)/TCP(dport=port, flags='S') # SYN bayrağı oluşturma
    response = sr1(syn, timeout=1, verbose=0) # SYN bayrağını gönderme ve cevap bekleme

    if response is None:
        return "Filtered"  # Yanıt yoksa port filtreli de
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK bayrağı gelirse
            # Bağlantıyı tamamlamak için ACK gönder
            ack = IP(dst=ip)/TCP(dport=port, flags='A', ack=response[TCP].seq + 1)
            send(ack, verbose=0)
            
            # Bağlantıyı sonlandırmak için RST gönder
            rst = IP(dst=ip)/TCP(dport=port, flags='R')
            send(rst, verbose=0)
            
            return "Open"
        elif response.getlayer(TCP).flags == 0x14:  # RST bayrağı gelirse
            return "Closed"


def scan_ports(ip, port_range):
    for port in port_range:
        status = scan_port(ip, port)
        print(f"Port {port}: {status}")

if __name__ == "__main__":
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))
    
    port_range = range(start_port, end_port + 1)
    scan_ports(target_ip, port_range)
"""
from scapy.all import *

# Port isimlerini txt dosyasından yükle
def load_port_names():
    port_names = {}
    with open("C:\\Users\\berke\\OneDrive\\Desktop\\staj\\Port Tarayıcısı\\portlist.txt", "r") as file:
        for line in file:
            if line.startswith("Sayısı"):  # Başlık satırlarını atla
                continue
            parts = line.split()
            if len(parts) >= 3:
                port = int(parts[0])
                protocol = parts[1].lower()
                service_name = parts[2]
                port_names[(port, protocol)] = service_name
    return port_names

def scan_port(ip, port, port_names):
    # TCP bağlantısı kurmaya çalış
    syn = IP(dst=ip)/TCP(dport=port, flags='S')
    response = sr1(syn, timeout=1, verbose=0)

    if response is None:
        return "Filtered"  # Yanıt yoksa port filtreli
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            # Bağlantıyı tamamlamak için ACK gönder
            send(IP(dst=ip)/TCP(dport=port, flags='A', ack=response[TCP].seq + 1), verbose=0)
            return "Open"  # Port açık
        elif response.getlayer(TCP).flags == 0x14:  # RST
            return "Closed"  # Port kapalı

def scan_ports(ip, port_range, port_names):
    for port in port_range:
        status = scan_port(ip, port, port_names)
        service = port_names.get((port, 'tcp'), "Bilinmeyen")
        print(f"Port {port}: {status} - {service}")

if __name__ == "__main__":
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))
    
    port_names = load_port_names()  # Port isimlerini yükle
    port_range = range(start_port, end_port + 1)
    scan_ports(target_ip, port_range, port_names)
    """
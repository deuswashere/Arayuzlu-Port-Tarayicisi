from scapy.all import *

def xmas_scan_port(ip, port):
    # Xmas TCP paketi oluştur (PSH, FIN ve URG bayrakları set edilmiştir)
    xmas_packet = IP(dst=ip)/TCP(dport=port, flags='FPU')
    response = sr1(xmas_packet, timeout=1, verbose=0)  # Paketi gönder ve yanıtı bekle

    if response is None:
        return "Open|Filtered"  # Yanıt yoksa port Open|Filtered
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x14:  # RST bayrağı gelirse port kapalı
            return "Closed"
        
    return "Open|Filtered"  # Diğer durumlarda yine Open|Filtered

def xmas_scan_ports(ip, port_range):
    for port in port_range:
        status = xmas_scan_port(ip, port)
        print(f"Port {port}: {status}")

if __name__ == "__main__":
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))

    port_range = range(start_port, end_port + 1)
    results = xmas_scan_ports(target_ip, port_range)

    
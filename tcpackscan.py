from scapy.all import *

def tcp_ack_scan_port(ip, port):
    ack_packet = IP(dst=ip)/TCP(dport=port, flags='A') # ACK paketi oluştur
    response = sr1(ack_packet, timeout=1, verbose=0)  # Paketi gönder ve yanıtı bekle

    if response is None:
        return "Filtered"  # Yanıt yoksa port filtrelenmiş
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x14:  # RST bayrağı gelirse port kapalı
            return "Closed"
    elif response.haslayer(ICMP):
        if int(response[ICMP].type) == 3:  # ICMP "Destination Unreachable" yanıtı varsa port filtrelenmiş
            return "Filtered" 

def ack_scan_ports(ip, port_range):
    for port in port_range:
        status = ack_scan_port(ip, port)
        print(f"Port {port}: {status}")

if __name__ == "__main__":
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))

    port_range = range(start_port, end_port + 1)
    results = ack_scan_ports(target_ip, port_range)

    # Sonuçları yazdır
    for port, status in results.items():
        print(f"Port {port}: {status}")
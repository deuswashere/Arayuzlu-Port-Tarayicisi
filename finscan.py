from scapy.all import *

def fin_scan_port(ip, port):
    fin_packet = IP(dst=ip)/TCP(dport=port, flags='F')  # FIN bayrağı oluştur
    response = sr1(fin_packet, timeout=1, verbose=0)  # FIN paketi gönder ve cevap bekle

    if response is None:
        return "Open|Filtered"  # Yanıt yoksa port Open|Filtered
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x14:  # RST bayrağı gelirse port kapalı
            return "Closed"  
    else:
        return "Open|Filtered"  # Diğer durumlarda yine Open|Filtered

def fin_scan_ports(ip, port_range):
    for port in port_range:
        status = fin_scan_port(ip, port)
        print(f"Port {port}: {status}")

if __name__ == "__main__":
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))

    port_range = range(start_port, end_port + 1)
    fin_scan_ports(target_ip, port_range)

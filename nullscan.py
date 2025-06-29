from scapy.all import *

def null_scan_port(ip, port):
    null_packet = IP(dst=ip)/TCP(dport=port, flags='') # Null TCP paketi oluştur (hiçbir bayrağı set etme)
    response = sr1(null_packet, timeout=1, verbose=0)  # Paketi gönder ve yanıtı bekle

    if response is None:
        return "Open|Filtered"  # Yanıt yoksa port Open|Filtered
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x14:  # RST bayrağı gelirse port kapalı
            return "Closed"
    return "Open|Filtered"  # Diğer durumlarda yine Open|Filtered

def null_scan_ports(ip, port_range):
      for port in port_range:
        status = null_scan_port(ip, port)
        print(f"Port {port}: {status}")

if __name__ == "__main__":
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))

    port_range = range(start_port, end_port + 1)
    results = null_scan_ports(target_ip, port_range)

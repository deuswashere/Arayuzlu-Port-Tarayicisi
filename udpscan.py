from scapy.all import *

def udp_scan_port(ip, port):
    udp_packet = IP(dst=ip)/UDP(dport=port) # UDP paketini oluşturur
    
    # UDP paketini gönderir ve karşı paket bekler
    response = sr1(udp_packet, timeout=1, verbose=0)  

    if response is None:
        # İlk yanıt yoksa, paketi tekrar gönder
        response = sr1(udp_packet, timeout=1, verbose=0)

    if response is None:
        # İkinci yanıt yoksa port open|filtered olarak seçilir.
        return "Open|Filtered"
    
    elif response.haslayer(UDP):
        return "Open" # UDP paketi geldiyse açık 
    
    elif response.haslayer(ICMP):

        icmp_type = response.getlayer(ICMP).type

        # Eğer ICMP(Type=3) Destination Unreachable cevabo dönerse port kapalı
        if icmp_type == 3:  
            return "Closed"
    
    return "Filtered"  # Diğer durumlar için filtreli 

def scan_ports(ip, port_range):
    for port in port_range:
        status = scan_port(ip, port)
        if status == "Open":
            print(f"Port {port}: {status}")
        elif status == "Open|Filtered":
            print(f"Port {port}: {status}")
        elif status == "Filtered":
            print(f"Port {port}: {status}")
        elif status == "Closed":
            print(f"Port {port}: {status}")

if __name__ == "__main__":
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))
    
    port_range = range(start_port, end_port + 1)
    scan_ports(target_ip, port_range)
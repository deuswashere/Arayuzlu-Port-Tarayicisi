from scapy.all import *

def tcp_syn_scan_port(ip, port):
    syn = IP(dst=ip)/TCP(dport=port, flags='S') # SYN bayrağı oluşturma
    response = sr1(syn, timeout=1, verbose=0) # SYN bayrağını gönderme ve cevap bekleme
    
    if response is None:
        return "Filtered"  # Yanıt yoksa port filtreli
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK bayrağı gelirse

            # Bağlantıyı sonlandırmak için RST gönder
            rst = IP(dst=ip)/TCP(dport=port, flags='R')
            send(rst, verbose=0)
            return "Open"  # Port açık
        
        elif response.getlayer(TCP).flags == 0x14:  # RST
            return "Closed"  # Port kapalı

def scan_ports(ip, port_range):
    for port in port_range:
        status = scan_port(ip, port)
        print(f"Port {port}: {status}")

if __name__ == "__main__":  # Burada _name_ yerine __name__ kullanmalısınız
    target_ip = input("Tarama yapmak istediğiniz IP adresini girin: ")
    start_port = int(input("Başlangıç portunu girin: "))
    end_port = int(input("Bitiş portunu girin: "))
    
    port_range = range(start_port, end_port + 1)
    scan_ports(target_ip, port_range)
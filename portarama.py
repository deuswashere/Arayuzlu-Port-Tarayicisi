import argparse
from scapy.all import conf, sr, sr1, IP, ICMP, TCP, UDP
from finscan import fin_scan_port
from nullscan import null_scan_port
from tcpackscan import tcp_ack_scan_port
from tcpconnectscan import tcp_connect_scan_port
from tcpsynscan import tcp_syn_scan_port
from udpscan import udp_scan_port
from xmasscan import xmas_scan_port
from ipaddress import ip_network
import nmap
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Pcap kullanımı aktif ediliyor.
# conf.use_pcap = True

# ------------------ HOST DISCOVERY FONKSİYONLARI ------------------

def discover_hosts(targets, icmp=False, pa=False, pu=False):
    alive_hosts = []
    for ip in targets:
        if icmp and host_discovery_icmp(ip):
            alive_hosts.append(ip)
        elif pa and host_discovery_PA(ip):
            alive_hosts.append(ip)
        elif pu and host_discovery_PU(ip):
            alive_hosts.append(ip)
        elif not (icmp or pa or pu):
            # Eğer hiçbir keşif yöntemi seçilmemişse tüm hedefleri kabul et
            alive_hosts.append(ip)
    return alive_hosts

def host_discovery_icmp(target, timeout=2):
    pkt = IP(dst=target)/ICMP()
    ans, _ = sr(pkt, timeout=timeout, verbose=0)
    return bool(ans)


def host_discovery_PA(target, dport=80, timeout=2):
    pkt = IP(dst=target)/TCP(dport=dport, flags="A")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    return resp is not None


def host_discovery_PU(target, dport=53, timeout=2):
    pkt = IP(dst=target)/UDP(dport=dport)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    return resp is None or (resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3)

# ------------------ MEVCUT FONKSİYONLAR ------------------

def load_port_names(portlist_path):
    port_names = {}
    with open(portlist_path, "r", encoding="latin-1") as file:
        for line in file:
            line = line.strip()
            if line.startswith("Port") or not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                try:
                    port = int(parts[0])
                    protocol = parts[1].lower()
                    service_name = parts[2]
                    port_names[(port, protocol)] = service_name
                except ValueError:
                    continue
    return port_names


def load_ports_file(path):
    ports = []
    if os.path.isfile(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                try:
                    ports.append(int(line))
                except ValueError:
                    continue
    return ports


def parse_custom_ports(port_str):
    ports = []
    for port_range in port_str.split(","):
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(port_range))
    return ports


def get_ports_by_service(service_name, port_dict):
    matching_ports = {"tcp": [], "udp": [], "sctp": []}
    for (port, protocol), name in port_dict.items():
        if service_name.endswith("???"):
            if name.lower().startswith(service_name[:-3].lower()):
                matching_ports[protocol].append(port)
        elif name.lower() == service_name.lower():
            matching_ports[protocol].append(port)
    return matching_ports


def parse_ports(port_str, port_dict):
    if port_str.endswith('.txt') and os.path.exists(port_str):
        file_ports = load_ports_file(port_str)
        return {"tcp": file_ports, "udp": [], "sctp": []}

    if port_str == "-":
        rng = list(range(1, 65536))
        return {"tcp": rng.copy(), "udp": rng.copy(), "sctp": rng.copy()}

    ports = {"tcp": [], "udp": [], "sctp": []}
    for part in port_str.split(","):
        part = part.strip()
        if part.startswith("U:"):
            ports["udp"].extend(parse_custom_ports(part[2:]))
        elif part.startswith("S:"):
            ports["tcp"].extend(parse_custom_ports(part[2:]))
        elif part.isalpha() or part.endswith("???"):
            matching_ports = get_ports_by_service(part, port_dict)
            for proto, proto_ports in matching_ports.items():
                ports[proto].extend(proto_ports)
        else:
            ports["tcp"].extend(parse_custom_ports(part))
    return ports


def parse_ip_range(ip_range):
    if "-" in ip_range and "/" not in ip_range:
        base_ip, range_part = ip_range.rsplit(".", 1)
        start, end = map(int, range_part.split("-"))
        return [f"{base_ip}.{i}" for i in range(start, end + 1)]
    elif "/" in ip_range:
        return [str(ip) for ip in ip_network(ip_range, strict=False)]
    else:
        return [ip_range]


def parse_short_ip_range(ip_range):
    if "," in ip_range:
        base_ip, last_part = ip_range.rsplit(".", 1)
        ips = []
        for part in last_part.split(","):
            if part.isdigit():
                ips.append(f"{base_ip}.{part}")
        return ips
    return [ip_range]


def load_ip_list(file_path):
    with open(file_path, "r") as file:
        return [line.strip() for line in file if line.strip()]

# ------------------ SCAN TARGET ------------------

def scan_target(ip, ports, scan_type, port_dict):
    scan_methods = {
        "fin": fin_scan_port,
        "null": null_scan_port,
        "ack": tcp_ack_scan_port,
        "connect": tcp_connect_scan_port,
        "syn": tcp_syn_scan_port,
        "udp": udp_scan_port,
        "xmas": xmas_scan_port,
    }

    scan_function = scan_methods.get(scan_type)
    if not scan_function:
        raise ValueError(f"Unsupported scan type: {scan_type}")

    results = []
    seen = set()
    for port in sorted(ports):
        if port in seen:
            continue
        seen.add(port)
        try:
            status = scan_function(ip, port)
        except Exception as e:
            print(f"[!] {ip}:{port} taramasında hata: {e}")
            continue

        if str(status).lower() != 'open':
            continue
        protocol = "udp" if scan_type == "udp" else "tcp"
        desc = port_dict.get((port, protocol), "Unknown")
        results.append((port, status, desc))
    return results

# ------------------ NMAP DETECTION ------------------

def nmap_detection(target, do_os, do_service, ports, scripts=None, discovery=""):
    nm = nmap.PortScanner()
    arguments = discovery + " " if discovery else ""
    if do_os:
        arguments += "-O "
    if do_service:
        arguments += "-sV "
    if scripts:
        arguments += f"--script={scripts} "

    port_string = ",".join(str(p) for p in sorted(ports))
    #print(f"{target} için nmap taraması başlatılıyor. Argümanlar: {arguments.strip()} | Portlar: {port_string}")
    try:
        nm.scan(hosts=target, ports=port_string, arguments=arguments.strip())
        return nm
    except Exception as e:
        print(f"[Nmap] Tarama sırasında hata oluştu: {e}")
        return None

# ------------------ MAIN ------------------

def main():
    parser = argparse.ArgumentParser(description="Custom Port Scanner with OS, Service and Host Discovery")
    parser.add_argument("targets", nargs="*", help="Target IPs/Hostnames")
    parser.add_argument("-p", "--ports", type=str, default="popularport.txt", help="Tarama yapılacak portlar (örn. 1-1024 veya popularport.txt)")
    parser.add_argument("--portlist", type=str, default="portlist.txt", help="Port listesi dosyasının yolu")
    parser.add_argument("-iL", "--input-list", type=str, help="Hedef IP adreslerini içeren dosya")
    parser.add_argument("--exclude", nargs="*", help="Tarama dışı bırakılacak IP veya aralıklar")
    parser.add_argument("--excludefile", type=str, help="Tarama dışı bırakılacak IP'leri içeren dosya")
    parser.add_argument("--exclude-ports", type=str, help="Tarama dışı bırakılacak port aralıkları")
    parser.add_argument("--os-detect", action="store_true", help="Nmap ile OS detection yap")
    parser.add_argument("--service-detect", action="store_true", help="Nmap ile servis detection yap")
    parser.add_argument("--scripts", nargs='?', const='all', default=None,
                    help="Script taraması yap. İstersen kategori ver: vuln, safe, exploit, auth, brute, discovery, default.")
    parser.add_argument("--ping", action="store_true", help="ICMP ping ile host discovery yap")
    parser.add_argument("--PA", action="store_true", help="TCP ACK ile host discovery yap")
    parser.add_argument("--PU", action="store_true", help="UDP ile host discovery yap")
    parser.add_argument("--scan-type", type=str, default="syn", choices=["fin", "null", "ack", "connect", "syn", "udp", "xmas"], help="Tarama tipi")
    args = parser.parse_args()

    port_dict = load_port_names(args.portlist)
    targets = []
    if args.input_list:
        targets = load_ip_list(args.input_list)
    elif args.targets:
        for target in args.targets:
            if "," in target:
                targets.extend(parse_short_ip_range(target))
            elif "-" in target or "/" in target:
                targets.extend(parse_ip_range(target))
            else:
                targets.append(target)

    exclude_ips = set()
    if args.exclude:
        for ex in args.exclude:
            exclude_ips.update(parse_ip_range(ex))
    if args.excludefile:
        exclude_ips.update(load_ip_list(args.excludefile))
    targets = [ip for ip in targets if ip not in exclude_ips]

    parsed = parse_ports(args.ports, port_dict)
    ports = parsed["tcp"] + parsed["udp"] + parsed["sctp"]
    if args.exclude_ports:
        exclude_ports = set(parse_custom_ports(args.exclude_ports))
        ports = [p for p in ports if p not in exclude_ports]

    if not (args.ping or args.PA or args.PU):
        print("Ping yapılmadı, varsayılan olarak ICMP discovery uygulanacak.")
        targets = discover_hosts(targets, icmp=True)
    else:
        targets = discover_hosts(targets, icmp=args.ping, pa=args.PA, pu=args.PU)

    if not targets:
        print("Aktif hiçbir hedef bulunamadı.")
        return
    for target in targets:
        
        print(f"\nScanning {target} with {args.scan_type} scan...")
        if args.ping:
            print(f" - ICMP Ping: {'Success (Host Up)' if host_discovery_icmp(target) else 'No response (Host Down)'}")
        if args.PA:
            print(f" - TCP ACK Ping: {'Success (Host Up)' if host_discovery_PA(target) else 'No response (Host Down)'}")
        if args.PU:
            print(f" - UDP Ping: {'Assumed Up (No response is typical)' if host_discovery_PU(target) else 'Host Down'}")

        # 1) Scapy ile portları tara ve sadece açıkları al
        port_results = scan_target(target, ports, args.scan_type, port_dict)
        if port_results:
            for port, status, desc in port_results:
                print(f"Port {port}: {status} ({desc})")
        else:
            print("No open ports found.")
            continue

        # 2) Açık port listesini hazırla
        open_ports = [p for p, _, _ in port_results]

        # 3) Sadece açık portlarla Nmap işlemi
        if open_ports and (args.os_detect or args.service_detect or args.scripts):
                nm_results = nmap_detection(
                        target,
                        args.os_detect,
                        args.service_detect,
                        open_ports,
                        scripts=args.scripts if args.scripts != '' else None
                )
                if nm_results is None:
                        continue

                hosts = nm_results.all_hosts()
                if not hosts:
                        print("[Nmap] Hiçbir host sonucu bulunamadı.")
                        continue

                host = hosts[0]

                if args.os_detect:
                        os_matches = nm_results[host].get('osmatch', [])
                        print("\nOS Detection:")
                        if os_matches:
                                for os in os_matches:
                                        print(f" - OS: {os['name']} (Accuracy: {os['accuracy']}%)")
                        else:
                                print(" - Sonuç bulunamadı.")

                if args.service_detect:
                        tcp_services = nm_results[host].get('tcp', {})
                        print("\nService Detection (open):")
                        for port, service in sorted(tcp_services.items()):
                                if service.get('state') == 'open':
                                        name = service.get('name', 'unknown')
                                        product = service.get('product', '')
                                        version = service.get('version', '')
                                        print(f" - Port {port}: {name} {product} {version}".strip())

                if args.scripts:
                        category = args.scripts.lower() if isinstance(args.scripts, str) else 'all'
                        print(f"\nScript Detection (Kategori: {category}):")
                        found_script = False

                        # Genel script çıktıları
                        script_results_host = nm_results[host].get('script', {})
                        if script_results_host:
                                for script_name, output in script_results_host.items():
                                        print(f" - {script_name}: {output}")
                                        found_script = True

                        # Port bazlı script çıktıları
                        for proto in ['tcp', 'udp']:
                                proto_data = nm_results[host].get(proto, {})
                                for port, data in proto_data.items():
                                        if "script" in data:
                                                print(f"\nPort {port} ({proto}) Script Output:")
                                                for script_name, output in data["script"].items():
                                                        print(f" - {script_name}: {output}")
                                                found_script = True

                        if not found_script:
                                print(" - Script çıktısı bulunamadı.")


            


if __name__ == "__main__":
    main()

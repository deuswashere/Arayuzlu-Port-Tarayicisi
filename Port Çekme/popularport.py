import requests

url = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
response = requests.get(url)

if response.status_code == 200:
    lines = response.text.splitlines()
    ports = []
    
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        service = parts[0]
        port_proto = parts[1]
        try:
            frequency = float(parts[2])
        except (IndexError, ValueError):
            continue
        try:
            port, proto = port_proto.split("/")
            port = int(port)
        except:
            continue
        ports.append((port, frequency))
    
    # Aynı portu birden fazla kez eklememek için set kullanalım
    seen = set()
    unique_ports = []
    for port, freq in sorted(ports, key=lambda x: -x[1]):
        if port not in seen:
            seen.add(port)
            unique_ports.append(port)
        if len(unique_ports) == 1000:
            break

    # Dosyaya yaz
    with open("popularport.txt", "w") as f:
        for port in unique_ports:
            f.write(f"{port}\n")

    print("popularport.txt başarıyla yazıldı. Toplam:", len(unique_ports))
else:
    print("nmap-services indirilemedi.")

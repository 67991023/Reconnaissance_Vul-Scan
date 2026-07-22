import nmap

scanner = nmap.PortScanner()

scanner.scan('127.0.0.1', '22-443')

for host in scanner.all_hosts():
    print(f"Host: {host} ({scanner[host].hostname()})")
    print(f"State: {scanner[host].state()}")
    for proto in scanner[host].all_protocols():
        print(f"Protocol: {proto}")
        ports = scanner[host][proto].keys()
        for port in ports:
            print(f"Port: {port} \t State: {scanner[host][proto][port]['state']}")
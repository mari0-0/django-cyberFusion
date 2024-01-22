# port_scanner.py

import nmap

def run_nmap(domain):
    nm = nmap.PortScanner()
    nm.scan(hosts=domain)

    result_strings = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']

                result_strings.append(
                    f"Port: {port}, Protocol: {proto}, Service: {service}, State: {state}, Version: {version}"
                )
    print("[+] Looking for open ports")

    return result_strings

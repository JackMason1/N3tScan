import re
import nmap
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

def check_vulnerabilities(protocol_version, key_exchange, cipher_suite):
    vulnerabilities = {
        "Lucky Thirteen": {"condition": "CBC" in cipher_suite, "colour": "green"},
        "RC4": {"condition": "RC4" in cipher_suite, "colour": "yellow"},
        "BEAST": {"condition": "TLS_RSA" in cipher_suite and "CBC" in cipher_suite and protocol_version in ["SSL 3.0", "TLSv1.0"], "colour": "blue"},
        "CRIME": {"condition": "TLS" in cipher_suite and "GZIP" in cipher_suite, "colour": "yellow"},
        "POODLE": {"condition": protocol_version == "SSL 3.0" and "CBC" in cipher_suite, "colour": "yellow"},
        "FREAK": {"condition": "EXPORT" in cipher_suite, "colour": "yellow"},
        "Logjam": {"condition": "DH" in key_exchange and not "ECDH" in key_exchange, "colour": "orange"},
        "SWEET32": {"condition": "3DES" in cipher_suite or "DES_CBC" in cipher_suite, "colour": "yellow"}
    }

    found_vulnerabilities = [{"vulnerability": vuln, "colour": details["colour"]} for vuln, details in vulnerabilities.items() if details["condition"]]

    return found_vulnerabilities

def ssl_scan1(address):
    target_host = ((address['host'][0]).split("/"))[0]
    for target_port in address['ports']:
        nm = nmap.PortScanner()
        if target_port['service'] == 'https':
            print (f"Checking: {target_host}")
            nm.scan(hosts=target_host, ports=str(target_port['port']), arguments='--script ssl-enum-ciphers')
            ssl_details = {}

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = list(nm[host][proto].keys())
                    for port in lport:
                        if 'script' in nm[host][proto][port] and 'ssl-enum-ciphers' in nm[host][proto][port]['script']:
                            ciphers_output = nm[host][proto][port]['script']['ssl-enum-ciphers']
                            current_version = None
                            for line in ciphers_output.split('\n'):
                                version_match = re.search(r'^\s*(TLSv1\.\d|SSLv\d\.\d|TLSv1\.\d{1,2})\s*:', line)
                                if version_match:
                                    current_version = version_match.group(1).strip()
                                    ssl_details[current_version] = []
                                elif current_version and 'ciphers:' in line.lower():
                                    continue  # Skip the 'ciphers:' line itself
                                elif current_version and re.search(r'^\s{6}[^\s]+', line):
                                    cipher_match = re.search(r'^\s{6}(\S.*?)\s+\((.*?)\)', line)
                                    if cipher_match:
                                        cipher_name, key_exchange = cipher_match.groups()
                                        vulns = check_vulnerabilities(current_version, key_exchange, cipher_name)
                                        # Ensure each cipher's vulnerabilities are stored in a list
                                        ssl_details[current_version].append({
                                            "cipher": cipher_name, 
                                            "keyExchange": key_exchange, 
                                            "vulnerabilities": vulns  # Changed to a list of vulnerabilities
                                        })
                                elif line.strip() == '' or re.search(r'^\s{2}\w', line):
                                    current_version = None  # We're out of the cipher list for the current version
            if ssl_details:
                target_port["ssl-ciphers"] = ssl_details
    
    return address

def findSSLCiphers(IP_addresses, threads_value):
    def process_address(address):
        return ssl_scan1(address)

    with ThreadPoolExecutor(max_workers=threads_value) as executor:
        results = executor.map(process_address, IP_addresses)
    
    return list(results)

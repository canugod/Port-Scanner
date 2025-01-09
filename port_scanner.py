import socket
import os
import sys
import time
from scapy.all import ARP, IP, ICMP, TCP, UDP, sr1, Raw

from concurrent.futures import ThreadPoolExecutor
import datetime
from netaddr import IPNetwork

# Define constants
OUTPUT_FILE = "scan_results.txt"

def validate_ip(ip):
    """Validates if the IP address is reachable via ARP."""
    pkt = ARP(pdst=ip)
    response = sr1(pkt, timeout=1, verbose=0)
    return response is not None

def ping_sweep(network):
    """Performs a ping sweep to find live hosts on the network."""
    print("Starting ping sweep...")
    live_hosts = []
    for ip in network:
        if validate_ip(ip):  # Check if the IP responds to ARP
            pkt = IP(dst=ip) / ICMP()
            reply = sr1(pkt, timeout=1, verbose=0)
            if reply:
                live_hosts.append(ip)
                print(f"Host {ip} is live.")
    return live_hosts

def scan_tcp_port(host, port):
    """Performs a TCP SYN scan on a given port."""
    try:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            return f"{host}:{port}/TCP - Open"
        elif response and response.haslayer(TCP) and response[TCP].flags == 0x14:
            return f"{host}:{port}/TCP - Closed"
    except Exception as e:
        return f"{host}:{port}/TCP - Error: {e}"
    return f"{host}:{port}/TCP - Filtered"

def scan_udp_port(host, port):
    """Performs a UDP scan on a given port."""
    try:
        pkt = IP(dst=host) / UDP(dport=port) / Raw(load="\x00")
        response = sr1(pkt, timeout=1, verbose=0)
        if not response:
            return f"{host}:{port}/UDP - Open|Filtered"
        elif response.haslayer(ICMP):
            return f"{host}:{port}/UDP - Closed"
    except Exception as e:
        return f"{host}:{port}/UDP - Error: {e}"
    return f"{host}:{port}/UDP - Filtered"

def os_detection(host):
    """Performs OS detection based on TTL and window size."""
    pkt = IP(dst=host) / ICMP()
    response = sr1(pkt, timeout=1, verbose=0)
    if response:
        ttl = response[IP].ttl
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Unknown"
    return "Unknown"

def save_results(results):
    """Saves the scan results to a file."""
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"Scan results\n")
        f.write(f"Started at: {datetime.datetime.now()}\n\n")
        for result in results:
            f.write(f"{result}\n")
        f.write(f"\nScan completed at: {datetime.datetime.now()}\n")

def main():
    target = input("Enter the target IP address or CIDR (e.g., 192.168.1.0/24): ")
    network = [str(ip) for ip in IPNetwork(target)] if "/" in target else [target]

    live_hosts = ping_sweep(network)
    if not live_hosts:
        print("No live hosts found.")
        return

    scan_results = []
    decoys = input("Enter decoy IPs (comma-separated): ").split(",")
    decoys = [ip.strip() for ip in decoys if validate_ip(ip)]

    print("Starting port scans...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        for host in live_hosts:
            os_info = os_detection(host)
            print(f"OS detection for {host}: {os_info}")
            for port in range(1, 1025):  # Scanning common ports
                tcp_result = executor.submit(scan_tcp_port, host, port).result()
                udp_result = executor.submit(scan_udp_port, host, port).result()
                scan_results.extend([tcp_result, udp_result])

    save_results(scan_results)
    print(f"Scan completed. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

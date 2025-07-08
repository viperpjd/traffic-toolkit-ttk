"""
Author: Peter Dunn
License: MIT
GitHub: https://github.com/viperpjd
LinkedIn: https://www.linkedin.com/in/pdunncs/
Description: Part of the Traffic Toolkit for network and security testing.
"""

# scanner.py
from scapy.all import IP, ICMP, sr1, conf, ARP, Ether, srp
import ipaddress

def ping_sweep(subnet, timeout=1):
    live_hosts = []
    for ip in ipaddress.IPv4Network(subnet, strict=False):
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp:
            print(f"[+] Host {ip} is up")
            live_hosts.append(str(ip))
    return live_hosts

def detect_gateway(iface):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
    ans, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv.psrc
    return None

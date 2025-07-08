"""
Author: Peter Dunn
License: MIT
GitHub: https://github.com/viperpjd
LinkedIn: https://www.linkedin.com/in/pdunncs/
Description: Part of the Traffic Toolkit for network and security testing.
"""

# generator.py
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, sendp, Raw
from common import random_mac, random_ip, random_port

def build_packet(proto, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, dns_qname=None):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)

    if proto == "ARP":
        return eth / ARP(psrc=src_ip, pdst=dst_ip, hwsrc=src_mac, hwdst=dst_mac)
    elif proto == "ICMP":
        return eth / ip / ICMP()
    elif proto == "DNS":
        return eth / ip / UDP(sport=src_port, dport=53) / DNS(rd=1, qd=DNSQR(qname=dns_qname or "example.com"))
    elif proto == "HTTP":
        tcp = TCP(sport=src_port, dport=dst_port, flags="PA", seq=100, ack=100)
        http_payload = f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\nUser-Agent: CustomGen\r\n\r\n"
        return eth / ip / tcp / Raw(load=http_payload)
    elif proto == "TCP":
        return eth / ip / TCP(sport=src_port, dport=dst_port, flags="S") / Raw(load="X"*32)
    elif proto == "UDP":
        return eth / ip / UDP(sport=src_port, dport=dst_port) / Raw(load="X"*32)
    else:
        raise ValueError("Unsupported protocol")

def send_packet(pkt, iface):
    sendp(pkt, iface=iface, verbose=False)

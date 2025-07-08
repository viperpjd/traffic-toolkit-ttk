"""
Author: Peter Dunn
License: MIT
GitHub: https://github.com/viperpjd
LinkedIn: https://www.linkedin.com/in/pdunncs/
Description: Part of the Traffic Toolkit for network and security testing.
"""

# sniffer.py
from scapy.all import sniff, TCP, IP
import json
import time

def start_sniffer(iface, dst_ip, dst_port, timeout=5, log_json=None, log_txt=None):
    results = []

    def filter_pkt(pkt):
        return IP in pkt and TCP in pkt and pkt[IP].src == dst_ip and pkt[TCP].sport == dst_port

    print(f"[Sniffer] Listening on {iface} for responses from {dst_ip}:{dst_port}...")
    packets = sniff(iface=iface, timeout=timeout, lfilter=filter_pkt)

    for pkt in packets:
        record = {
            "src_ip": pkt[IP].src,
            "src_port": pkt[TCP].sport,
            "flags": str(pkt[TCP].flags),
            "payload": bytes(pkt[TCP].payload).hex()[:64]
        }
        results.append(record)
        print(f"[Sniffer] {record}")

    if log_json:
        with open(log_json, 'w') as f:
            json.dump(results, f, indent=2)

    if log_txt:
        with open(log_txt, 'w') as f:
            for r in results:
                f.write(str(r) + '\n')

    return results

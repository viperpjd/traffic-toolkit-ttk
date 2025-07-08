"""
Author: Peter Dunn
License: MIT
GitHub: https://github.com/viperpjd
LinkedIn: https://www.linkedin.com/in/pdunncs/
Description: Part of the Traffic Toolkit for network and security testing.
"""

# replay.py
from scapy.all import rdpcap, sendp
import time

def replay_pcap(filename, iface, interval=1.0):
    packets = rdpcap(filename)
    for pkt in packets:
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(interval)
    print(f"Replayed {len(packets)} packets from {filename} on {iface}")

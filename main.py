"""
Author: Peter Dunn
License: MIT
GitHub: https://github.com/viperpjd
LinkedIn: https://www.linkedin.com/in/pdunncs/
Description: Part of the Traffic Toolkit for network and security testing.
"""

# main.py - Command-line interface for the traffic toolkit

import argparse
from generator import build_packet, send_packet
from replay import replay_pcap
from scanner import ping_sweep, detect_gateway
from sniffer import start_sniffer
from common import random_mac, random_ip, random_port
from scapy.all import get_if_hwaddr

def run_generator(args):
    src_mac = random_mac() if args.src_mac == "random" else args.src_mac
    src_ip = random_ip() if args.src_ip == "random" else args.src_ip
    src_port = random_port() if args.src_port is None else args.src_port
    dst_port = args.dst_port or (80 if args.protocol == "HTTP" else 443 if args.protocol == "SSL" else 12345)

    pkt = build_packet(
        proto=args.protocol,
        src_mac=src_mac,
        dst_mac=args.dst_mac,
        src_ip=src_ip,
        dst_ip=args.dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        dns_qname=args.dns_query
    )
    send_packet(pkt, args.iface)

def run_replay(args):
    replay_pcap(args.pcap_file, args.iface, args.interval)

def run_scan(args):
    if args.ping_sweep:
        live = ping_sweep(args.ping_sweep)
        print(f"Live hosts: {live}")
    elif args.detect_gateway:
        gw = detect_gateway(args.iface)
        print(f"Detected gateway: {gw}")

def run_sniff(args):
    start_sniffer(
        iface=args.iface,
        dst_ip=args.dst_ip,
        dst_port=args.dst_port,
        timeout=args.timeout,
        log_json=args.log_json,
        log_txt=args.log_txt
    )

def main():
    parser = argparse.ArgumentParser(description="Modular Traffic Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Generate
    gen = subparsers.add_parser("generate", help="Generate and send traffic")
    gen.add_argument("--iface", required=True)
    gen.add_argument("--src-mac", default="random")
    gen.add_argument("--dst-mac", required=True)
    gen.add_argument("--src-ip", default="random")
    gen.add_argument("--dst-ip", required=True)
    gen.add_argument("--src-port", type=int)
    gen.add_argument("--dst-port", type=int)
    gen.add_argument("--protocol", choices=["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"], required=True)
    gen.add_argument("--dns-query")

    # Replay
    rep = subparsers.add_parser("replay", help="Replay packets from pcap")
    rep.add_argument("pcap_file")
    rep.add_argument("--iface", required=True)
    rep.add_argument("--interval", type=float, default=1.0)

    # Scan
    scan = subparsers.add_parser("scan", help="Ping sweep or detect gateway")
    scan.add_argument("--iface", required=True)
    scan.add_argument("--ping-sweep", help="CIDR subnet to ping (e.g., 192.168.1.0/24)")
    scan.add_argument("--detect-gateway", action="store_true")

    # Sniff
    sniff = subparsers.add_parser("sniff", help="Sniff and log TCP replies")
    sniff.add_argument("--iface", required=True)
    sniff.add_argument("--dst-ip", required=True)
    sniff.add_argument("--dst-port", type=int, required=True)
    sniff.add_argument("--timeout", type=int, default=5)
    sniff.add_argument("--log-json")
    sniff.add_argument("--log-txt")

    args = parser.parse_args()

    if args.command == "generate":
        run_generator(args)
    elif args.command == "replay":
        run_replay(args)
    elif args.command == "scan":
        run_scan(args)
    elif args.command == "sniff":
        run_sniff(args)

if __name__ == "__main__":
    main()

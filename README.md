# 🧰 Traffic Toolkit (TTK)

A modular Python-based network traffic toolkit for penetration testers, red teamers, and network engineers. This tool allows you to generate custom packets, replay PCAP files, perform ping sweeps, sniff for TCP responses, and more.

---

## 🚀 Features

- **Traffic Generation** (TCP, UDP, ICMP, ARP, DNS, HTTP)
- **Packet Replay** from `.pcap` files
- **Ping Sweep** of `/24` subnets
- **Gateway Detection**
- **TCP Response Sniffer** with logging to JSON/TXT
- **Random IP, MAC, and Port Support**
- **Modular Code Structure**

---

## 📦 Requirements

```bash
pip install scapy cryptography
```

> Must be run with root privileges for raw packet access.

---

## 🧪 Example Usage

### 1. Generate Traffic
```bash
sudo python3 main.py generate --iface eth0 --dst-mac aa:bb:cc:dd:ee:ff --dst-ip 192.168.1.10 --protocol TCP
```

### 2. Replay PCAP
```bash
sudo python3 main.py replay replay_file.pcap --iface eth0 --interval 0.5
```

### 3. Ping Sweep
```bash
sudo python3 main.py scan --iface eth0 --ping-sweep 192.168.1.0/24
```

### 4. Detect Gateway
```bash
sudo python3 main.py scan --iface eth0 --detect-gateway
```

### 5. Sniff TCP Responses
```bash
sudo python3 main.py sniff --iface eth0 --dst-ip 192.168.1.10 --dst-port 80 --log-json out.json
```

---

## 📁 Modules

- `generator.py` – build and send custom packets
- `replay.py` – replay traffic from saved PCAP files
- `scanner.py` – ping sweep and gateway detection
- `sniffer.py` – passive TCP sniffer with JSON/TXT logging
- `common.py` – helper utilities
- `main.py` – CLI entrypoint

---

## 📜 License

MIT License – Use responsibly. This tool is intended for authorized testing and educational purposes only.

---

## 👤 Author

**Peter Dunn**  
Cybersecurity Engineer | Red Team Specialist  
[LinkedIn](https://www.linkedin.com/in/pdunncs/)  
[GitHub](https://github.com/viperpjd)

> Built with ❤️ for security testing and network research.

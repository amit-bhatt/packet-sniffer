# 📡 Packet Sniffer – Python & Scapy

A Python-based packet sniffer built using **Scapy**, capable of capturing and analyzing network packets in real-time. Useful for security research, traffic monitoring, and educational purposes.

---

## 🚀 Features

- Capture live packets from network interface
- Display:
  - Source IP, Destination IP
  - Protocol (TCP, UDP, ICMP)
  - Source and Destination Ports
- Optional: Filter by protocol or port
- Save captured packets to `.pcap` or `.csv` files

---

## ⚙️ Requirements

- Python 3.6+
- Scapy

Install dependencies:

```bash
pip install -r requirements.txt
pip install scapy
```
🧪 Example Usage

```bash
sudo python sniffer.py
sudo python sniffer.py --protocol tcp --port 80
```

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
```
Or manually:
pip install scapy

🧪 Example Usage

sudo python sniffer.py

Or with filter:

sudo python sniffer.py --protocol tcp --port 80

📂 Output Example
yaml


[+] Captured Packet
Src: 192.168.1.2 → Dst: 142.250.183.142 | Protocol: TCP | Sport: 50532 → Dport: 443
🛡️ Disclaimer
This tool is for educational purposes only.
Do not use on networks you don't own or have explicit permission to monitor.

👤 Author
Amit Bhatt
📧 amitbhatt7900@gmail.com
🔗 GitHub Profile

yaml

---

### ✅ Step 2: Commit the File
Click “**Commit changes**” at the bottom of the GitHub page.

---

Let me know once this is done — I’ll then give you the code for `sniffer.py` (the actual working script for packet capturing).

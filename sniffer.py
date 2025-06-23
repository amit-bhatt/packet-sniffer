from scapy.all import sniff, IP, TCP, UDP, ICMP
import argparse

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        if proto == 6 and TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif proto == 17 and UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif proto == 1 and ICMP in packet:
            protocol = "ICMP"
            sport = "-"
            dport = "-"
        else:
            protocol = f"Other({proto})"
            sport = "-"
            dport = "-"

        print(f"[+] Captured Packet")
        print(f"Src: {src} → Dst: {dst} | Protocol: {protocol} | Sport: {sport} → Dport: {dport}\n")

def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer using Scapy")
    parser.add_argument("--protocol", help="Filter by protocol: tcp, udp, icmp", type=str)
    parser.add_argument("--port", help="Filter by port", type=int)
    args = parser.parse_args()

    filters = []
    if args.protocol:
        filters.append(args.protocol.lower())
    if args.port:
        filters.append(f"port {args.port}")

    capture_filter = ' and '.join(filters)

    print(f"[+] Starting packet capture... (Filter: {capture_filter if capture_filter else 'None'})\n")
    sniff(filter=capture_filter, prn=process_packet, store=0)

if __name__ == "__main__":
    main()

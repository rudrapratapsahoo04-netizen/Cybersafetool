from pathlib import Path

def analyze_pcap():
    print("PCAP analyzer requires Scapy.")
    path = Path(input("PCAP/PCAPNG path: ").strip())
    if not path.is_file():
        print("File not found.")
        return
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        print("Install Scapy with: pip install scapy")
        return

    packets = rdpcap(str(path))
    protocols = {}
    conversations = {}
    for pkt in packets:
        proto = "OTHER"
        if TCP in pkt: proto = "TCP"
        elif UDP in pkt: proto = "UDP"
        elif IP in pkt: proto = "IP"
        protocols[proto] = protocols.get(proto, 0) + 1
        if IP in pkt:
            key = tuple(sorted((pkt[IP].src, pkt[IP].dst)))
            conversations[key] = conversations.get(key, 0) + 1

    print("Packets:", len(packets))
    print("Protocols:", protocols)
    print("Top conversations:")
    for pair, count in sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {pair[0]} <-> {pair[1]} : {count}")

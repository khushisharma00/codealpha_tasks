from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


def process_packet(packet):
    print("\n" + "=" * 70)
    print("Time :", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if packet.haslayer(IP):
        print("Source IP        :", packet[IP].src)
        print("Destination IP   :", packet[IP].dst)

    if packet.haslayer(TCP):
        print("Protocol         : TCP")
        print("Source Port      :", packet[TCP].sport)
        print("Destination Port :", packet[TCP].dport)

    elif packet.haslayer(UDP):
        print("Protocol         : UDP")
        print("Source Port      :", packet[UDP].sport)
        print("Destination Port :", packet[UDP].dport)

    else:
        print("Protocol         : Other")

    print("Packet Length    :", len(packet), "Bytes")
    print("=" * 70)


print("=" * 70)
print("      CODEALPHA - BASIC NETWORK SNIFFER")
print("=" * 70)
print("Capturing packets...")
print("Press Ctrl + C to stop.\n")

sniff(prn=process_packet, store=False)
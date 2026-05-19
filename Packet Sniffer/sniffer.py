from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


def process_packet(packet):
    print("\n=== New Packet Captured ===")

    if IP in packet:
        ip_layer = packet[IP]

        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if TCP in packet:
            print("Protocol Type: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol Type: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif ICMP in packet:
            print("Protocol Type: ICMP")

        payload = bytes(packet.payload)

        if payload:
            print(f"Payload: {payload[:50]}")


print("Starting Network Sniffer...")
print("Press CTRL+C to stop")

sniff(iface="Wi-Fi", prn=process_packet, store=False)
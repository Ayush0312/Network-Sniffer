from scapy.all import sniff, Ether, IP, TCP, UDP

# Packet callback function
def packet_callback(packet):
    # Check if the packet has an Ethernet layer
    if packet.haslayer(Ether):
        print("Ethernet Frame:")
        print(f"  Source MAC: {packet[Ether].src}")
        print(f"  Destination MAC: {packet[Ether].dst}")

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        print("\nIP Packet:")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  Protocol: {packet[IP].proto}")

        # Check for TCP packets
        if packet.haslayer(TCP):
            print("\nTCP Segment:")
            print(f"  Source Port: {packet[TCP].sport}")
            print(f"  Destination Port: {packet[TCP].dport}")
            print(f"  Sequence Number: {packet[TCP].seq}")
            print(f"  Acknowledgment Number: {packet[TCP].ack}")

        # Check for UDP packets
        elif packet.haslayer(UDP):
            print("\nUDP Datagram:")
            print(f"  Source Port: {packet[UDP].sport}")
            print(f"  Destination Port: {packet[UDP].dport}")

    print("\n" + "-"*50 + "\n")

# Start sniffing
print("Starting network sniffer...")
sniff(prn=packet_callback, store=0)

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol
        if proto == 6:  # TCP
            protocol = "TCP"
        elif proto == 17:  # UDP
            protocol = "UDP"
        else:
            protocol = "Other"

        # Extract and print packet information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        # If the packet has a payload, display it
        if protocol == "TCP" and TCP in packet:
            payload = packet[TCP].payload
            print(f"Payload: {payload}")
        elif protocol == "UDP" and UDP in packet:
            payload = packet[UDP].payload
            print(f"Payload: {payload}")

        print("-" * 50)

# Start sniffing (this example captures packets on all interfaces)
sniff(prn=packet_callback, store=0)

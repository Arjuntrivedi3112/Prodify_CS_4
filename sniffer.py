from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Determine the protocol
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"
        else:
            proto_name = "Other"

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {proto_name}")

        if proto_name in ["TCP", "UDP"]:
            payload = bytes(packet[proto_name].payload)
            print(f"Payload: {payload[:100]}\n")
        elif proto_name == "ICMP":
            print(f"Payload: ICMP Payload\n")
            
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)

from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"
        else:
            proto_name = str(protocol)

        print(f"\n--- Packet #{packet_count} | Time: {datetime.now().strftime('%H:%M:%S')} ---")
        print(f"Source IP : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol : {proto_name}")

        if TCP in packet:
            print(f"Source Port : {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"Source Port : {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors='ignore')
                print(f"Payload : {payload[:200]}")
            except:
                print("Payload : Binary Data")
        else:
            print("Payload : No Payload")

print("Network Sniffer Started...")
print("Ab browser me Google / YouTube kholo...")
print("Rokne ke liye CTRL + C dabao\n")

sniff(prn=process_packet, store=False, count=20)

print(f"\nTotal Packets Captured: {packet_count}")
print("Sniffer Finished!")

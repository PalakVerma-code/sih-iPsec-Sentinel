import os
import random
from scapy.all import IP, IPv6, UDP, Raw, wrpcap

def generate_sih_testbed(filename="sih_master_dataset.pcap"):
    packets = []
    
    # 1. IKEv2 Negotiation (Main Mode / Aggressive Mode Scenarios)
    ikev2_init = IP(src="192.168.1.10", dst="192.168.1.1")/UDP(sport=500, dport=500)/Raw(
        load=b'\x00'*8 + b'\x00'*8 + b'\x21\x20\x22\x08' + b'\x00'*8 + b'\x00\x00\x00\x90' + 
        b'\x22\x00\x00\x30' + b'AES-256-GCM-DH19-SHA384-PFS-ENABLED'
    )
    packets.append(ikev2_init)

    # 2. IPv6 ESP Tunnel Mode Traffic
    for _ in range(30):
        esp_v6 = IPv6(src="2001:db8::1", dst="2001:db8::2", nh=50)/Raw(load=b'\x00'*random.choice([1200, 1400, 1380])) # Video
        packets.append(esp_v6)

    # 3. IPv4 ESP Transport Mode Traffic (VoIP Small Bursts)
    for _ in range(40):
        esp_voip = IP(src="10.0.0.5", dst="10.0.0.1", proto=50)/Raw(load=b'\x00'*random.choice([120, 160, 180])) # VoIP
        packets.append(esp_voip)

    # 4. AH (Authentication Header) Protocol 51 Packet
    ah_packet = IP(src="10.0.0.5", dst="10.0.0.1", proto=51)/Raw(load=b'\x00'*64)
    packets.append(ah_packet)

    wrpcap(filename, packets)
    print(f"[+] Multi-Profile SIH Testbed PCAP generated: {filename}")

if __name__ == "__main__":
    generate_sih_testbed()
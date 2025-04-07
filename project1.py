from scapy.all import sniff, Ether, IP

def packet_callback(packet):
    """Process each captured packet"""
    if Ether in packet:  # Check if it's an Ethernet frame
        dest_mac = packet[Ether].dst
        src_mac = packet[Ether].src
        eth_proto = hex(packet[Ether].type)  # EtherType in hex
        
        print("\nEthernet Frame:")
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
        if IP in packet:
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            print(f"Source IP:{src_ip},Dectination IP : {dest_ip}")
def main():
    print("🔍 Sniffing network packets... (Press Ctrl+C to stop)")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()

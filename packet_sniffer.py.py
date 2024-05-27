from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

def sniff_packets(interface):
    sniff(iface=interface, store=False, prn=process_packet)

if _name_ == "_main_":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3.11 packet_sniffer.py -i <interface>")
    else:
        interface = sys.argv[2]
        sniff_packets(interface)

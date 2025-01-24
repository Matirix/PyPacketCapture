# Parse Ethernet header
def format_mac(hex_data):
    return ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))


def format_hex_to_decimal(hex_data):
    return '.'.join(map(str, (int(hex_data[i:i+2], 16) for i in range(0, 8, 2))))


def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    # TODO Add the stuff here - FOR Ethernet, ARP, IPV4, TCP, UDP, & ICMP
    if ether_type == "0806":  # ARP in Hex
        parse_arp_header(payload)
    elif ether_type == "0800":  # IPv4
        # Then do if statements for ICMP, TCP, UDP headers
        pass
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)

    print(f" ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {int(hex_data[4:8], 16)}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {int(hex_data[8:10], 16)}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {int(hex_data[10:12], 16)}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {int(hex_data[12:16], 16)}")
    print(f"  {'Sender MAC:':<25} {hex_data[16:28]:<20} | {format_mac(hex_data[16:28])}")
    print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {format_hex_to_decimal(hex_data[28:36])}")
    print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {format_mac(hex_data[36:48])}")
    print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {format_hex_to_decimal(hex_data[48:56])}")


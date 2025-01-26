# Parse Ethernet header
def format_mac(hex_data):
    return ':'.join(hex_data[i:i + 2] for i in range(0, 12, 2))


def format_hex_to_decimal(hex_data):
    return '.'.join(str(int(hex_data[i:i + 2], 16)) for i in range(0, len(hex_data), 2))


def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i + 2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i + 2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]
    print("RAW HEX_DATA\n", hex_data)

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP in Hex
        parse_arp_header(payload)
    elif ether_type == "0800":  # IPv4
        parse_ipv4_header(payload)
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


def parse_ipv4_header(hex_data):
    total_length = hex_data[4:8]
    flags_and_fragment_offset = hex_data[12:16]
    flags_and_fragment_offset_int = int(flags_and_fragment_offset, 16)

    # Convert the flags_and_fragment_offset to binary and format it
    flags_in_bin = bin(flags_and_fragment_offset_int)[2:].zfill(16)  # Extra Padding

    reserved = int(flags_in_bin[0])
    df = int(flags_in_bin[1])
    mf = int(flags_in_bin[2])
    frag_offset = int(flags_in_bin[2:], 2)

    src_ip = hex_data[24:32]
    dest_ip = hex_data[32:40]
    protocol = hex_data[18:20]
    payload = hex_data[40:]

    print(f"IPv4 Header")
    print(hex_data)
    print(f"  {'Version:':<25} {hex_data[:1]:<20} | {int(hex_data[:1], 16)}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {int(hex_data[1:2], 16) * 4} bytes")  # A word is 4 bytes.
    print(f"  {'Total Length:':<25} {total_length:<20} | {int(total_length, 16)}")
    print(f"  {'Flags & Frag Offset':<25} {flags_and_fragment_offset:<20} | {bin(int(flags_and_fragment_offset, 16))}")
    print(f"  {'--Reserved:':<25} {reserved:<20}")
    print(f"  {'--DF (Do not Fragment):':<25} {df:<20} ")
    print(f"  {'--MF (More Fragments):':<25} {mf:<20}")
    print(f"  {'--Fragment Offset:':<25} {frag_offset:<20} | {frag_offset}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {int(hex_data[18:20], 16)}")
    print(f"  {'Source IP:':<25} {src_ip:<20} | {format_hex_to_decimal(src_ip)}")
    print(f"  {'Destination IP:':<25} {dest_ip:<20} | {format_hex_to_decimal(dest_ip)}")

    if protocol == '06':
        parse_tcp_header(payload)
    elif protocol == '11':
        parse_udp_header(payload)
    elif protocol == '01':
        parse_icmp_header(payload)
    else:
        print("Protocols accepted: ICMP, UDP and TCP")


def parse_tcp_header(hex_data):
    flags = hex_data[24:28]
    flags_in_binary = bin(int(flags, 16))[9:]
    reserved = bin(int(hex_data[24:25], 16))

    print(f" TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {int(hex_data[:4], 16)}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {int(hex_data[4:8], 16)}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {int(hex_data[8:16], 16)}")
    print(f"  {'Acknowledgement Number:':<25} {hex_data[16:24]:<20} | {int(hex_data[16:24], 16)}")
    print(f"  {'Data Offset:':<25} {hex_data[24:25]:<20} | {int(hex_data[24:25], 16) * 4} bytes")
    print(f"  {'Reserved:':<25} {"0b" + reserved[3:4]:<20} | {int(reserved,2 )}")
    print(f"  {'Flags:':<25} {'0b' + flags_in_binary:<20} | {int(flags_in_binary,2)}")
    print(f"  {'--NS:':<25} {flags_in_binary[0]:<20}")
    print(f"  {'--CWR:':<25} {flags_in_binary[1]:<20}")
    print(f"  {'--ECE:':<25} {flags_in_binary[2]:<20} ")
    print(f"  {'--URG:':<25} {flags_in_binary[3]:<20} ")
    print(f"  {'--ACK:':<25} {flags_in_binary[4]:<20}")
    print(f"  {'--PSH:':<25} {flags_in_binary[5]:<20}")
    print(f"  {'--RST:':<25} {flags_in_binary[6]:<20}")
    print(f"  {'--SYN:':<25} {flags_in_binary[7]:<20}")
    print(f"  {'--FIN:':<25} {flags_in_binary[8]:<20}")


    print(f"  {'Window Size:':<25} {hex_data[28:32]:<20} | {int(hex_data[28:32], 16)}")
    print(f"  {'Checksum:':<25} {hex_data[32:36]:<20} | {int(hex_data[32:36], 16)}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[36:40]:<20} | {int(hex_data[36:40], 16)}")
    print(f"  {'Payload (Hex):':<25} {hex_data[40:]:<20}")


def parse_udp_header(hex_data):
    src_p = hex_data[0:4]
    dest_p = hex_data[4:8]
    length = hex_data[8:12]
    checksum = hex_data[12:16]
    payload = hex_data[16:]
    print(f"UDP Headers")
    print(f"  {'Source Port:':<25} {src_p:<20} | {int(src_p, 16)}")
    print(f"  {'Destination Port:':<25} {dest_p:<20} | {int(dest_p, 16)}")
    print(f"  {'Length:':<25} {length:<20} | {int(length, 16)}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
    print(f"  {'Payload:':<25} {payload:<20}")


def parse_icmp_header(hex_data):
    p_type = hex_data[0:2]
    code = hex_data[2:4]
    checksum = hex_data[4:8]
    payload = hex_data[8:]
    print(f"ICMP Header")
    print(f"  {'Type:':<25} {p_type:<20} | {int(p_type, 16)}")
    print(f"  {'Code:':<25} {code:<20} | {int(code, 16)}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
    print(f"  {'Payload:':<25} {payload:<20}")

import socket
import struct
import textwrap

def get_mac_addr(mac_raw):
    """Convert a MAC address bytes into a readable string"""
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

def get_ip(addr):
    """Convert IPv4 bytes to dotted decimal string"""
    return '.'.join(map(str, addr))

def format_multi_line(prefix, string, size=80):
    """Format multi-line string or bytes with prefix indentation"""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ethernet_head(raw_data):
    """Parse Ethernet frame"""
    dest, src, proto = struct.unpack('!6s6sH', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(proto)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def ipv4_head(raw_data):
    """Parse IPv4 packet"""
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', raw_data[:20])
    src_ip = get_ip(src)
    target_ip = get_ip(target)
    data = raw_data[header_length:]
    return version_header_length, version, header_length, ttl, proto, src_ip, target_ip, data

def tcp_head(raw_data):
    """Parse TCP segment"""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!HHLLH', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1,
    }
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flags, data

def udp_head(raw_data):
    """Parse UDP segment"""
    src_port, dest_port, length = struct.unpack('!HH2xH', raw_data[:8])
    data = raw_data[8:]
    return src_port, dest_port, length, data

def icmp_head(raw_data):
    """Parse ICMP packet"""
    packet_type, code, checksum = struct.unpack('!BBH', raw_data[:4])
    data = raw_data[4:]
    return packet_type, code, checksum, data

def parse_http(data_bytes):
    """Try to decode HTTP data"""
    try:
        http_data = data_bytes.decode('utf-8')
        return http_data
    except UnicodeDecodeError:
        return data_bytes

def main():
    # Create raw socket and bind to all interfaces
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Error: You need to run this program as root/administrator.")
        return
    except Exception as e:
        print(f"Socket could not be created: {e}")
        return

    print("Starting packet sniffer... Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = s.recvfrom(65535)
            dest_mac, src_mac, proto, data = ethernet_head(raw_data)

            print(f"\nEthernet Frame: Dest: {dest_mac}, Src: {src_mac}, Protocol: {proto}")

            # IPv4
            if proto == 8:
                ipv4 = ipv4_head(data)
                version, header_len, ttl, proto_num, src_ip, target_ip, ip_data = ipv4[1], ipv4[2], ipv4[3], ipv4[4], ipv4[5], ipv4[6], ipv4[7]

                print(f"\tIPv4 Packet: Version: {version}, Header Length: {header_len}, TTL: {ttl}")
                print(f"\tProtocol: {proto_num}, Source: {src_ip}, Target: {target_ip}")

                # TCP
                if proto_num == 6:
                    src_port, dest_port, seq, ack, flags, tcp_data = tcp_head(ip_data)
                    print(f"\tTCP Segment: Src Port: {src_port}, Dest Port: {dest_port}")
                    print(f"\tSequence: {seq}, Acknowledgment: {ack}")
                    print("\tFlags:")
                    print(f"\t\tURG: {flags['URG']}, ACK: {flags['ACK']}, PSH: {flags['PSH']}")
                    print(f"\t\tRST: {flags['RST']}, SYN: {flags['SYN']}, FIN: {flags['FIN']}")

                    if tcp_data:
                        # Check if HTTP traffic (port 80)
                        if src_port == 80 or dest_port == 80:
                            print("\tHTTP Data:")
                            http_text = parse_http(tcp_data)
                            if isinstance(http_text, str):
                                for line in http_text.split('\n'):
                                    print("\t\t" + line)
                            else:
                                print(format_multi_line('\t\t', tcp_data))
                        else:
                            print("\tTCP Data:")
                            print(format_multi_line('\t\t', tcp_data))

                # ICMP
                elif proto_num == 1:
                    icmp_type, code, checksum, icmp_data = icmp_head(ip_data)
                    print(f"\tICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                    print("\tICMP Data:")
                    print(format_multi_line('\t\t', icmp_data))

                # UDP
                elif proto_num == 17:
                    src_port, dest_port, length, udp_data = udp_head(ip_data)
                    print(f"\tUDP Segment: Src Port: {src_port}, Dest Port: {dest_port}, Length: {length}")

                else:
                    print("\tOther IPv4 Data:")
                    print(format_multi_line('\t\t', ip_data))

            else:
                print("Non-IPv4 Ethernet Data:")
                print(format_multi_line('\t', data))

    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

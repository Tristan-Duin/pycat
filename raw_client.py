import socket
import struct
import sys
import random
import select

PROTO_TCP = 6
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def make_ip(src, dst, payload_len):
    pkt_id = random.randint(0, 65535)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + payload_len, pkt_id, 0, 64, PROTO_TCP, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + payload_len, pkt_id, 0, 64, PROTO_TCP, checksum(hdr), socket.inet_aton(src), socket.inet_aton(dst))

def make_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, data=b''):
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 5840, 0, 0)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, PROTO_TCP, len(hdr) + len(data))
    chk = checksum(pseudo + hdr + data)
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 5840, chk, 0) + data

def send_pkt(sock, src_ip, dst_ip, sport, dport, seq, ack, flags, data=b''):
    tcp = make_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, data)
    sock.sendto(make_ip(src_ip, dst_ip, len(tcp)) + tcp, (dst_ip, 0))

def parse_pkt(pkt):
    src_ip = socket.inet_ntoa(struct.unpack('!BBHHHBBH4s4s', pkt[:20])[8])
    sport, dport, seq, ack, _, flags, _, _, _ = struct.unpack('!HHIIBBHHH', pkt[20:40])
    return src_ip, sport, dport, seq, ack, flags, pkt[40:]

def get_local_ip(dst):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 80))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

def run_client(server_ip, server_port):
    local_ip = get_local_ip(server_ip)  # correct outbound IP for this destination
    local_port = random.randint(10000, 60000)
    seq = random.randint(0, 2**32 - 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.settimeout(5)

    print(f"[*] SYN -> {server_ip}:{server_port}  (from {local_ip}:{local_port})")
    send_pkt(sock, local_ip, server_ip, local_port, server_port, seq, 0, SYN)
    seq += 1

    # Wait for SYN-ACK - filter by ports only, capture actual server IP
    server_seq = None
    actual_server_ip = None
    while True:
        pkt, _ = sock.recvfrom(65535)
        src_ip, sport, dport, seq_in, ack_in, flags, _ = parse_pkt(pkt)
        if sport == server_port and dport == local_port:
            if flags & SYN and flags & ACK and ack_in == seq:
                server_seq = seq_in
                actual_server_ip = src_ip
                print(f"[*] SYN-ACK <- {src_ip}:{server_port}")
                break

    # ACK - complete handshake
    send_pkt(sock, local_ip, server_ip, local_port, server_port, seq, server_seq + 1, ACK)
    print(f"[*] ACK -> {actual_server_ip}:{server_port}  -- connected")
    print(f"[*] Type messages and press Enter. Ctrl+C to quit.\n")

    sock.settimeout(0.05)

    try:
        while True:
            # Check for incoming packets
            try:
                pkt, _ = sock.recvfrom(65535)
                src_ip, sport, dport, seq_in, ack_in, flags, data = parse_pkt(pkt)
                if src_ip == actual_server_ip and sport == server_port and dport == local_port:
                    if flags & FIN:
                        print("\n[*] Server closed connection")
                        break
            except socket.timeout:
                pass

            # Check stdin
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if r:
                line = sys.stdin.readline()
                if not line:
                    break
                data = line.encode()
                send_pkt(sock, local_ip, server_ip, local_port, server_port, seq, server_seq + 1, PSH | ACK, data)
                seq += len(data)

    except KeyboardInterrupt:
        pass

    send_pkt(sock, local_ip, server_ip, local_port, server_port, seq, server_seq + 1, FIN | ACK)
    print("[*] FIN sent, bye")
    sock.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python raw_client.py <host> [port]")
        sys.exit(1)
    run_client(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 9999)

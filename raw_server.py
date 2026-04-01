import socket
import struct
import sys
import random

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
    return struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 20 + payload_len, pkt_id, 0, 64, PROTO_TCP, checksum(hdr), socket.inet_aton(src), socket.inet_aton(dst))

def make_tcp(s_ip, d_ip, s_port, d_port, seq, ack, flags, data=b''):
    hdr = struct.pack('!HHIIBBHHH', s_port, d_port, seq, ack, 0x50, flags, 5840, 0, 0)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(s_ip), socket.inet_aton(d_ip),
        0, PROTO_TCP, len(hdr) + len(data))
    chk = checksum(pseudo + hdr + data)
    return struct.pack('!HHIIBBHHH', s_port, d_port, seq, ack, 0x50, flags, 5840, chk, 0) + data

def send_pkt(sock, s_ip, d_ip, s_port, d_port, seq, ack, flags, data=b''):
    tcp = make_tcp(s_ip, d_ip, s_port, d_port, seq, ack, flags, data)
    sock.sendto(make_ip(s_ip, d_ip, len(tcp)) + tcp, (d_ip, 0))

def parse_pkt(pkt):
    s_ip = socket.inet_ntoa(struct.unpack('!BBHHHBBH4s4s', pkt[:20])[8])
    s_port, d_port, seq, ack, _, flags, _, _, _ = struct.unpack('!HHIIBBHHH', pkt[20:40])
    return s_ip, s_port, d_port, seq, ack, flags, pkt[40:]

def get_local_ip(dst):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 80))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

def run_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    seq = random.randint(0, 2**32 - 1)
    peer_ip = peer_port = peer_seq = None
    local_ip = None
    connected = False

    print(f"[*] Listening on port {port}")

    try:
        while True:
            pkt, _ = sock.recvfrom(65535)
            s_ip, s_port, d_port, seq_in, ack_in, flags, data = parse_pkt(pkt)

            if d_port != port:
                continue

            # SYN - start handshake
            if flags & SYN and not flags & ACK and not connected:
                peer_ip, peer_port, peer_seq = s_ip, s_port, seq_in
                local_ip = get_local_ip(peer_ip)  # pick correct outbound IP
                print(f"[*] SYN  <- {s_ip}:{s_port}  (local={local_ip})")
                send_pkt(sock, local_ip, peer_ip, port, peer_port, seq, peer_seq + 1, SYN | ACK)
                print(f"[*] SYN-ACK -> {s_ip}:{s_port}")
                seq += 1

            # ACK - handshake complete
            elif flags == ACK and not connected and s_ip == peer_ip:
                print(f"[*] ACK  <- {s_ip}:{s_port}  -- connection established")
                connected = True
                peer_seq = seq_in

            # Data or FIN
            elif connected and s_ip == peer_ip:
                if flags & FIN:
                    send_pkt(sock, local_ip, peer_ip, port, peer_port, seq, seq_in + 1, FIN | ACK)
                    print("\n[*] FIN  <- peer, connection closed")
                    break
                if data:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                    send_pkt(sock, local_ip, peer_ip, port, peer_port, seq, seq_in + len(data), ACK)

    except KeyboardInterrupt:
        print("\n[*] Interrupted")
    finally:
        sock.close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    run_server(port)

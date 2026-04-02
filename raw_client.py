import socket
import struct
import sys
import random
import select
from typing import Optional

# IP protocol number for TCP
PROTO_TCP: int = 6

# TCP flag bitmasks
FIN: int = 0x01
SYN: int = 0x02
RST: int = 0x04
PSH: int = 0x08
ACK: int = 0x10


def checksum(data: bytes) -> int:
    """Compute the Internet Checksum (RFC 1071).

    Used for both IP and TCP header checksums. Works by summing all 16-bit
    words, folding carries back in, and returning the one's complement.
    """
    # Pad to an even length so we can unpack as 16-bit words
    if len(data) % 2:
        data += b'\x00'

    # Unpack as big-endian unsigned 16-bit integers and sum them
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))

    # Fold any carry bits back into the lower 16 bits
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)

    # Return the one's complement, masked to 16 bits
    return ~s & 0xffff


def make_ip(src: str, dst: str, payload_len: int) -> bytes:
    """Build a 20-byte IPv4 header with a correct checksum.

    The header is first packed with a zeroed checksum field so the checksum
    can be computed over it, then repacked with the real checksum.
    """
    pkt_id = random.randint(0, 65535)

    # Pack the IPv4 header with checksum = 0 for initial computation.
    #   '!BBHHHBBH4s4s' layout                        (20 bytes total):
    #   B  - Version (4) + IHL (5) combined as 0x45   (1 byte)
    #   B  - Type of Service / DSCP                   (1 byte)
    #   H  - Total Length (IP header + payload)       (2 bytes)
    #   H  - Identification (random per-packet ID)    (2 bytes)
    #   H  - Flags + Fragment Offset (0 = don't frag) (2 bytes)
    #   B  - TTL (64 hops)                            (1 byte)
    #   B  - Protocol (6 = TCP)                       (1 byte)
    #   H  - Header Checksum (0 placeholder here)     (2 bytes)
    #   4s - Source IP address      (4 bytes, packed)
    #   4s - Destination IP address (4 bytes, packed)
    hdr = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,                       # IPv4, 5-word (20-byte) header
        0,                          # TOS
        20 + payload_len,           # total packet length
        pkt_id,                     # identification
        0,                          # flags + fragment offset
        64,                         # TTL
        PROTO_TCP,                  # upper-layer protocol
        0,                          # checksum placeholder
        socket.inet_aton(src),      # source IP
        socket.inet_aton(dst),      # destination IP
    )

    # Repack with the computed checksum replacing the zero placeholder
    return struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, 20 + payload_len, pkt_id, 0, 64,
        PROTO_TCP, checksum(hdr),
        socket.inet_aton(src), socket.inet_aton(dst),
    )


def make_tcp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    data: bytes = b'',
) -> bytes:
    """Build a TCP segment (header + data) with a correct checksum.

    The checksum is computed over a pseudo-header (required by the TCP spec)
    concatenated with the TCP header and payload.
    """
    #   TCP header – '!HHIIBBHHH' layout              (20 bytes, no options):
    #   H - Source port                               (2 bytes)
    #   H - Destination port                          (2 bytes)
    #   I - Sequence number                           (4 bytes)
    #   I - Acknowledgment number                     (4 bytes)
    #   B - Data offset (0x50 = 5 words / 20 bytes)   (1 byte)
    #   B - TCP flags (SYN, ACK, FIN, PSH, etc.)      (1 byte)
    #   H - Window size (5840 bytes)                  (2 bytes)
    #   H - Checksum (0 placeholder)                  (2 bytes)
    #   H - Urgent pointer                            (2 bytes)
    hdr = struct.pack(
        '!HHIIBBHHH',
        sport, dport, seq, ack,
        0x50,       # data offset: 5 32-bit words (20 bytes), no options
        flags,      # TCP flags
        5840,       # window size
        0,          # checksum placeholder
        0,          # urgent pointer
    )

    #   TCP pseudo-header used for checksum calculation – '!4s4sBBH':
    #   4s - Source IP address       (4 bytes)
    #   4s - Destination IP address  (4 bytes)
    #   B  - Reserved / zero         (1 byte)
    #   B  - Protocol (6 = TCP)      (1 byte)
    #   H  - TCP segment length      (2 bytes)  (header + data)
    pseudo = struct.pack(
        '!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,                          # reserved
        PROTO_TCP,
        len(hdr) + len(data),       # total TCP segment length
    )

    chk = checksum(pseudo + hdr + data)

    # Repack with the real checksum
    return struct.pack(
        '!HHIIBBHHH',
        sport, dport, seq, ack,
        0x50, flags, 5840, chk, 0,
    ) + data


def send_pkt(
    sock: socket.socket,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    data: bytes = b'',
) -> None:
    """Construct and send a full IP + TCP packet on the raw socket."""
    tcp = make_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, data)
    sock.sendto(make_ip(src_ip, dst_ip, len(tcp)) + tcp, (dst_ip, 0))


def parse_pkt(pkt: bytes) -> tuple[str, int, int, int, int, int, bytes]:
    """Extract key fields from a raw IP + TCP packet.

    Returns (src_ip, sport, dport, seq, ack, flags, payload).
    """
    # Pull the source IP from the IPv4 header (field index 8 = src addr)
    # '!BBHHHBBH4s4s' mirrors the IP header layout from make_ip()
    src_ip = socket.inet_ntoa(
        struct.unpack('!BBHHHBBH4s4s', pkt[:20])[8]
    )

    # Unpack the TCP header fields – same '!HHIIBBHHH' layout as make_tcp()
    sport, dport, seq, ack, _, flags, _, _, _ = struct.unpack(
        '!HHIIBBHHH', pkt[20:40]
    )

    # Everything past byte 40 is TCP payload (assumes no IP/TCP options)
    return src_ip, sport, dport, seq, ack, flags, pkt[40:]


def get_local_ip(dst: str) -> str:
    """Determine the local IP address used to reach *dst*.

    Opens a throwaway UDP socket and connects to the destination so the OS
    selects the correct outbound interface, then returns that interface's IP.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 80))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


def run_client(server_ip: str, server_port: int) -> None:
    """Connect to a raw-socket server and relay stdin over TCP."""
    local_ip = get_local_ip(server_ip)
    local_port = random.randint(10000, 60000)
    seq = random.randint(0, 2**32 - 1)

    # Open a raw TCP socket; IP_HDRINCL tells the kernel we supply our own IP header
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.settimeout(5)

    # --- Three-way handshake: SYN → SYN-ACK → ACK ---

    # Step 1: send SYN
    print(f"[*] SYN -> {server_ip}:{server_port}  (from {local_ip}:{local_port})")
    send_pkt(sock, local_ip, server_ip, local_port, server_port, seq, 0, SYN)
    seq += 1  # SYN consumes one sequence number

    # Step 2: wait for SYN-ACK
    server_seq: Optional[int] = None
    actual_server_ip: Optional[str] = None
    while True:
        pkt, _ = sock.recvfrom(65535)
        src_ip, sport, dport, seq_in, ack_in, flags, _ = parse_pkt(pkt)
        if sport == server_port and dport == local_port:
            if flags & SYN and flags & ACK and ack_in == seq:
                server_seq = seq_in
                actual_server_ip = src_ip
                print(f"[*] SYN-ACK <- {src_ip}:{server_port}")
                break

    # Step 3: send ACK to finish the handshake
    send_pkt(sock, local_ip, server_ip, local_port, server_port, seq, server_seq + 1, ACK)
    print(f"[*] ACK -> {actual_server_ip}:{server_port}  -- connected")
    print(f"[*] Type messages and press Enter. Ctrl+C to quit.\n")

    # Switch to a short timeout so we can interleave recv() and stdin reads
    sock.settimeout(0.05)

    try:
        while True:
            # Poll for incoming packets from the server
            try:
                pkt, _ = sock.recvfrom(65535)
                src_ip, sport, dport, seq_in, ack_in, flags, data = parse_pkt(pkt)
                if src_ip == actual_server_ip and sport == server_port and dport == local_port:
                    if flags & FIN:
                        print("\n[*] Server closed connection")
                        break
            except socket.timeout:
                pass

            # Poll stdin for user input
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if r:
                line = sys.stdin.readline()
                if not line:
                    break
                data = line.encode()
                send_pkt(
                    sock, local_ip, server_ip, local_port, server_port,
                    seq, server_seq + 1, PSH | ACK, data,
                )
                seq += len(data)  # advance seq by bytes sent

    except KeyboardInterrupt:
        pass

    # Graceful close: send FIN-ACK
    send_pkt(sock, local_ip, server_ip, local_port, server_port, seq, server_seq + 1, FIN | ACK)
    print("[*] FIN sent, bye")
    sock.close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python raw_client.py <host> [port]")
        sys.exit(1)
    run_client(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 9999)

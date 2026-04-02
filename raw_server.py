import socket
import struct
import sys
import random
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
    #   4s - Source IP address                        (4 bytes, packed)
    #   4s - Destination IP address                   (4 bytes, packed)
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
    src_port: int,
    dst_port: int,
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
        src_port, dst_port, seq, ack,
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
        src_port, dst_port, seq, ack,
        0x50, flags, 5840, chk, 0,
    ) + data


def send_pkt(
    sock: socket.socket,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    data: bytes = b'',
) -> None:
    """Construct and send a full IP + TCP packet on the raw socket."""
    tcp = make_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, data)
    sock.sendto(make_ip(src_ip, dst_ip, len(tcp)) + tcp, (dst_ip, 0))


def parse_pkt(pkt: bytes) -> tuple[str, int, int, int, int, int, bytes]:
    """Extract key fields from a raw IP + TCP packet.

    Returns (src_ip, src_port, dst_port, seq, ack, flags, payload).
    """
    # Pull the source IP from the IPv4 header (field index 8 = src addr)
    # '!BBHHHBBH4s4s' mirrors the IP header layout from make_ip()
    src_ip = socket.inet_ntoa(
        struct.unpack('!BBHHHBBH4s4s', pkt[:20])[8]
    )

    # Unpack the TCP header fields – same '!HHIIBBHHH' layout as make_tcp()
    src_port, dst_port, seq, ack, _, flags, _, _, _ = struct.unpack(
        '!HHIIBBHHH', pkt[20:40]
    )

    # Everything past byte 40 is TCP payload (assumes no IP/TCP options)
    return src_ip, src_port, dst_port, seq, ack, flags, pkt[40:]


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


def run_server(port: int) -> None:
    """Listen on *port* for one TCP connection and print received data."""
    # Open a raw TCP socket; IP_HDRINCL tells the kernel we supply our own IP header
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    seq = random.randint(0, 2**32 - 1)
    peer_ip: Optional[str] = None
    peer_port: Optional[int] = None
    peer_seq: Optional[int] = None
    local_ip: Optional[str] = None
    connected: bool = False

    print(f"[*] Listening on port {port}")

    try:
        while True:
            pkt = sock.recv(65535)
            src_ip, src_port, dst_port, seq_in, ack_in, flags, data = parse_pkt(pkt)

            # Ignore packets not addressed to our port
            if dst_port != port:
                continue

            # --- Three-way handshake (server side) ---

            # Step 1: incoming SYN – reply with SYN-ACK
            if flags & SYN and not flags & ACK and not connected:
                peer_ip, peer_port, peer_seq = src_ip, src_port, seq_in
                local_ip = get_local_ip(peer_ip)
                print(f"[*] SYN  <- {src_ip}:{src_port}  (local={local_ip})")
                send_pkt(sock, local_ip, peer_ip, port, peer_port, seq, peer_seq + 1, SYN | ACK)
                print(f"[*] SYN-ACK -> {src_ip}:{src_port}")
                seq += 1  # SYN consumes one sequence number

            # Step 2: incoming ACK – handshake complete
            elif flags == ACK and not connected and src_ip == peer_ip:
                print(f"[*] ACK  <- {src_ip}:{src_port}  -- connection established")
                connected = True
                peer_seq = seq_in

            # --- Data / teardown ---
            elif connected and src_ip == peer_ip:
                if flags & FIN:
                    # Peer wants to close – acknowledge and exit
                    send_pkt(sock, local_ip, peer_ip, port, peer_port, seq, seq_in + 1, FIN | ACK)
                    print("\n[*] FIN  <- peer, connection closed")
                    break
                if data:
                    # Print received payload and ACK the data
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

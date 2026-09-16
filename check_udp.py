#!/usr/bin/env python3
"""Verify the socks inbound's UDP relay and the address it advertises.

Connects to the SOCKS5 server, does a UDP ASSOCIATE, prints the BND.ADDR it
answers with (this is what settings.ip / the default controls) and then sends a
real DNS query over UDP through the proxy.

    python3 /tmp/socks5_udp_check.py <socks-host> <socks-port>
"""
import socket
import struct
import sys


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SystemExit("connection closed early")
        buf += chunk
    return buf


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 54321

    tcp = socket.create_connection((host, port), timeout=10)
    tcp.sendall(b"\x05\x01\x00")                       # SOCKS5, no-auth
    if recv_exact(tcp, 2) != b"\x05\x00":
        raise SystemExit("socks: auth negotiation failed")

    # UDP ASSOCIATE, DST 0.0.0.0:0 (we do not restrict the client source)
    tcp.sendall(b"\x05\x03\x00\x01" + b"\x00" * 4 + b"\x00\x00")
    reply = recv_exact(tcp, 4)
    if reply[1] != 0x00:
        raise SystemExit("socks: UDP ASSOCIATE rejected (rep=%d)" % reply[1])
    atyp = reply[3]
    if atyp == 0x01:
        bnd_addr = socket.inet_ntoa(recv_exact(tcp, 4))
    elif atyp == 0x04:
        bnd_addr = socket.inet_ntop(socket.AF_INET6, recv_exact(tcp, 16))
    else:
        raise SystemExit("socks: unexpected address type %d" % atyp)
    bnd_port = struct.unpack(">H", recv_exact(tcp, 2))[0]
    print("UDP ASSOCIATE OK, advertised relay address: %s:%d" % (bnd_addr, bnd_port))

    # Build a DNS query for example.com A record.
    qname = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\x00"
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)

    target = socket.inet_aton("8.8.8.8") + struct.pack(">H", 53)   # 8.8.8.8:53
    packet = b"\x00\x00\x00" + b"\x01" + target + dns               # RSV(2) FRAG(1) ATYP(1)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(12)
    udp.sendto(packet, (bnd_addr, bnd_port))
    data, _src = udp.recvfrom(4096)
    if len(data) < 10:
        raise SystemExit("udp: short reply: %r" % data)
    # The reply carries a SOCKS5 UDP header first: RSV(2) FRAG(1) ATYP(1) ADDR PORT(2..18)
    head = 4 + {1: 4, 4: 16}.get(data[3], 0) + 2
    dns_reply = data[head:]
    if len(dns_reply) < 12:
        raise SystemExit("udp: no DNS payload: %r" % data)
    answers = struct.unpack(">H", dns_reply[6:8])[0]
    print("DNS over UDP through the proxy OK: %d bytes back, answer count=%d"
          % (len(dns_reply), answers))
    print("=> UDP relay works with the current inbound config")


if __name__ == "__main__":
    main()
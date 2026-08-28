"""Find a phone's wireless-debugging port, from a host on the phone's LAN.

WHY THIS EXISTS. Android randomises the adb port every time wireless debugging
restarts, and it restarts on every reboot and every re-pair. The port therefore
has to be DISCOVERED, not remembered - `provisioning-a-pixel.md` says as much
and then gives a port that was already stale when it was written.

Reading it off a running `ssh -L` is not discovery, it is reading somebody
else's homework: it only works when a tunnel already exists.

Run this ON a host that shares the phone's broadcast domain - the travel router
in front of the Pixels, not the laptop:

    ssh root@<router> "python3 - <phone-ip>" < server/tools/find_adb_port.py

Two methods, in order of cost:

1. An mDNS one-shot query for `_adb-tls-connect._tcp`, which is what adbd
   advertises. It binds an EPHEMERAL port and sets the QU (unicast-response)
   bit, because a router running avahi-daemon already owns 5353 and would
   otherwise take the replies.
2. A threaded TCP connect scan, which nothing about the phone's advertising can
   break.

Measured 2026-08-19 on a GL-MT3000 travel router: mDNS returns NOTHING - the
control query sees no responses at all, so multicast does not reach the
phone through that router - and the scan finds the port in about ten seconds.
The control query is printed either way, because a method that silently finds
nothing looks exactly like a phone that is switched off.
"""
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

TARGET = sys.argv[1] if len(sys.argv) > 1 else None
LOW, HIGH = 30000, 50000


def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def skip_name(buf: bytes, i: int) -> int:
    """Step over a DNS name. Only the LENGTH matters here, never the value."""
    while i < len(buf):
        length = buf[i]
        if length == 0:
            return i + 1
        if length & 0xC0 == 0xC0:  # a compression pointer is always terminal
            return i + 2
        i += 1 + length
    return i


def mdns(services, accept_any: bool = False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))  # ephemeral: avahi keeps 5353
    sock.settimeout(1.0)
    header = struct.pack(">HHHHHH", 0x1234, 0, len(services), 0, 0, 0)
    # QCLASS 0x8001 is IN with the QU bit: answer unicast, to our source port.
    body = b"".join(encode_name(s) + struct.pack(">HH", 12, 0x8001) for s in services)
    sock.sendto(header + body, ("224.0.0.251", 5353))

    ports, heard_anything, malformed = set(), False, 0
    last_error = None
    deadline = time.time() + 4
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(9000)
        except socket.timeout:
            continue
        heard_anything = True
        if not accept_any and TARGET and addr[0] != TARGET:
            continue
        try:
            qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
            i = 12
            for _ in range(qd):
                i = skip_name(data, i) + 4
            for _ in range(an + ns + ar):
                i = skip_name(data, i)
                rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
                i += 10
                if rtype == 33 and rdlen >= 6:  # SRV carries the port
                    ports.add(struct.unpack(">H", data[i + 4:i + 6])[0])
                i += rdlen
        except (struct.error, IndexError) as truncated:
            # COUNTED, NOT SWALLOWED. Anything on this link may answer a
            # multicast query, and a packet this parser cannot walk is
            # ordinary - it is not a reason to stop reading the others. But a
            # run that heard forty packets and could not parse one of them is
            # a different situation from a run that heard nothing, and the
            # whole point of the control query below is that those two must
            # not look alike. So the count is reported rather than dropped.
            #
            # struct.error and IndexError are what a truncated or hostile
            # record raises. A broader catch here would also swallow a bug in
            # skip_name, which should reach a person.
            malformed += 1
            last_error = truncated
    if malformed:
        print(
            f"# mdns: {malformed} packet(s) could not be parsed, last: {last_error!r}",
            file=sys.stderr,
        )
    return ports, heard_anything


def open_port(port: int):
    sock = socket.socket()
    sock.settimeout(0.35)
    try:
        sock.connect((TARGET, port))
        return port
    except Exception:
        return None
    finally:
        sock.close()


# The control FIRST. A method that finds nothing and a network that carries
# nothing look identical from the outside, and only one of them is the phone.
_, heard = mdns(["_services._dns-sd._tcp.local"], accept_any=True)
print(
    "# mdns control: " + ("responses seen" if heard else "NO responses - mdns is unusable here"),
    file=sys.stderr,
)

found, _ = mdns(["_adb-tls-connect._tcp.local", "_adb-tls-pairing._tcp.local"])
if found:
    for port in sorted(found):
        print(f"{port} mdns")
    sys.exit(0)

print("# mdns found nothing; scanning", file=sys.stderr)
hits = [p for p in ThreadPoolExecutor(max_workers=256).map(open_port, range(LOW, HIGH)) if p]
for port in sorted(hits):
    print(f"{port} scan")
if not hits:
    print("NONE")

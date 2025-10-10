#!/usr/bin/env python3
"""
Simple Port Scanner

Author:     Tan Amos (s22)
Institute:  Centre for Cybersecurity
Unit:       CCK3_250714
Trainer:    Samson
Date:       Oct 2025

Features:
- Scan IPv4 hosts and optionally discover live ones first
- Scan TCP/UDP ports (single ports or ranges), with optional multithreading
- Show hostnames (reverse DNS) when available
- Grab quick TCP banners (e.g., HTTP headers)
- Use smarter UDP probes (DNS/NTP/SSDP) and label results: open / closed / open|filtered
- Auto‑tune timeouts based on network round‑trip time (RTT)
- Use sensible service names (with a few overrides)
- Save results to CSV (with timestamps, duration, service, and first‑line banner)
"""
# ============================== 1) Module Setup ===============================

# ---------------------------------- Imports -----------------------------------
# Store annotations as strings (faster imports; avoids forward refs)
from __future__ import annotations

# Standard library
import csv            # CSV output for scan results
import errno          # Cross‑platform error codes (e.g., ECONNREFUSED)
import ipaddress      # IPv4 address/CIDR parsing
import re             # Port list parsing (e.g., "20-80")
import secrets        # Random IDs for DNS queries
import socket         # TCP/UDP networking
import struct         # Pack/unpack protocol bytes (DNS/NTP)
import sys            # Version checks and clean exit
import time           # Timeouts, RTT measurement, elapsed durations
from concurrent.futures import ThreadPoolExecutor  # Simple multithreading
from datetime import datetime, timezone           # Timestamps for logs/CSV
from functools import lru_cache                   # Cache rDNS/service lookups

# Typing
from typing import Sequence                       # Sized/ordered sequences

# ----------------------------- Runtime Requirement ----------------------------
# Exit early on unsupported Python so users get a clear message up front.
if sys.version_info < (3, 10):
    print("[!] Python 3.10+ required.", flush=True)
    raise SystemExit(1)

# --------------------------------- Constants ----------------------------------
# NOTE: constants use ALL_CAPS; time values include a "_S" suffix (seconds).

# Config flags
# After discovery, optionally resolve reverse DNS
DISCOVERY_SHOW_RDNS: bool = False
# Also print UDP non‑open states (not saved to CSV)
UDP_SHOW_NONOPEN: bool = False
UDP_VERBOSITY_PROMPTED: bool = False  # Ask once per run about UDP verbosity
AUTOTUNE_ENABLED: bool = False        # Enable RTT‑based timeout tuning
AUTOTUNE_PROMPTED: bool = False       # Ask once per run about auto‑tune

# Safety caps — prevent accidental huge scans or too many threads
MAX_HOSTS: int = 4096
MAX_WORKERS: int = 100

# Port spec parsing — precompiled pattern (e.g., "80" or "20-25")
PORT_SPEC_TOKEN_RE = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")

# Timeouts (seconds). Short defaults keep scans responsive.
TCP_BANNER_TIMEOUT_S: float = 2.0     # Read timeout when grabbing TCP banners
TCP_CONNECT_TIMEOUT_S: float = 0.5    # Per TCP connect() attempt
UDP_TIMEOUT_S: float = 1.0            # Per UDP probe wait

# RTT auto‑tune — use a few common ports that respond quickly/refuse reliably
RTT_PROBE_PORTS: tuple[int, ...] = (22, 53, 80, 443, 3128, 3389, 8000, 8080)
RTT_PROBE_TIMEOUT_S: float = 1.5      # Timeout per connect() probe
RTT_PROBE_SAMPLES: int = 5            # Number of valid samples to collect

# Discovery — quick reachability via UDP DNS
DNS_DISCOVERY_PORT: int = 53

# HTTP banner ports — places where a HEAD request usually yields headers fast
HTTP_PROBE_PORTS: tuple[int, ...] = (80, 3128, 8000, 8080, 8081, 8888)

# Common TCP ports for liveness checks (open OR refused => host is up)
TCP_LIVENESS_PORTS: tuple[int, ...] = (
    22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3128, 3389, 5900, 8000, 8080
)

# Service name overrides — stable names regardless of /etc/services differences
CUSTOM_SERVICES_TCP: dict[int, str] = {
    21: "ftp",              # File Transfer Protocol
    22: "ssh",              # Secure Shell (remote login)
    23: "telnet",           # Legacy remote shell (unencrypted)
    25: "smtp",             # Simple Mail Transfer Protocol (email)
    53: "domain",           # Domain Name System (DNS)
    80: "http",             # Hypertext Transfer Protocol (web)
    110: "pop3",            # Post Office Protocol (email retrieval)
    135: "msrpc",           # Microsoft Remote Procedure Call (RPC)
    139: "netbios-ssn",     # NetBIOS Session Service (legacy Windows sharing)
    143: "imap",            # Internet Message Access Protocol (email)
    443: "https",           # HTTP Secure (over TLS; encrypted web)
    # Directory Services; SMB over TCP (file/printer sharing)
    445: "microsoft-ds",
    3128: "http-proxy",     # Common web proxy (e.g., Squid default)
    3389: "ms-wbt-server",  # Micosoft Windows Based Terminal (RDP)
    5900: "vnc",            # Virtual Network Computing (remote desktop)
    8000: "http",           # Alternate web port
    8080: "http-alt",       # Alternate HTTP/proxy port
}
CUSTOM_SERVICES_UDP: dict[int, str] = {
    53: "domain",           # DNS (queries/responses)
    123: "ntp",             # Network Time Protocol
    # Simple Service Discovery Protocol (UPnP discovery)
    1900: "ssdp",
}

# UDP probe payloads — tiny, protocol‑appropriate packets
NTP_CLIENT_PACKET = bytes([0x1B]) + b"\x00" * 47  # LI=0, VN=3, Mode=3 (client)
SSDP_MSEARCH_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

# =============================== 2) Parsing ===================================
"""Turn user text into clean lists of integers"""


def parse_port_range(s: str) -> list[int]:
    """Parse a mixed list of ports/ranges into a de-duplicated list of ports.

    Accepts tokens like "80", "20-25" separated by commas and/or spaces.
    - Validates bounds (1..65535) for every token.
    - Supports reversed ranges (e.g., "90-80").
    - Preserves the *first-seen* order while removing duplicates.
    """
    # Split on commas and/or whitespace; drop empty fragments.
    tokens = [t.strip() for t in re.split(r"[\s,]+", s) if t.strip()]
    if not tokens:
        raise ValueError("empty port list")

    seen: set[int] = set()   # Tracks ports we've already added (for de-dup).
    out: list[int] = []      # Maintains the order in which ports first appear.

    for tok in tokens:
        # Validate each token using the precompiled regex from module setup.
        # fullmatch() ensures the whole token matches (no partials like "80x").
        m = PORT_SPEC_TOKEN_RE.fullmatch(tok)
        if not m:
            raise ValueError(
                "Use numbers and ranges like '80' or '20-25', separated by commas/spaces"
            )
        a = int(m.group(1))  # Left side of the dash (or the lone number).
        # No right side => single port.
        b = int(m.group(2)) if m.group(2) else a

        # Normalize reversed ranges (e.g., "90-80" -> 80..90).
        lo, hi = (a, b) if a <= b else (b, a)

        # A single bounds check per token is cheaper than per expanded port.
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
            raise ValueError("Ports must be between 1 and 65535.")

        # Expand the range and append only ports we haven't seen yet.
        for p in range(lo, hi + 1):
            if p not in seen:
                seen.add(p)
                out.append(p)

    return out


def parse_index_list(expr: str, max_n: int) -> list[int]:
    """Parse selections like "1-3,5" (supports "4-1") into 1-based indices.

    Ensures all indices fall within 1..max_n, preserves first-seen order,
    and removes duplicates. Supports the fast path "all" to select every item.
    """
    # Normalize once so we can accept 'ALL', 'All', etc.
    expr = expr.strip().lower()

    # Shortcut: allow quick selection of everything.
    if expr in ("a", "all", "*"):
        return list(range(1, max_n + 1))

    # Split on commas and/or whitespace; drop empties for robust parsing.
    tokens = [t.strip() for t in re.split(r"[\s,]+", expr) if t.strip()]
    if not tokens:
        raise ValueError("empty selection")

    raw: list[int] = []  # May include duplicates; we'll clean up later.
    for tok in tokens:
        # Accept either a single number or a 'start-end' range (any order).
        m = re.fullmatch(r"(\d+)-(\d+)", tok)
        if m:
            a, b = int(m.group(1)), int(m.group(2))

            # Verify both ends are within bounds before expanding.
            if not (1 <= a <= max_n and 1 <= b <= max_n):
                raise ValueError("range out of bounds")

            # Choose direction: step=1 for ascending, -1 for descending ranges.
            step = 1 if a <= b else -1

            # range() excludes the stop value, so add 'step' to include it.
            raw.extend(list(range(a, b + step, step)))
        else:
            # Single number path with a simple bounds check.
            i = int(tok)
            if not (1 <= i <= max_n):
                raise ValueError("index out of bounds")
            raw.append(i)

    # De-duplicate while preserving first-seen order.
    out: list[int] = []
    seen: set[int] = set()
    for i in raw:
        if i not in seen:
            out.append(i)
            seen.add(i)
    return out

# ========================= 3) DNS / Networking Utils ==========================
# Helpers for IPv4 resolution, service labels, and RTT-based timeout logic.
# Kept separate so higher-level scanning code stays small and readable.
# IPv4-only by design. Expensive lookups are cached with @lru_cache.


def resolve_ipv4_target(user_input: str) -> str:
    """Return an IPv4 string for a literal IP or a hostname."""
    # Fast path: accept a dotted-quad directly; reject IPv6 early so the rest
    # of the tool stays IPv4-only.
    try:
        ip = ipaddress.ip_address(user_input)
        if ip.version != 4:
            raise ValueError(
                "IPv6 addresses are not supported by this scanner.")
        return str(ip)
    except ValueError:
        pass  # Not a literal IP; try DNS lookup below.

    try:
        # For hostnames: request IPv4 results only and pick the first usable one.
        # rstrip('.') lets "example.com." still resolve.
        host = user_input.rstrip(".")
        infos = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            # Avoid unusable families.
            flags=getattr(socket, "AI_ADDRCONFIG", 0),
        )
        if not infos:
            raise ValueError("Could not resolve hostname to an IPv4 address.")
        return infos[0][4][0]
    except OSError as e:
        # Normalize OS errors into a simple ValueError for the caller.
        raise ValueError(
            "Could not resolve hostname to an IPv4 address.") from e


@lru_cache(maxsize=8192)
def reverse_dns(ip: str) -> str | None:
    """Best‑effort PTR lookup; returns hostname or None."""
    # gethostbyaddr may be slow/fail; caching keeps repeated calls cheap.
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".")  # Normalize by removing trailing dot.
    except (socket.herror, OSError):
        return None


@lru_cache(maxsize=4096)
def get_service_name(port: int, proto: str) -> str | None:
    """Map (port, proto) → service label, honoring stable overrides first."""
    # Prefer our custom map for consistency across systems; if missing, fall back
    # to the OS service database. Return None when unknown.
    if proto == "tcp" and port in CUSTOM_SERVICES_TCP:
        return CUSTOM_SERVICES_TCP[port]
    if proto == "udp" and port in CUSTOM_SERVICES_UDP:
        return CUSTOM_SERVICES_UDP[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


def estimate_rtt_s(
    ip: str,
    ports: tuple[int, ...] = RTT_PROBE_PORTS,
    per_try: float = RTT_PROBE_TIMEOUT_S,
    samples_needed: int = RTT_PROBE_SAMPLES,
) -> float | None:
    """Estimate RTT (seconds) via quick TCP connects to common ports."""
    # Treat both success and ECONNREFUSED as "reachable" samples.
    refused_codes = {errno.ECONNREFUSED}
    if sys.platform.startswith("win"):
        refused_codes.add(10061)  # WSAECONNREFUSED on Windows.

    samples: list[float] = []
    for port in ports:
        t0 = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(per_try)
                rc = s.connect_ex((ip, port))
        except OSError:
            continue  # Skip this port if the attempt itself fails.

        dt = time.perf_counter() - t0
        if rc == 0 or rc in refused_codes:
            samples.append(dt)
        if len(samples) >= samples_needed:
            break

    if not samples:
        return None
    samples.sort()
    return samples[len(samples) // 2]  # Median for robustness.


def compute_timeouts_from_rtt(rtt_s: float) -> tuple[float, float, float]:
    """Convert RTT guess to (tcp_connect, banner_read, udp_recv) timeouts."""
    # Clamp to sensible ranges so values behave well on very fast/slow links.
    def clamp(x, lo, hi):
        return max(lo, min(hi, x))

    tcp = clamp(10.0 * rtt_s, 0.3, 5.0)   # ~10×RTT
    banner = clamp(18.0 * rtt_s, 1.0, 8.0)  # ~18×RTT
    udp = clamp(10.0 * rtt_s, 0.5, 5.0)   # ~10×RTT
    return round(tcp, 2), round(banner, 2), round(udp, 2)


def autotune_timeouts_for(ip: str) -> None:
    """Measure RTT to this host and update module-level timeouts."""
    # If RTT cannot be inferred (e.g., filtered), keep existing values but print why.
    global TCP_CONNECT_TIMEOUT_S, TCP_BANNER_TIMEOUT_S, UDP_TIMEOUT_S

    rtt = estimate_rtt_s(ip)
    if rtt is None:
        print(
            "[*] RTT auto-tune: unable to infer link latency (filtered/timeouts). Keeping current timeouts.",
            flush=True,
        )
        return

    tcp, banner, udp = compute_timeouts_from_rtt(rtt)
    TCP_CONNECT_TIMEOUT_S, TCP_BANNER_TIMEOUT_S, UDP_TIMEOUT_S = tcp, banner, udp
    print(
        f"[*] RTT auto-tune: RTT≈{int(rtt * 1000)}ms -> TCP={tcp}s, Banner={banner}s, UDP={udp}s",
        flush=True,
    )


def icmp_port_unreachable(exc: BaseException) -> bool:
    """Return True when an exception signals ICMP *Port Unreachable*."""
    # Normalize platform-specific errors so UDP logic can classify "closed"
    # consistently across POSIX and Windows.
    return (
        getattr(exc, "errno", None) == errno.ECONNREFUSED
        or getattr(exc, "winerror", None) == 10054
    )


# =============================== 4) Probes ====================================
"""Protocol‑aware payload builders used by UDP/TCP scanners."""

# Why: many UDP services ignore empty packets. A tiny, valid request
# boosts the chance of getting a reply we can classify (open vs. closed/filtered)
# without external libraries.


def build_dns_query_packet(name: str = "example.com") -> bytes:
    """Build a minimal DNS A query (wire format)."""
    # Trim a trailing dot so both "example.com" and "example.com." work.
    name = name.strip(".")

    # Encode each label using IDNA so Unicode domains are handled safely.
    labels = [lbl.encode("idna") for lbl in name.split(".") if lbl]

    # DNS limits: each label ≤ 63 bytes, full name ≤ 253 bytes.
    # If out of bounds, fall back to a safe default query.
    if any(len(lbl) > 63 for lbl in labels) or sum(len(lbl) + 1 for lbl in labels) + 1 > 253:
        labels = [b"example", b"com"]

    # Build QNAME: <len><label>...<0>  (zero byte terminates the name)
    qname = b"".join(len(lbl).to_bytes(1, "big") +
                     lbl for lbl in labels) + b"\x00"

    # 12‑byte header:
    #  - tid: random transaction ID to match replies
    #  - flags: 0x0100 = standard query, Recursion Desired (RD)
    #  - QDCOUNT=1; ANCOUNT=NSCOUNT=ARCOUNT=0
    tid = secrets.randbits(16)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)

    # Question section: QTYPE=A (IPv4), QCLASS=IN (Internet)
    qtype_qclass = b"\x00\x01\x00\x01"

    return header + qname + qtype_qclass


def udp_probe_payload(port: int) -> bytes | None:
    """Return a tiny UDP probe for a known port, else None."""
    # Service‑specific probes improve accuracy (many UDP daemons ignore empty packets).
    if port == 53:    # DNS resolver
        return build_dns_query_packet("example.com")
    if port == 123:   # NTP time service
        return NTP_CLIENT_PACKET
    if port == 1900:  # SSDP/UPnP discovery
        return SSDP_MSEARCH_REQUEST
    # Unknown port: let the caller send a generic single‑byte probe.
    return None


# ============================= 5) Primitives ==================================
"""Low-level, single-port probes. Called by the range scanners.
- Keep each probe fast, self-contained, and side-effect free.
- Return simple signals so callers can format output and decide next steps.
"""


def probe_tcp_port(
    target_ip: str,
    port: int,
    host_header: str | None = None,
) -> tuple[bool, str | None]:
    """Open one TCP connection and (best-effort) read a short banner."""
    try:
        # One connect attempt with a tight timeout keeps scans responsive.
        with socket.create_connection((target_ip, port), TCP_CONNECT_TIMEOUT_S) as s:
            try:
                if port in HTTP_PROBE_PORTS:
                    # For common HTTP ports, send a tiny HTTP HEAD request.
                    # This almost always yields a quick, descriptive server header.
                    # Prefer the provided hostname (for SNI/virtual hosts),
                    # else try rDNS once (cached), else use the raw IP.
                    host_hdr = (host_header or reverse_dns(
                        target_ip) or target_ip)
                    try:
                        # Normalize to ASCII via IDNA to avoid encoding errors.
                        host_hdr = host_hdr.encode("idna").decode("ascii")
                    except Exception:
                        host_hdr = target_ip

                    # Include :port for non-80 to help name-based vhosts on alt ports.
                    host_line = f"{host_hdr}:{port}" if port != 80 else host_hdr

                    # Minimal request; 'Connection: close' ensures the server closes fast.
                    req = (
                        "HEAD / HTTP/1.1\r\n"
                        f"Host: {host_line}\r\n"
                        "User-Agent: simple-scan/1.0\r\n"
                        "Accept: */*\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii", "ignore")
                    s.sendall(req)
                else:
                    # Non-HTTP: a newline is a harmless nudge; some daemons reply with a banner.
                    s.sendall(b"\r\n")

                # Longer timeout for the read path; services can be slow to reply.
                s.settimeout(TCP_BANNER_TIMEOUT_S)
                # small read to avoid stalling and keep memory tiny
                data = s.recv(1024)
                # latin-1 never fails to decode and preserves bytes 1:1; trim whitespace.
                banner = data.decode(
                    "latin-1", "replace").strip() if data else None

            except socket.timeout:
                # Connection succeeded but no banner within the read window.
                banner = None
            except OSError:
                # Any per-read error => treat as no banner; port still considered open.
                banner = None
            return True, banner
    except OSError:
        # connect() failed (timeout, refused, network error) => not open for TCP.
        return False, None


def first_line_of(text: str | None) -> str:
    """Return the first line of text or an empty string if None/blank."""
    return "" if not text else text.splitlines()[0]


def probe_udp_port(
    target_ip: str,
    port: int,
    payload: bytes | None = None,
    timeout: float | None = None,
) -> tuple[str, str | None]:
    """Probe one UDP port; return (state, optional_text).

    States:
      - 'open'          : a UDP response was received
      - 'closed'        : ICMP Port Unreachable seen (treat as definitely closed)
      - 'open|filtered' : no response — could be dropped by a firewall or a quiet service
    """
    if timeout is None:
        timeout = UDP_TIMEOUT_S  # picks up current (possibly auto-tuned) value

    # Use a smart payload for known protocols; otherwise a single zero byte is a safe default.
    if payload is None:
        payload = udp_probe_payload(port) or b"\x00"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # UDP has no handshake; connect() just sets default remote addr for send/recv.
            s.connect((target_ip, port))
            try:
                s.sendall(payload)
                data = s.recv(1024)  # any bytes back means the port responded
                if not data:
                    return "open", None
                return "open", data.decode("latin-1", "replace").strip()

            except socket.timeout:
                # No reply within the window — ambiguous on UDP.
                return "open|filtered", None
            except ConnectionRefusedError:
                # ICMP Port Unreachable (POSIX) => definitely closed.
                return "closed", None
            except ConnectionResetError as e:
                # Windows may surface ICMP Port Unreachable as WSAECONNRESET (10054).
                if getattr(e, "winerror", None) == 10054:
                    return "closed", None
                return "open|filtered", None
            except OSError as e:
                # Some platforms map ICMP errors to generic OSError; translate if possible.
                if icmp_port_unreachable(e):
                    return "closed", None
                return "open|filtered", None
    except OSError:
        # Could not create/connect the UDP socket (rare) — treat as no visible response.
        return "open|filtered", None


# ============================== 6) Discovery ==================================
"""Find which hosts are up before scanning their ports."""


def is_host_reachable(ip: str, timeout: float | None = None, check_udp: bool = True) -> bool:
    """Fast liveness check via TCP (and optional UDP)."""
    # If caller doesn't set a timeout, use the module default.
    if timeout is None:
        timeout = TCP_CONNECT_TIMEOUT_S

    # Treat a refused TCP connection as "host is up" (service is closed but the stack replied).
    refused_codes = {errno.ECONNREFUSED}
    if sys.platform.startswith("win"):
        refused_codes.add(10061)  # WSAECONNREFUSED on Windows

    # --- TCP heuristic ---
    # Try a few common ports. If any connect() succeeds OR is explicitly refused, the host is reachable.
    for port in TCP_LIVENESS_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                rc = s.connect_ex((ip, port))
                if rc == 0 or rc in refused_codes:
                    return True
        except OSError:
            continue  # ignore per-port errors and try the next port

    # --- UDP heuristic (DNS 53) ---
    # Optional: send a tiny DNS query. Any reply or ICMP "port unreachable" means the host exists.
    if check_udp:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Keep UDP wait short but not zero; bound by both UDP and TCP timeouts.
                s.settimeout(min(UDP_TIMEOUT_S, max(0.1, timeout)))
                s.connect((ip, DNS_DISCOVERY_PORT))
                try:
                    s.sendall(build_dns_query_packet("example.com"))
                    # any payload => host responded => up
                    _ = s.recv(1)
                    return True
                except socket.timeout:
                    pass                    # no UDP reply; can't conclude
                except ConnectionRefusedError:
                    return True             # ICMP port unreachable => host reachable
                except ConnectionResetError as e:
                    if getattr(e, "winerror", None) == 10054:
                        return True         # Windows-specific ICMP unreachable
                except OSError as e:
                    if icmp_port_unreachable(e):
                        return True         # ICMP port unreachable => host reachable
                    # else: fall through (treat as inconclusive)
        except OSError:
            pass  # couldn't create/connect UDP socket; inconclusive

    return False  # none of the quick checks proved reachability


def expand_ipv4_block(block: str) -> list[str]:
    """Expand a single IPv4 or CIDR into a list of host IPs (with size limits)."""
    # strict=False lets users enter either a host (=> /32) or a network like 192.168.1.5/24.
    net = ipaddress.ip_network(block, strict=False)
    if net.version != 4:
        raise ValueError("IPv6 addresses are not supported by this scanner.")
    # Guardrails: avoid overwhelming the machine (and the network).
    if net.num_addresses > MAX_HOSTS + 2:  # +2 for network/broadcast addresses
        raise ValueError(
            f"Network too large ({net.num_addresses}). Try a smaller block.")
    if net.num_addresses == 1:
        return [str(net.network_address)]
    # ipaddress.hosts() skips network/broadcast addresses for IPv4.
    return [str(ip) for ip in net.hosts()]


def discover_live_hosts(block: str) -> list[str]:
    """Probe each host in a block; return a sorted list of IPs that look alive."""
    ips = expand_ipv4_block(block)
    task_count = len(ips)

    # Let the user decide whether to parallelize discovery.
    use_threads, workers = prompt_threads(
        task_count, context="discovery", noun="hosts")
    mode_str = f"with {workers} thread(s)" if use_threads else "without threading"
    print(
        f"\n[*] Starting live-host discovery for {block}: probing {task_count} host(s) {mode_str}...",
        flush=True,
    )

    start = time.perf_counter()
    if use_threads:
        # Run reachability checks in parallel. Thread pool is fine here because checks are I/O-bound.
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(is_host_reachable, ips))
    else:
        results = [is_host_reachable(ip) for ip in ips]

    # Keep only hosts that responded; sort for stable, human-friendly output.
    alive = [ip for ip, ok in zip(ips, results) if ok]
    alive.sort(key=ipaddress.ip_address)

    # Optional: show reverse DNS names in the printed list.
    global DISCOVERY_SHOW_RDNS
    if alive:
        choice = ask(
            "Resolve reverse DNS for live hosts in the list? (y/N): ").strip().lower()
        DISCOVERY_SHOW_RDNS = choice.startswith("y")
    else:
        DISCOVERY_SHOW_RDNS = False

    show_live_hosts(alive, with_names=DISCOVERY_SHOW_RDNS)

    elapsed = time.perf_counter() - start
    print(
        f"[*] Discovery finished: {len(alive)}/{task_count} hosts alive in {elapsed:.2f}s.\n",
        flush=True,
    )
    return alive

# =============================== 7) Scanning ==================================


def scan_tcp_ports(
    target_ip: str,
    ports: Sequence[int],
    host_header: str | None = None,
) -> list[tuple[int, str | None, str]]:
    """Sequential TCP scan; print open ports and return rows for CSV."""
    rows: list[tuple[int, str | None, str]] = [
    ]  # (port, service, first_banner_line)
    for port in ports:
        # Single connection attempt per port; banner grab when possible.
        is_open, banner = probe_tcp_port(
            target_ip, port, host_header=host_header
        )
        if is_open:
            # Stable service label if known.
            svc = get_service_name(port, "tcp")
            # Keep printouts short.
            fl = first_line_of(banner)
            line = f"OPEN   tcp/{port}" + (f" ({svc})" if svc else "")
            print(line if not fl else f"{line}  |  {fl}", flush=True)
            rows.append((port, svc, fl))
    return rows


def scan_tcp_ports_threaded(
    target_ip: str,
    ports: Sequence[int],
    workers: int = MAX_WORKERS,
    host_header: str | None = None,
) -> list[tuple[int, str | None, str]]:
    """TCP scan using a thread pool (good for I/O-bound work like connects)."""

    def task(port: int) -> tuple[int, str | None, str] | None:
        # Run one port probe in a worker; return CSV row or None if closed.
        try:
            is_open, banner = probe_tcp_port(
                target_ip, port, host_header=host_header)
            if not is_open:
                return None
            return (port, get_service_name(port, "tcp"), first_line_of(banner))
        except Exception:
            # Defensive: keep scanning even if a single port raises unexpectedly.
            return None

    # Map ports -> results concurrently; ex.map preserves input order.
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, ports))

    # Keep only open ports, then sort for tidy, predictable output.
    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])

    # Print after sorting so the console output isn't interleaved.
    for port, svc, fl in rows:
        line = f"OPEN   tcp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)
    return rows


def scan_udp_ports(
    target_ip: str,
    ports: Sequence[int],
) -> list[tuple[int, str | None, str]]:
    """Sequential UDP scan; show 'open' and (optionally) non-open states."""
    rows: list[tuple[int, str | None, str]] = []
    for port in ports:
        status, reply = probe_udp_port(target_ip, port)
        if status == "open":
            svc = get_service_name(port, "udp")
            fl = first_line_of(reply)
            line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
            print(line if not fl else f"{line}  |  {fl}", flush=True)
            rows.append((port, svc, fl))
        elif UDP_SHOW_NONOPEN:
            # Show visibility into timeouts/ICMP results without writing to CSV.
            svc = get_service_name(port, "udp")
            print(f"{status.upper():<13} udp/{port}" +
                  (f" ({svc})" if svc else ""), flush=True)
    return rows


def scan_udp_ports_threaded(
    target_ip: str,
    ports: Sequence[int],
    workers: int = MAX_WORKERS,
) -> list[tuple[int, str | None, str]]:
    """UDP scan via threads; prints non-open states inline for progress."""

    def task(port: int) -> tuple[int, str | None, str] | None:
        status, reply = probe_udp_port(target_ip, port)
        if status != "open":
            if UDP_SHOW_NONOPEN:
                svc = get_service_name(port, "udp")
                # Print from worker (ordering may interleave—acceptable for progress).
                print(f"{status.upper():<13} udp/{port}" +
                      (f" ({svc})" if svc else ""), flush=True)
            return None
        return (port, get_service_name(port, "udp"), first_line_of(reply))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, ports))

    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])  # Stabilize output order by port number.

    for port, svc, fl in rows:
        line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)
    return rows


# =============================== 8) Output ====================================


def csv_escape_cell(s: str) -> str:
    """Make a CSV cell safe for spreadsheets.

    - Prefix leading formula characters (=, +, -, @) with an apostrophe to avoid
      formula injection.
    - Strip newlines and NULs so rows stay one line each.
    """
    if not s:
        return s
    # If the first char could start a spreadsheet formula, prefix once with '\''.
    if s[0] in "=+-@ \t" and not s.startswith("'"):
        s = "'" + s
    # Replace line breaks and NULs; keep output single-line and printable.
    return s.replace("\r", " ").replace("\n", " ").replace("\x00", "")


def write_results_csv(
    rows: list[tuple[int, str | None, str]],
    target_ip: str,
    started_iso: str,
    elapsed_s: float,
    protocol: str = "tcp",
    target_name: str | None = None,
) -> str:
    """Write scan results to a CSV file; return the filename (or "(write_failed)").

    Columns: target_ip, target_name, protocol, port, service, banner_first_line_of,
    scan_started, scan_elapsed_s. File name includes the target and a timestamp.
    """
    # Time-stamped suffix for unique, sortable filenames (local time).
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Make a safe, short label from the hostname/label for the file name.
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", (target_name or "").strip())
    if len(safe_name) > 60:
        safe_name = safe_name[:60].rstrip("_")

    filename = f"scan_{target_ip}{('_' + safe_name) if safe_name else ''}_{ts}.csv"

    try:
        # utf-8-sig adds a BOM so Excel opens it as UTF-8 without mojibake.
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)

            # Header row documents the schema for downstream tools.
            w.writerow([
                "target_ip",
                "target_name",
                "protocol",
                "port",
                "service",
                "banner_first_line_of",
                "scan_started",
                "scan_elapsed_s",
            ])

            # Data rows: escape user/remote text to keep CSV safe and tidy.
            for port, svc, fl in rows:
                w.writerow([
                    target_ip,
                    csv_escape_cell(target_name or ""),
                    protocol,
                    port,
                    csv_escape_cell(svc or ""),
                    csv_escape_cell(fl),
                    started_iso,
                    f"{elapsed_s:.2f}",
                ])
    except OSError as e:
        # I/O issues (permissions, disk full, invalid path, etc.).
        print(f"[!] Could not write results to '{filename}': {e}", flush=True)
        return "(write_failed)"

    return filename


# ============================ 9) CLI Prompts ==================================
"""Interactive prompts and input validation for the CLI flow.

These helpers keep user interaction consistent and beginner-friendly.
They only gather/validate input; scanning logic lives elsewhere.
"""

# Note: We pass `flush=True` to print() throughout so messages appear immediately
# instead of sitting in a buffer. This keeps prompts responsive, especially when
# output is piped or threads are used.


def ask(prompt: str) -> str:
    """Read a line from the user; exit cleanly on EOF or Ctrl+C.

    Keeps all callers simple: either we get a string or we terminate with a
    clear message (no stack traces for normal control cases).
    """
    try:
        return input(prompt)
    except EOFError:
        print("\n[!] No input available. Exiting.", flush=True)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.", flush=True)
        raise SystemExit(130)


def prompt_mode() -> str:
    """Return 'tcp' or 'udp' after a simple check."""
    while True:
        mode = ask("Scan mode (tcp/udp): ").strip().lower()
        if mode in ("tcp", "udp"):
            return mode
        # Short, friendly hint for beginners.
        print("[!] Please enter 'tcp' or 'udp'. Try again.", flush=True)


def prompt_ports() -> list[int]:
    """Ask for ports/ranges (e.g., 443, 80, 443-445) → list of unique ports."""
    while True:
        s = ask("Enter ports/ranges (e.g., 443, 80, 443-445, 8000, 20-25): ").strip()
        try:
            # Centralized validation lives in parse_port_range() so rules are in one place.
            return parse_port_range(s)
        except ValueError as err:
            print(f"[!] {err}. Try again.", flush=True)


def prompt_threads(task_count: int, context: str = "scanning", noun: str = "ports") -> tuple[bool, int]:
    """Ask whether to use threads and, if so, how many.

    Returns (use_threads, workers). Caps workers for safety and useful parallelism.
    """
    # If there's only one unit of work, threading won't help.
    if task_count <= 1:
        return False, 1

    use_threads = ask(
        f"Use threads for {context} ({noun})? (y/N): ").strip().lower().startswith("y")
    if not use_threads:
        return False, 1

    # Avoid oversubscribing the system (and pointlessly spawning more threads than tasks).
    cap = max(1, min(task_count, MAX_WORKERS))
    while True:
        s = ask(
            f"{context.capitalize()} workers (1-{cap}) [ENTER for {cap}]: ").strip()
        if not s:  # ENTER → default
            return True, cap
        try:
            w = int(s)
            if 1 <= w <= cap:
                return True, w
            print(
                f"[!] Worker count must be between 1 and {cap}. Try again.", flush=True)
        except ValueError:
            print("[!] Invalid worker count. Enter a positive integer.", flush=True)


def prompt_scan_params() -> tuple[list[int], str, bool, int]:
    """Collect (ports, mode, use_threads, workers) from the user."""
    # Order matters for a smooth flow: ports → mode → threading.
    ports = prompt_ports()
    mode = prompt_mode()
    # pool size depends on how many ports
    use_threads, workers = prompt_threads(len(ports))
    print()  # visual spacer for readability
    return ports, mode, use_threads, workers


def prompt_discovery_block() -> str | None:
    """Ask for an IPv4 host or CIDR block; ENTER skips discovery."""
    while True:
        block = ask(
            "Enter IP or CIDR (e.g., '127.0.0.1' or '192.168.1.0/30') [ENTER to skip]: "
        ).strip()

        if not block:
            return None  # user chose to skip discovery

        try:
            # strict=False accepts single IPs (treated as /32) and subnets that are
            # auto-rounded to the network start (e.g., 192.168.1.5/24 → 192.168.1.0/24).
            net = ipaddress.ip_network(block, strict=False)

            if net.version != 4:  # IPv6 explicitly not supported here
                print(
                    "[!] IPv6 not supported. Enter IPv4 or press ENTER.", flush=True)
                continue

            # Guardrail against very large scans that can overwhelm the machine/network.
            if net.num_addresses > MAX_HOSTS + 2:  # +2 accounts for network/broadcast
                print(
                    f"[!] Network too large ({net.num_addresses}). Max {MAX_HOSTS}.", flush=True)
                continue

            return block

        except ValueError as err:
            print(f"[!] {err}. Try again, or press ENTER to skip.", flush=True)


def prompt_target_ip() -> tuple[str, str | None]:
    """Ask for a host, resolve to IPv4, and return (ip, friendly_name_or_None)."""
    while True:
        user_target = ask("Enter target (IP or hostname): ").strip()
        try:
            # Resolve once (hostname → IPv4). Raises ValueError if resolution fails.
            target_ip = resolve_ipv4_target(user_target)

            try:
                # If this parses as an IP, the user typed a literal IP.
                ipaddress.ip_address(user_target)
                rdns = reverse_dns(target_ip)  # try to find a name for the IP
                if rdns:
                    print(f"Target: {target_ip} ({rdns})", flush=True)
                    target_name = rdns
                else:
                    print(f"Target: {target_ip}", flush=True)
                    target_name = None

            except ValueError:
                # Otherwise the user typed a hostname; keep their text as the label.
                rdns = reverse_dns(target_ip)
                # Only show rDNS if it exists and differs from what the user typed.
                if rdns and rdns.lower() != user_target.lower():
                    print(
                        f"Target resolved to: {target_ip} (rDNS: {rdns})", flush=True)
                else:
                    print(f"Target resolved to: {target_ip}", flush=True)
                target_name = user_target

            return target_ip, target_name

        except ValueError as err:
            # Bad hostname or unsupported address → prompt again.
            print(f"[!] {err}. Try again.", flush=True)


def show_live_hosts(live: list[str], *, with_names: bool = False) -> None:
    """Print a numbered list of live hosts; optionally resolve names for context."""
    print("[*] Live hosts:", flush=True)
    if live:
        if with_names:
            # Best-effort reverse DNS, done in parallel so the list prints quickly.
            with ThreadPoolExecutor(max_workers=min(len(live), 50)) as ex:
                # preserves input order
                names = list(ex.map(reverse_dns, live))
            for i, (ip, name) in enumerate(zip(live, names), 1):
                label = f"{ip} ({name})" if name else ip
                print(f"  {i}. {label}", flush=True)
        else:
            for i, ip in enumerate(live, 1):
                print(f"  {i}. {ip}", flush=True)
    else:
        print("  (none)", flush=True)


def select_live_hosts(live: list[str], *, show_list: bool = False) -> list[str]:
    """Let the user pick hosts from the discovery list; return the chosen IPs."""
    if not live:
        print("[*] No live hosts to select.", flush=True)
        return []

    if show_list:  # Optional re-print on repeat selections
        show_live_hosts(live, with_names=DISCOVERY_SHOW_RDNS)

    while True:
        sel = ask("Select hosts (e.g., 1-3,5 or 'all'): ").strip()
        try:
            # Convert '1-3,5' into indices and map to IPs.
            idxs = parse_index_list(sel, len(live))
            return [live[i - 1] for i in idxs]  # indices are 1-based
        except (ValueError, TypeError):
            print("[!] Invalid selection. Try again.", flush=True)


# ================================ 10) Runner ==================================


def run_scan_for_target(
    target_ip: str,
    ports: Sequence[int],
    mode: str,
    use_threads: bool,
    workers: int,
    target_name: str | None = None,
) -> None:
    """Orchestrate a single scan run for one host.

    Args:
        target_ip: IPv4 address to scan.
        ports: Concrete list/sequence of ports to check.
        mode: "tcp" or "udp".
        use_threads: Whether to parallelize over ports.
        workers: Max worker threads if threading.
        target_name: Optional label/hostname for nicer output & HTTP Host header.

    Why this lives in one function: keeps the scan flow readable (prompt -> scan -> save),
    and makes it easy to call repeatedly with different settings.
    """
    # Friendly label for logs (IP only, or IP + name if available).
    label = f"{target_ip}" if not target_name else f"{target_ip} ({target_name})"
    print(f"Target selected: {label}", flush=True)

    # --- One‑time feature toggles (remembered in globals) ---------------------
    # Ask once per process whether to enable RTT‑based timeouts.
    global AUTOTUNE_ENABLED, AUTOTUNE_PROMPTED
    if not AUTOTUNE_PROMPTED:
        choice = ask(
            "Enable RTT-based auto-tuning of timeouts (recommended on WAN/VPN)? (y/N): "
        ).strip().lower()
        AUTOTUNE_ENABLED = choice.startswith("y")
        AUTOTUNE_PROMPTED = True

    if AUTOTUNE_ENABLED:
        # Measures median RTT to common ports, then adjusts TCP/UDP/banner timeouts.
        autotune_timeouts_for(target_ip)

    # Ask once whether to show non‑open UDP states. Helpful for learning/visibility,
    # but can be noisy, so it's opt-in and remembered.
    global UDP_SHOW_NONOPEN, UDP_VERBOSITY_PROMPTED
    if mode == "udp" and not UDP_VERBOSITY_PROMPTED:
        choice = ask(
            "Also show non-open UDP results (CLOSED / OPEN|FILTERED)? (y/N): "
        ).strip().lower()
        UDP_SHOW_NONOPEN = choice.startswith("y")
        UDP_VERBOSITY_PROMPTED = True

    # --- Scan bookkeeping ------------------------------------------------------
    port_count = len(ports)
    start = time.perf_counter()  # high‑res timer for duration
    # Local time with timezone in ISO‑8601 for easy Excel/CSV and human reading.
    started_iso = datetime.now(
        timezone.utc).astimezone().isoformat(timespec="seconds")

    # --- Thread policy ---------------------------------------------------------
    # If there's <=1 port, threading doesn't help; otherwise cap to a safe/usable size.
    if use_threads:
        if port_count <= 1:
            use_threads = False
        else:
            workers = max(1, min(workers, port_count, MAX_WORKERS))

    eff_concurrency = (
        f"with {workers} thread(s)" if use_threads else "without threading"
    )
    print(
        f"[*] Scanning {mode.upper()} on {label}: {port_count} port(s) {eff_concurrency}...",
        flush=True,
    )

    # --- Execute the scan ------------------------------------------------------
    if mode == "tcp":
        protocol = "tcp"
        rows = (
            scan_tcp_ports_threaded(
                target_ip, ports, workers, host_header=target_name
            )
            if use_threads
            else scan_tcp_ports(target_ip, ports, host_header=target_name)
        )
    else:
        protocol = "udp"
        rows = (
            scan_udp_ports_threaded(target_ip, ports, workers)
            if use_threads
            else scan_udp_ports(target_ip, ports)
        )

    # --- Wrap up ---------------------------------------------------------------
    elapsed = time.perf_counter() - start

    if not rows:
        # Nothing open in the chosen set; still report cleanly.
        print(f"No open {mode.upper()} ports in this selection.", flush=True)
    else:
        # Save a tidy CSV for later review / spreadsheet work.
        out_file = write_results_csv(
            rows,
            target_ip,
            started_iso,
            elapsed,
            protocol=protocol,
            target_name=target_name,
        )
        print(f"[*] Results saved to {out_file}", flush=True)

    print(
        f"[*] Done in {elapsed:.2f}s - scanned {port_count} {mode.upper()} port(s) - found {len(rows)} open.\n",
        flush=True,
    )


# ================================ 11) Main ====================================


def main() -> None:
    """Interactive entry point that guides the user through discovery and scanning."""
    # Friendly banner + reminder about ethics/permission.
    print("\n=== Simple Port Scanner ===")
    print("by Tan Amos, Oct 2025\n")
    print("[!] Only scan hosts you have permission to test.\n")

    # Optional step: find live hosts first, then let the user pick.
    use_discovery = ask(
        "Discover live hosts first? (y/N): ").strip().lower().startswith("y")

    # These hold a preselected host if discovery finds exactly one.
    preselected_target: str | None = None
    preselected_name: str | None = None
    live: list[str] = []

    if use_discovery:
        # Allow the user to try multiple discovery blocks (or skip entirely).
        while True:
            block = prompt_discovery_block()
            if block is None:
                print("[*] Discovery skipped.", flush=True)
                break

            # returns sorted list of IPv4 strings
            live = discover_live_hosts(block)

            if not live:
                # No hits: offer retry or fall back to manual entry.
                choice = ask(
                    "No live hosts. Try discovery again (t) or proceed with manual target entry (m)? [t/m]: "
                ).strip().lower()
                if choice.startswith("t"):
                    continue
                else:
                    live = []
                    break

            # Convenience: if only one host is up, auto-select it.
            if len(live) == 1:
                preselected_target = live[0]
                preselected_name = reverse_dns(
                    preselected_target) if DISCOVERY_SHOW_RDNS else None
                if preselected_name:
                    print(
                        f"[*] Using the only live host: {preselected_target} ({preselected_name})", flush=True)
                else:
                    print(
                        f"[*] Using the only live host: {preselected_target}", flush=True)
            break  # done with the discovery phase

    # ---- Path A: exactly one discovered host (already chosen) ----
    if preselected_target:
        target_ip = preselected_target
        while True:
            # Each loop lets the user rescan the same host with different params.
            ports, mode, use_threads, workers = prompt_scan_params()
            run_scan_for_target(target_ip, ports, mode,
                                use_threads, workers, preselected_name)
            if not ask("Scan the same discovered host again with different settings? (y/N): ").strip().lower().startswith("y"):
                break
        return  # done

    # ---- Path B: multiple discovered hosts (let user pick one or many) ----
    if live and len(live) > 1:
        first_prompt = True
        while True:
            to_scan = select_live_hosts(live, show_list=not first_prompt)
            if not to_scan:  # user cancelled
                break

            ports, mode, use_threads, workers = prompt_scan_params()

            # Scan each selected host with the same settings.
            for ip in to_scan:
                name = reverse_dns(ip) if DISCOVERY_SHOW_RDNS else None
                run_scan_for_target(ip, ports, mode,
                                    use_threads, workers, name)

            first_prompt = False
            if not ask("Scan more hosts from the list? (y/N): ").strip().lower().startswith("y"):
                break
        return  # done

    # ---- Path C: manual entry (no discovery or discovery skipped/empty) ----
    target_ip, target_name = prompt_target_ip()
    while True:
        ports, mode, use_threads, workers = prompt_scan_params()
        run_scan_for_target(target_ip, ports, mode,
                            use_threads, workers, target_name)
        if not ask("Scan the same host again with different settings? (y/N): ").strip().lower().startswith("y"):
            break


if __name__ == "__main__":
    # Graceful Ctrl+C handling so users don't see a long traceback.
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting cleanly.", flush=True)

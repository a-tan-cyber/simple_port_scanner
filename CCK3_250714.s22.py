#!/usr/bin/env python3
"""
Network Scanner

Author:     Tan Amos (s22)
Institute:  Centre for Cybersecurity
Unit:       CCK3_250714
Trainer:    Samson
Date:       Oct 2025

Features:
- IPv4 scanning with optional live host discovery
- TCP/UDP port scan (single port or range), with optional multithreading
- Shows hostnames (reverse DNS) when available
- Grabs simple TCP banners (e.g., web server headers)
- Smarter UDP probes (DNS/NTP/SSDP) and labels results: open / closed / filtered
- Can auto-adjust timeouts based on network speed (RTT)
- Uses common service names (with sensible overrides)
- Saves results to CSV (includes timestamps, duration, service, and first-line banner)
"""

from __future__ import annotations
# Postpone evaluation of type annotations so they’re stored as strings.
# This avoids import-order issues (forward refs) and lowers runtime overhead.

import csv            # Write scan results to a CSV file.
import errno          # Portable error codes (e.g., ECONNREFUSED) across OSes.
import ipaddress      # Validate/expand IPv4 addresses and CIDR blocks.
import re             # Fast parsing of user input (e.g., "20-80") with regex.
import socket         # Core networking (TCP/UDP connect, send/recv).
import struct
import secrets
import sys            # Version/platform checks; clean exits.
import time           # Timing: timeouts, RTT measurement, elapsed durations.
from concurrent.futures import ThreadPoolExecutor  # Simple multithreading.
# Type hint for ordered, sized containers (list/tuple/range)
from typing import Sequence
from datetime import datetime, timezone   # Timestamps for logs/CSV.
from functools import lru_cache

# ----------------------------- Runtime Requirements -----------------------------
# Ensure features used (e.g., PEP 604 types: str | None) are available.
if sys.version_info < (3, 10):
    print("[!] Python 3.10+ required.", flush=True)
    raise SystemExit(1)

# --------------------------------- Constants -----------------------------------

# If true, try reverse DNS after discovery.
SHOW_NAMES_FOR_DISCOVERY: bool = False


# Token regex for ports and ranges like "80" or "20-25".
# Validate each comma/space‑separated token with this pattern.
# Precompiled: faster than re.compile per call.
PORT_TOKEN_RE = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")

# Baseline timeouts (seconds). Short by default so scans feel responsive.
BANNER_TIMEOUT: float = 2.0         # Read timeout when grabbing TCP banners.
TCP_CONNECT_TIMEOUT: float = 0.5    # Per TCP connect() attempt.
UDP_TIMEOUT: float = 1.0            # Per UDP probe (recv) wait.

# Optional: automatically adjust timeouts based on connection speed (RTT).
# On slow networks the scanner waits longer; on fast ones it keeps waits short.
AUTO_TUNE_TIMEOUTS: bool = False    # Off by default; ask the user once.
ASKED_AUTOTUNE: bool = False        # Guard to prevent re-prompting.
RTT_PROBE_PORTS: tuple[int, ...] = (22, 53, 80, 443, 3128, 3389, 8000, 8080)
RTT_PROBE_PER_TRY: float = 1.5      # Timeout for each connect() probe.
RTT_PROBE_SAMPLES: int = 5          # Stop after this many valid samples.

# UDP discovery probe (DNS) — small payload keeps discovery fast.
UDP_PROBE_PORT: int = 53

# If True, also print UDP 'closed' / 'open|filtered' lines (not saved to CSV)
SHOW_UDP_NONOPEN: bool = False
# One-time prompt guard for UDP non-open visibility
ASKED_UDP_VERBOSITY: bool = False

# Ports where an HTTP-style HEAD request tends to return a banner quickly.
HTTP_BANNER_PORTS: tuple[int, ...] = (80, 3128, 8000, 8080, 8081, 8888)

# Common ports to try first to check if a host is reachable (alive).
# Closed-but-reachable (ECONNREFUSED) also signals the host is alive.
COMMON_TCP_PORTS: tuple[int, ...] = (
    22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3128, 3389, 5900, 8000, 8080
)

# Prefer stable, predictable service names regardless of /etc/services variations.
CUSTOM_SERVICES_TCP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",           # DNS
    80: "http",
    110: "pop3",
    135: "msrpc",           # MS Remote Procedure Call
    139: "netbios-ssn",     # Netbios Session Service
    143: "imap",
    443: "https",
    445: "microsoft-ds",    # MS Directory Services
    3128: "http-proxy",
    3389: "ms-wbt-server",  # MS Windows Based Terminal (RDP)
    5900: "vnc",            # Virtual Network Computing
    8000: "http",
    8080: "http-alt",
}

CUSTOM_SERVICES_UDP: dict[int, str] = {
    53: "domain",
    123: "ntp",
    1900: "ssdp",           # Simple Service Discovery Protocol
}

NTP_CLIENT_PACKET = bytes([0x1B]) + b"\x00" * 47  # LI=0, VN=3, Mode=3 (client)

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

# Safety caps to avoid more targets/threads than the machine can handle.
MAX_HOSTS: int = 4096
MAX_WORKERS: int = 100


# ------------------------------ Prompt Utilities -------------------------------
"""Helpers for interactive prompts and input validation."""
# Note: For print(), we set flush=True throughout this script so messages appear
# immediately instead of waiting in a buffer. This keeps prompts/progress updates
# responsive during scans and still works reliably when output is piped or when
# threads are used.


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        print("\n[!] No input available. Exiting.", flush=True)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.", flush=True)
        raise SystemExit(130)


def prompt_discovery_block() -> str | None:
    """Ask for an IPv4 host or CIDR; ENTER skips."""
    while True:
        # Allow either a single IP (e.g., 192.168.1.10) or a small subnet (e.g., /30).
        block = ask(
            "Enter IP or CIDR (e.g., '127.0.0.1' or '192.168.1.0/30') [ENTER to skip]: "
        ).strip()

        # user chose to skip discovery
        if not block:
            return None

        try:
            # Parse/validate the user's text as an IP network.
            net = ipaddress.ip_network(block, strict=False)
            # strict=False accepts:
            #   - a single IP like "192.168.1.10" (treated as a /32 network)
            #   - an address with a prefix like "192.168.1.5/24"
            #     and automatically round it down to the true network start
            #     (e.g., becomes 192.168.1.0/24).
            # Raises ValueError if the input isn't a valid IPv4/IPv6 address or network.

            # Only allow IPv4; reject IPv6 inputs.
            if net.version != 4:
                print(
                    "[!] IPv6 not supported. Enter IPv4 or press ENTER.", flush=True)
                continue

            # Prevent huge scans by limiting address count.
            if net.num_addresses > MAX_HOSTS + 2:  # +2 for network/broadcast address
                print(
                    f"[!] Network too large ({net.num_addresses}). Max {MAX_HOSTS}.", flush=True)
                continue

            return block

        # ipaddress raised a parse error -> ask again.
        except ValueError as err:
            print(f"[!] {err}. Try again, or press ENTER to skip.", flush=True)


def prompt_target_ip() -> tuple[str, str | None]:
    """Ask for a target and ensure it resolves to IPv4."""
    while True:
        user_target = ask("Enter target (IP or hostname): ").strip()
        try:
            # Resolve once (hostname -> IPv4 string). Raises ValueError on failure.
            target_ip = resolve_target(user_target)

            try:
                # If this succeeds, the user typed a literal IP.
                ipaddress.ip_address(user_target)
                # Try to find a name for the IP.
                rdns = reverse_dns(target_ip)
                if rdns:
                    print(f"Target: {target_ip} ({rdns})", flush=True)
                    target_name = rdns
                else:
                    print(f"Target: {target_ip}", flush=True)
                    target_name = None

            except ValueError:
                # Otherwise the user typed a hostname; keep what they typed as the label.
                rdns = reverse_dns(target_ip)

                # Show rDNS only when it exists and differs from what the user typed.
                if rdns and rdns.lower() != user_target.lower():
                    print(
                        f"Target resolved to: {target_ip} (rDNS: {rdns})", flush=True)
                else:
                    print(f"Target resolved to: {target_ip}", flush=True)

                target_name = user_target

            return target_ip, target_name

        # Bad hostname or unsupported address -> try again.
        except ValueError as err:
            print(f"[!] {err}. Try again.", flush=True)


def prompt_port_range() -> list[int]:
    """Ask for ports/ranges like "80, 443-445"; return a de-duplicated list of ports."""
    while True:
        s = ask("Enter ports/ranges (e.g., 443, 80, 443-445, 8000, 20-25): ").strip()
        try:
            return parse_port_range(s)  # centralized validation
        except ValueError as err:
            print(f"[!] {err}. Try again.", flush=True)


def prompt_mode() -> str:
    """Return 'tcp' or 'udp' after validation."""
    while True:
        mode = ask("Scan mode (tcp/udp): ").strip().lower()
        if mode in ("tcp", "udp"):
            return mode
        # Bad input -> try again.
        print("[!] Please enter 'tcp' or 'udp'. Try again.", flush=True)


def prompt_threads(task_count: int, context: str = "scanning", noun: str = "ports") -> tuple[bool, int]:
    """
    Ask whether to use threads and how many; returns (use_threads, workers).
    Args:
      task_count: number of independent tasks (e.g., #ports or #hosts)
      context: text to show in the prompt, e.g. "scanning" or "discovery"
      noun: what is parallelized over, e.g. "ports" or "hosts"
    """
    # If there's only one task, threading can't help; skip the prompt.
    if task_count <= 1:
        return False, 1

    # Simple yes/no gate for threading.
    use_threads = ask(
        f"Use threads for {context} ({noun})? (y/N): ").strip().lower().startswith("y")
    # treat any input starting with 'y' as Yes
    if not use_threads:
        return False, 1

    # Cap workers to prevent spawning more threads than useful or safe.
    cap = max(1, min(task_count, MAX_WORKERS))
    while True:
        s = ask(
            f"{context.capitalize()} workers (1-{cap}) [ENTER for {cap}]: ").strip()
        if not s:               # ENTER pressed.
            return True, cap    # Default to the safe cap.
        try:
            w = int(s)
            if 1 <= w <= cap:
                return True, w
            # If input was not between 1 and cap
            print(
                f"[!] Worker count must be between 1 and {cap}. Try again.", flush=True)

        # Bad input
        except ValueError:
            print("[!] Invalid worker count. Enter a positive integer.", flush=True)


def choose_scan_params() -> tuple[list[int], str, bool, int]:
    """Collect (ports, mode, use_threads, workers) from prompts."""
    # Ask in a friendly order: ports -> mode -> threading. Then add a spacer line.
    ports = prompt_port_range()
    mode = prompt_mode()
    # Thread pool sizing is based on the number of discrete ports selected.
    use_threads, workers = prompt_threads(len(ports))
    print()  # visual spacer for readability
    return ports, mode, use_threads, workers


def show_live_hosts(live: list[str], *, with_names: bool = False) -> None:
    """Pretty‑print a numbered list of live hosts (optionally with names)."""
    # live: list of IP strings; '*' makes with_names keyword-only (must call like with_names=True)
    print("[*] Live hosts:", flush=True)
    if live:
        if with_names:
            # Resolve names quickly without slowing discovery (best‑effort).
            with ThreadPoolExecutor(max_workers=min(len(live), 50)) as ex:
                # ThreadPoolExecutor: runs many function calls in parallel threads.
                # Use up to one thread per host, capped at 50 to avoid oversubscribing/overwhelming CPU and DNS.

                names = list(ex.map(reverse_dns, live))
                # Schedule reverse_dns(ip) for each IP and yield results in input order;
                # list(...) forces immediate evaluation.

            # Pair each IP with its resolved name (if any).
            for i, (ip, name) in enumerate(zip(live, names), 1):
                label = f"{ip} ({name})" if name else ip
                print(f"  {i}. {label}", flush=True)
        else:
            # No names requested; just list the IPs.
            for i, ip in enumerate(live, 1):
                print(f"  {i}. {ip}", flush=True)
    else:
        print("  (none)", flush=True)


def select_hosts(live: list[str], *, show_list: bool = False) -> list[str]:
    """Let the user choose which live hosts to scan; return their IPs."""
    if not live:
        print("[*] No live hosts to select.", flush=True)
        return []

    # Optionally re‑show the list (useful on repeat selections).
    if show_list:
        show_live_hosts(live, with_names=SHOW_NAMES_FOR_DISCOVERY)

    while True:
        sel = ask("Select hosts (e.g., 1-3,5 or 'all'): ").strip()
        try:
            # Convert selections like '1-3,5' into 1‑based indices, then map to IPs.
            idxs = parse_index_list(sel, len(live))
            return [live[i - 1] for i in idxs]
        # Bad format or out‑of‑range numbers.
        except (ValueError, TypeError):
            print("[!] Invalid selection. Try again.", flush=True)


# ------------------------------ Parsing Utilities --------------------------------
"""Helpers that turn user text into clean numbers/lists."""


def parse_port_range(s: str) -> list[int]:
    """Parse string of numbers/ranges -> unique ports (in input order).
    - Accepts single ports and ranges, separated by commas and/or spaces.
    - Validates bounds (1..65535) and supports reversed ranges (e.g., "90-80").
    - De‑duplicates so callers don't rescan the same port twice.
    """
    # Split on commas and/or whitespace; drop empty fragments.
    tokens = [t.strip() for t in re.split(r"[\s,]+", s) if t.strip()]
    if not tokens:
        raise ValueError("empty port list")

    seen: set[int] = set()   # track what is already added
    out: list[int] = []      # preserve first‑seen order

    for tok in tokens:
        # match the entire token (rejects extras/partials)
        m = PORT_TOKEN_RE.fullmatch(tok)
        if not m:
            raise ValueError(
                "Use numbers and ranges like '80' or '20-25', separated by commas/spaces"
            )
        a = int(m.group(1))  # first number in token (left side of dash)
        # second number if present; else same as 'a' (single port)
        b = int(m.group(2)) if m.group(2) else a

        # Allow reversed like '90-80' by normalizing (lo<=hi).
        lo, hi = (a, b) if a <= b else (b, a)

        # Bounds check once per token.
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
            raise ValueError("Ports must be between 1 and 65535.")

        # Expand the range and append only new ports.
        for p in range(lo, hi + 1):
            if p not in seen:
                seen.add(p)
                out.append(p)

    return out


def parse_index_list(expr: str, max_n: int) -> list[int]:
    """
    Parse string of numbers/ranges -> 1-based indices within 1..max_n.
    Supports reversed ranges (e.g., '4-1'). De-duplicates in first-seen order.
    """
    # Normalize: trim spaces; make lower so we can accept 'ALL'/'All'.
    expr = expr.strip().lower()

    # Fast paths for 'all' selections.
    if expr in ("a", "all", "*"):
        return list(range(1, max_n + 1))

    # Split on commas and/or whitespace, drop empties.
    tokens = [t.strip() for t in re.split(r"[,\s]+", expr) if t.strip()]
    if not tokens:
        raise ValueError("empty selection")

    raw: list[int] = []  # collect possibly duplicated indices here
    for tok in tokens:
        # Range token like '3-6' or reversed '6-3'.
        m = re.fullmatch(r"(\d+)-(\d+)", tok)

        if m:
            a, b = int(m.group(1)), int(m.group(2))

            # Ensure both ends are within bounds.
            if not (1 <= a <= max_n and 1 <= b <= max_n):
                raise ValueError("range out of bounds")

            # step=1 for ascending ranges, -1 for descending (so '4-1' works).
            step = 1 if a <= b else -1

            # range() is exclusive of the stop, so add step to include it.
            raw.extend(list(range(a, b + step, step)))

        else:
            # Single number token.
            i = int(tok)
            if not (1 <= i <= max_n):
                raise ValueError("index out of bounds")
            raw.append(i)

    # De‑duplicate while preserving first-seen order.
    out: list[int] = []
    seen: set[int] = set()
    for i in raw:
        if i not in seen:
            out.append(i)
            seen.add(i)
    return out

# ---------------------------- DNS & Host Discovery -----------------------------


def resolve_target(user_input: str) -> str:
    """Return an IPv4 address string from either an IP or hostname."""
    try:
        ip = ipaddress.ip_address(user_input)
        if ip.version != 4:
            raise ValueError(
                "IPv6 addresses are not supported by this scanner.")
        return str(ip)
    except ValueError:
        pass

    try:
        # Get only IPv4 (AF_INET) stream endpoints; take the first address
        host = user_input.rstrip(".")
        infos = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            flags=getattr(socket, "AI_ADDRCONFIG", 0),
        )
        if not infos:
            raise ValueError("Could not resolve hostname to an IPv4 address.")
        return infos[0][4][0]
    except OSError as e:
        raise ValueError(
            "Could not resolve hostname to an IPv4 address.") from e


@lru_cache(maxsize=8192)
def reverse_dns(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".")
    except (socket.herror, OSError):
        return None


def estimate_rtt_seconds(ip: str,
                         ports: tuple[int, ...] = RTT_PROBE_PORTS,
                         per_try: float = RTT_PROBE_PER_TRY,
                         samples_needed: int = RTT_PROBE_SAMPLES) -> float | None:
    """
    Try TCP connect() to several common ports with a short timeout.
    Count both success (rc==0) and ECONNREFUSED as valid samples (host reachable).
    Return median elapsed seconds, or None if we couldn't get any samples.
    """
    refused_codes = {errno.ECONNREFUSED}
    if sys.platform.startswith("win"):
        refused_codes.add(10061)  # WSAECONNREFUSED

    samples: list[float] = []
    for port in ports:
        t0 = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(per_try)
                rc = s.connect_ex((ip, port))
        except OSError:
            continue  # skip this port sample

        dt = time.perf_counter() - t0
        if rc == 0 or rc in refused_codes:
            samples.append(dt)
        if len(samples) >= samples_needed:
            break

    if not samples:
        return None
    samples.sort()
    return samples[len(samples) // 2]  # median


def timeouts_from_rtt(rtt_s: float) -> tuple[float, float, float]:
    """
    Map RTT to sensible timeouts with bounds:
      TCP ≈ 10×RTT (0.3–5.0s)
      Banner ≈ 18×RTT (1.0–8.0s)
      UDP ≈ 10×RTT (0.5–5.0s)
    """
    def clamp(x, lo, hi): return max(lo, min(hi, x))
    tcp = clamp(10.0 * rtt_s, 0.3, 5.0)
    banner = clamp(18.0 * rtt_s, 1.0, 8.0)
    udp = clamp(10.0 * rtt_s, 0.5, 5.0)
    # round a bit for nicer prints
    return round(tcp, 2), round(banner, 2), round(udp, 2)


def autotune_timeouts_for(ip: str) -> None:
    """
    Adjust module-level timeouts based on measured RTT. If we can't infer RTT
    (everything filtered/timed out), keep existing timeouts.
    """
    global TCP_CONNECT_TIMEOUT, BANNER_TIMEOUT, UDP_TIMEOUT

    rtt = estimate_rtt_seconds(ip)
    if rtt is None:
        print("[*] RTT auto-tune: unable to infer link latency (filtered/timeouts). "
              "Keeping current timeouts.", flush=True)
        return

    tcp, banner, udp = timeouts_from_rtt(rtt)
    TCP_CONNECT_TIMEOUT, BANNER_TIMEOUT, UDP_TIMEOUT = tcp, banner, udp
    print(f"[*] RTT auto-tune: RTT≈{int(rtt * 1000)}ms -> "
          f"TCP={tcp}s, Banner={banner}s, UDP={udp}s", flush=True)


def icmp_port_unreachable(exc: BaseException) -> bool:
    # POSIX: errno.ECONNREFUSED; Windows: WSAECONNRESET (10054)
    return getattr(exc, "errno", None) == errno.ECONNREFUSED or getattr(exc, "winerror", None) == 10054


def is_host_up(ip: str, timeout: float | None = None, check_udp: bool = True) -> bool:
    """
    Consider host 'up' if:
      - any TCP connect_ex returns 0 (open), or
      - TCP returns ECONNREFUSED (closed but reachable), or
      - (optional) UDP 53 probe yields any reply or ICMP port unreachable (closed).
    """
    if timeout is None:
        timeout = TCP_CONNECT_TIMEOUT

    refused_codes = {errno.ECONNREFUSED}

    if sys.platform.startswith("win"):
        refused_codes.add(10061)  # WSAECONNREFUSED on Windows

    # --- TCP heuristic ---
    for port in COMMON_TCP_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                rc = s.connect_ex((ip, port))
                if rc == 0 or rc in refused_codes:
                    return True
        except OSError:
            continue  # try the next common port

    # --- UDP heuristic (DNS 53) ---
    if check_udp:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(min(UDP_TIMEOUT, max(0.1, timeout)))
                s.connect((ip, UDP_PROBE_PORT))
                try:
                    s.sendall(dns_query("example.com"))
                    _ = s.recv(1)          # any payload -> host is up
                    return True
                except socket.timeout:
                    pass                    # no UDP reply; can't conclude
                except ConnectionRefusedError:
                    return True             # ICMP port unreachable => host reachable
                except ConnectionResetError as e:
                    if getattr(e, "winerror", None) == 10054:
                        return True         # Windows ICMP unreachable
                except OSError as e:
                    if icmp_port_unreachable(e):
                        return True  # ICMP port unreachable => host reachable
                    # else fall through (treat as inconclusive)
        except OSError:
            pass  # couldn't create/connect UDP socket; inconclusive

    return False


def expand_ips(block: str) -> list[str]:
    net = ipaddress.ip_network(block, strict=False)
    if net.version != 4:
        raise ValueError("IPv6 addresses are not supported by this scanner.")
    if net.num_addresses > MAX_HOSTS + 2:
        raise ValueError(
            f"Network too large ({net.num_addresses}). Try a smaller block.")
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(ip) for ip in net.hosts()]


def discover_live_hosts(block: str) -> list[str]:
    """
    Return IPs that appear alive (TCP connect() returns 0 or ECONNREFUSED).
    """
    ips = expand_ips(block)
    task_count = len(ips)

    use_threads, workers = prompt_threads(
        task_count, context="discovery", noun="hosts")
    mode_str = f"with {workers} thread(s)" if use_threads else "without threading"
    print(
        f"\n[*] Starting live-host discovery for {block}: probing {task_count} host(s) {mode_str}...", flush=True)

    start = time.perf_counter()
    if use_threads:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(is_host_up, ips))
    else:
        results = [is_host_up(ip) for ip in ips]

    alive = [ip for ip, ok in zip(ips, results) if ok]
    alive.sort(key=ipaddress.ip_address)

    global SHOW_NAMES_FOR_DISCOVERY
    if alive:
        choice = ask(
            "Resolve reverse DNS for live hosts in the list? (y/N): ").strip().lower()
        SHOW_NAMES_FOR_DISCOVERY = choice.startswith("y")
    else:
        SHOW_NAMES_FOR_DISCOVERY = False

    show_live_hosts(alive, with_names=SHOW_NAMES_FOR_DISCOVERY)

    elapsed = time.perf_counter() - start
    print(
        f"[*] Discovery finished: {len(alive)}/{task_count} hosts alive in {elapsed:.2f}s.\n", flush=True)
    return alive


# --- UDP protocol-specific probe payloads ---

def dns_query(name: str = "example.com") -> bytes:
    """
    Minimal DNS A IN query for 'name' with RD=1.
    """
    name = name.strip(".")
    labels = [lbl.encode("idna") for lbl in name.split(".") if lbl]
    # Enforce RFC limits: label <= 63 bytes, full name <= 253 bytes.
    if any(len(lbl) > 63 for lbl in labels) or sum(len(lbl) + 1 for lbl in labels) + 1 > 253:
        labels = [b"example", b"com"]
    qname = b"".join(len(lbl).to_bytes(1, "big") +
                     lbl for lbl in labels) + b"\x00"
    # Random ID, flags=0x0100 (standard query, RD), QDCOUNT=1
    tid = secrets.randbits(16)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qtype_qclass = b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
    return header + qname + qtype_qclass


def udp_payload_for_port(port: int) -> bytes | None:
    """
    Return a protocol-appropriate probe payload for select UDP ports.
    For other ports, return None (caller will fall back to a generic probe).
    """
    if port == 53:    # DNS
        return dns_query("example.com")
    if port == 123:   # NTP
        return NTP_CLIENT_PACKET
    if port == 1900:  # SSDP/UPnP
        return SSDP_MSEARCH
    return None


# ------------------------------ Scan Primitives --------------------------------

def check_port_with_banner(
    target_ip: str,
    port: int,
    host_header: str | None = None,
) -> tuple[bool, str | None]:
    """Connect once to test TCP and try to read a short banner."""
    try:
        with socket.create_connection((target_ip, port), TCP_CONNECT_TIMEOUT) as s:
            try:
                if port in HTTP_BANNER_PORTS:
                    # Prefer a friendly hostname if we already have one.
                    # Fallback to rDNS once (cached), then the raw IP.
                    host_hdr = (host_header or reverse_dns(
                        target_ip) or target_ip)
                    try:
                        host_hdr = host_hdr.encode("idna").decode("ascii")
                    except Exception:
                        host_hdr = target_ip

                    # Include :port on non-80 to help name-based vhosts on alt ports
                    host_line = f"{host_hdr}:{port}" if port != 80 else host_hdr

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
                    s.sendall(b"\r\n")

                # set the longer window only for the read path
                s.settimeout(BANNER_TIMEOUT)
                data = s.recv(1024)
                banner = data.decode(
                    "latin-1", "replace").strip() if data else None

            except socket.timeout:
                banner = None
            except OSError:
                banner = None
            return True, banner
    except OSError:
        return False, None


def first_line(text: str | None) -> str:
    return "" if not text else text.splitlines()[0]


def scan_udp_once(
    target_ip: str,
    port: int,
    payload: bytes | None = None,
    timeout: float | None = None,
) -> tuple[str, str | None]:
    """
    Returns:
      "open" -> reply received (with optional text)
      "closed" -> ICMP port unreachable (ECONNREFUSED/WSAECONNRESET)
      "open|filtered" -> no reply (timeout/dropped)
    """
    if timeout is None:
        timeout = UDP_TIMEOUT  # picks up current (possibly auto-tuned) value

    # Choose a smarter probe if caller didn't specify one
    if payload is None:
        payload = udp_payload_for_port(port) or b"\x00"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            try:
                s.sendall(payload)
                data = s.recv(1024)
                if not data:
                    return "open", None
                return "open", data.decode("latin-1", "replace").strip()

            except socket.timeout:
                return "open|filtered", None
            except ConnectionRefusedError:
                return "closed", None
            except ConnectionResetError as e:
                if getattr(e, "winerror", None) == 10054:
                    return "closed", None
                return "open|filtered", None
            except OSError as e:
                if icmp_port_unreachable(e):
                    return "closed", None
                return "open|filtered", None
    except OSError:
        return "open|filtered", None

# ---------------------------- Scan Range Functions -----------------------------


@lru_cache(maxsize=4096)
def svc_name(port: int, proto: str) -> str | None:
    if proto == "tcp" and port in CUSTOM_SERVICES_TCP:
        return CUSTOM_SERVICES_TCP[port]
    if proto == "udp" and port in CUSTOM_SERVICES_UDP:
        return CUSTOM_SERVICES_UDP[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


def scan_tcp_range(
    target_ip: str,
    ports: Sequence[int],
    host_header: str | None = None,
) -> list[tuple[int, str | None, str]]:
    rows: list[tuple[int, str | None, str]] = []
    for port in ports:
        is_open, banner = check_port_with_banner(
            target_ip, port, host_header=host_header
        )  # single connect per port
        if is_open:
            svc = svc_name(port, "tcp")
            fl = first_line(banner)
            line = f"OPEN   tcp/{port}" + (f" ({svc})" if svc else "")
            print(line if not fl else f"{line}  |  {fl}", flush=True)
            rows.append((port, svc, fl))
    return rows


def scan_tcp_range_threaded(
    target_ip: str,
    ports: Sequence[int],
    workers: int = MAX_WORKERS,
    host_header: str | None = None,
) -> list[tuple[int, str | None, str]]:
    def task(port: int) -> tuple[int, str | None, str] | None:
        try:
            is_open, banner = check_port_with_banner(
                target_ip, port, host_header=host_header
            )  # single connect per port
            if not is_open:
                return None
            return (port, svc_name(port, "tcp"), first_line(banner))
        except Exception:
            # Defensive: ignore unexpected per-port errors so the whole scan continues
            return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, ports))  # preserves input order

    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])
    for port, svc, fl in rows:
        line = f"OPEN   tcp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)
    return rows


def scan_udp_range(
    target_ip: str,
    ports: Sequence[int],
) -> list[tuple[int, str | None, str]]:
    rows: list[tuple[int, str | None, str]] = []
    for port in ports:
        status, reply = scan_udp_once(target_ip, port)
        if status == "open":
            svc = svc_name(port, "udp")
            fl = first_line(reply)
            line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
            print(line if not fl else f"{line}  |  {fl}", flush=True)
            rows.append((port, svc, fl))
        elif SHOW_UDP_NONOPEN:
            # Print non-open states for visibility, but don't add to CSV rows
            svc = svc_name(port, "udp")
            print(f"{status.upper():<13} udp/{port}" +
                  (f" ({svc})" if svc else ""), flush=True)
    return rows


def scan_udp_range_threaded(
    target_ip: str,
    ports: Sequence[int],
    workers: int = MAX_WORKERS,
) -> list[tuple[int, str | None, str]]:
    def task(port: int) -> tuple[int, str | None, str] | None:
        status, reply = scan_udp_once(target_ip, port)
        if status != "open":
            if SHOW_UDP_NONOPEN:
                svc = svc_name(port, "udp")
                # Print from worker thread (ordering may interleave; acceptable for progress)
                print(f"{status.upper():<13} udp/{port}" +
                      (f" ({svc})" if svc else ""), flush=True)
            return None
        return (port, svc_name(port, "udp"), first_line(reply))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, ports))

    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])
    for port, svc, fl in rows:
        line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)
    return rows


# --------------------------------- Output -------------------------------------

def csv_safe(s: str) -> str:
    if not s:
        return s
    # Only prefix if it isn't already an apostrophe
    if s[0] in "=+-@ \t" and not s.startswith("'"):
        s = "'" + s
    return s.replace("\r", " ").replace("\n", " ").replace("\x00", "")


def save_csv(
    rows: list[tuple[int, str | None, str]],
    target_ip: str,
    started_iso: str,
    elapsed_s: float,
    protocol: str = "tcp",
    target_name: str | None = None,
) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", (target_name or "").strip())
    if len(safe_name) > 60:
        safe_name = safe_name[:60].rstrip("_")
    filename = f"scan_{target_ip}{('_' + safe_name) if safe_name else ''}_{ts}.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([
                "target_ip",
                "target_name",
                "protocol",
                "port",
                "service",
                "banner_first_line",
                "scan_started",
                "scan_elapsed_s",
            ])
            for port, svc, fl in rows:
                w.writerow([
                    target_ip,
                    csv_safe(target_name or ""),
                    protocol,
                    port,
                    csv_safe(svc or ""),
                    csv_safe(fl),
                    started_iso,
                    f"{elapsed_s:.2f}",
                ])
    except OSError as e:
        print(f"[!] Could not write results to '{filename}': {e}", flush=True)
        return "(write_failed)"
    return filename


def run_scan_for_target(
    target_ip: str,
    ports: Sequence[int],
    mode: str,
    use_threads: bool,
    workers: int,
    target_name: str | None = None,
) -> None:
    label = f"{target_ip}" if not target_name else f"{target_ip} ({target_name})"
    print(f"Target selected: {label}", flush=True)

    # Ask once per run whether to enable RTT auto-tune
    global AUTO_TUNE_TIMEOUTS, ASKED_AUTOTUNE
    if not ASKED_AUTOTUNE:
        choice = ask(
            "Enable RTT-based auto-tuning of timeouts (recommended on WAN/VPN)? (y/N): "
        ).strip().lower()
        AUTO_TUNE_TIMEOUTS = choice.startswith("y")
        ASKED_AUTOTUNE = True

    if AUTO_TUNE_TIMEOUTS:
        autotune_timeouts_for(target_ip)

    # Ask once per run whether to also show UDP non-open states (closed / open|filtered)
    global SHOW_UDP_NONOPEN, ASKED_UDP_VERBOSITY
    if mode == "udp" and not ASKED_UDP_VERBOSITY:
        choice = ask(
            "Also show non-open UDP results (CLOSED / OPEN|FILTERED)? (y/N): "
        ).strip().lower()
        SHOW_UDP_NONOPEN = choice.startswith("y")
        ASKED_UDP_VERBOSITY = True

    port_count = len(ports)
    start = time.perf_counter()
    started_iso = datetime.now(
        timezone.utc).astimezone().isoformat(timespec="seconds")

    # Thread policy: disable for 0/1 port; otherwise cap to useful/safe limit.
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

    if mode == "tcp":
        protocol = "tcp"
        rows = (
            scan_tcp_range_threaded(
                target_ip, ports, workers, host_header=target_name)
            if use_threads
            else scan_tcp_range(target_ip, ports, host_header=target_name)
        )
    else:
        protocol = "udp"
        rows = (
            scan_udp_range_threaded(target_ip, ports, workers)
            if use_threads
            else scan_udp_range(target_ip, ports)
        )

    elapsed = time.perf_counter() - start

    if not rows:
        print(f"No open {mode.upper()} ports in this selection.", flush=True)
    else:
        out_file = save_csv(
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


# ----------------------------------- Main --------------------------------------

def main() -> None:
    print("\n=== Network Scanner ===")
    print("by Tan Amos, Oct 2025\n")
    print("[!] Only scan hosts you have permission to test.\n")

    # optional live-host discovery
    use_discovery = ask(
        "Discover live hosts first? (y/N): ").strip().lower().startswith("y")
    preselected_target: str | None = None
    preselected_name: str | None = None
    live: list[str] = []

    if use_discovery:
        while True:
            block = prompt_discovery_block()
            if block is None:
                print("[*] Discovery skipped.", flush=True)
                break

            live = discover_live_hosts(block)

            if not live:
                choice = ask(
                    "No live hosts. Try discovery again (t) or proceed with manual target entry (m)? [t/m]: "
                ).strip().lower()
                if choice.startswith("t"):
                    continue
                else:
                    live = []
                    break

            if len(live) == 1:
                preselected_target = live[0]
                preselected_name = reverse_dns(
                    preselected_target) if SHOW_NAMES_FOR_DISCOVERY else None
                if preselected_name:
                    print(
                        f"[*] Using the only live host: {preselected_target} ({preselected_name})", flush=True)
                else:
                    print(
                        f"[*] Using the only live host: {preselected_target}", flush=True)
            break

    # single discovered host path
    if preselected_target:
        target_ip = preselected_target
        while True:
            ports, mode, use_threads, workers = choose_scan_params()
            run_scan_for_target(target_ip, ports, mode,
                                use_threads, workers, preselected_name)
            if not ask("Scan the same discovered host again with different settings? (y/N): ").strip().lower().startswith("y"):
                break
        return

    # multiple discovered hosts path
    if live and len(live) > 1:
        first_prompt = True
        while True:
            to_scan = select_hosts(live, show_list=not first_prompt)
            if not to_scan:
                break

            ports, mode, use_threads, workers = choose_scan_params()

            for ip in to_scan:
                name = reverse_dns(ip) if SHOW_NAMES_FOR_DISCOVERY else None
                run_scan_for_target(ip, ports, mode,
                                    use_threads, workers, name)

            first_prompt = False
            if not ask("Scan more hosts from the list? (y/N): ").strip().lower().startswith("y"):
                break
        return

    # manual path
    target_ip, target_name = prompt_target_ip()
    while True:
        ports, mode, use_threads, workers = choose_scan_params()
        run_scan_for_target(target_ip, ports, mode,
                            use_threads, workers, target_name)
        if not ask("Scan the same host again with different settings? (y/N): ").strip().lower().startswith("y"):
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting cleanly.", flush=True)

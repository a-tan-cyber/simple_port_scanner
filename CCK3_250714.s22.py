#!/usr/bin/env python3

# === Script Authored by ===
# Student Name:	Tan Amos
# Institute:	Centre for Cybersecurity
# Class Code: 	CCK3_250714
# Student Code: s22
# Trainer:      Samson

# Project 1: Simple Port Scanner

# Overview:
# This project involves creating a port scanning tool used to probe a target system or
# network to identify which ports are open and listening for connections. This project
# introduces beginners to key cybersecurity concepts like networking, sockets, and
# TCP/UDP communication while strengthening Python skills.

# Project Goals:
# • Learn to use Python's socket module.
# • Understand the basics of port scanning and network security.
# • Develop a simple tool to scan for open ports on a target system.
# • Understand the concept of open ports and why securing them is critical.

# Features of the Port Scanner:
# 1. Accepts a target IP address or hostname.
# 2. Allows the user to specify a range of ports to scan.
# 3. Scans for open TCP or UDP ports.
# 4. Prints the results (open ports) in a user-friendly format.
# 5. Retrieve and display service banners for open ports.
# 6. Save scan results to a file for later analysis.
# 7. Add functionality to ping a range of IPs to discover live hosts.
# 8. Speed up scanning by checking multiple ports simultaneously (Multi-Threading).

import csv
import errno
import ipaddress    # to validate user input IP addresses
import re           # for regular expressions, to validate user input port ranges
import socket       # to create network connections
import time         # to measure scan duration

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

PortRange = tuple[int, int]

port_range_pattern = re.compile(r"^\s*([0-9]+)\s*-\s*([0-9]+)\s*$")

COMMON_TCP_PORTS: tuple[int, ...] = (80, 443, 22, 8000)

USE_THREADS: bool = True
MAX_WORKERS: int = 100


def parse_port_range(s: str) -> tuple[int, int]:
    m = port_range_pattern.match(s)
    if not m:
        raise ValueError("Use format low-high, e.g. 60-120")
    low, high = int(m.group(1)), int(m.group(2))
    if not (0 <= low <= 65535 and 0 <= high <= 65535 and low <= high):
        raise ValueError("Ports must be 0–65535 and low <= high.")
    return low, high


def resolve_target(user_input: str) -> str:
    """Return an IPv4 address string from either an IP or a hostname."""
    # 1) If it is already a valid IP, just use it.
    try:
        ipaddress.ip_address(user_input)  # raises ValueError if not a valid IP
        return user_input
    except ValueError:
        pass

    # 2) Otherwise, resolve hostname to IPv4
    try:
        return socket.gethostbyname(user_input)  # DNS (or /etc/hosts) lookup
    except socket.gaierror as e:                # gaierror: get address info error
        # "as e" and "from e": Preserve the root cause of error in traceback for debugging
        raise ValueError(
            "Could not resolve hostname to an IPv4 address.") from e


def scan_tcp_once(target_ip: str, port: int, *, timeout: float = 0.5) -> bool:
    # AF_INET: IPv4; SOCK_STREAM: TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # to prevent hanging forever
        s.settimeout(timeout)
        # try to connect; 0 = success, non-zero = error
        result = s.connect_ex((target_ip, port))
        return result == 0                          # True = open, False = not open


def grab_banner(target_ip: str, port: int, timeout: float = 1.0) -> str | None:
    """
    Try to connect and read a short 'banner' from a TCP service.
    Returns the banner text, or None if nothing is received quickly.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))

            # Send a small 'nudge', which can trigger banners on some services
            try:
                # some common ports that HTTP/S usually use
                if port in (80, 8080, 8000, 443, 8443):
                    # send a safe HTTP request
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    # send a safe newline message
                    s.sendall(b"\r\n")
            except OSError:
                # If sending fails, still try to read whatever the server may send
                pass

            try:
                data = s.recv(1024)  # read up to 1024 bytes
            except socket.timeout:
                return None

            if not data:
                return None

            # decode from binary to text
            return data.decode(errors="ignore").strip()

    except OSError:
        # Could not connect or other socket issue
        return None


def check_port_with_banner(target_ip: str, port: int) -> tuple[bool, str | None]:
    """
    Try to connect to a TCP port.
    If open, also try to grab a short banner.
    Returns (is_open, banner) or None.
    """
    # 1) Use the simple TCP check
    is_open = scan_tcp_once(target_ip, port, timeout=0.5)

    # 2) If open, try to read a benner (may still be None if service is quiet)
    banner = grab_banner(target_ip, port, timeout=1.0) if is_open else None

    # 3) Hand both results back to the caller
    return is_open, banner


def first_line(text: str | None) -> str:
    """Return the first line of a banner (or '' if None)."""
    if not text:
        return ""
    return text.splitlines()[0]


def is_host_up_socket(ip: str, timeout: float = 0.4) -> bool:
    """
    Return True if the host appears alive based on TCP connect() behavior.
    Host is considered up if any probe returns:
        - 0 (connect OK) or
        - ECONNREFUSED (host answered but port closed)
    """
    for port in COMMON_TCP_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                rc = s.connect_ex((ip, port))  # 0 = OK; else an errno code
                if rc == 0 or rc == errno.ECONNREFUSED:
                    return True  # host responded -> alive
                # else, try next port (timeout, no route, etc.)
        except OSError:
            # network hiccup, just try the next port
            pass
    return False


def expand_ips(block: str) -> list[str]:
    """
    Accepts single IP address or CIDR block and returns IP strings to test.
    - For a single-address block (/32), return just that one IP.
    - For larger blocks, use .hosts() to skip network/broadcast.
    """
    net = ipaddress.ip_network(block, strict=False)  # parse input as a network
    if net.num_addresses == 1:  # e.g., '127.0.0.1' -> /32
        return [str(net.network_address)]
    return [str(ip) for ip in net.hosts()]  # iterate usable host IPs


def discover_live_hosts(block: str) -> list[str]:
    """
    Return IPs that appear alive (TCP connect() returns 0 or ECONNREFUSED)
    """
    ips = expand_ips(block)
    alive: list[str] = []
    for ip in ips:
        if is_host_up_socket(ip):
            alive.append(ip)
    return alive


def scan_udp_once(target_ip: str, port: int, payload: bytes | None = None, timeout: float = 1.0) -> tuple[str, str | None]:
    """
    Probe a UDP port once.
    Returns (status, reply_text or None) where status is one of:
        - "open"            -> a reply datagram was received
        - "closed"          -> ICMP port unreachable (ECONNREFUSED)
        -"open|filtered"    -> no reply (timeout or dropped)
    """
    if payload is None:
        payload = b"\x00"  # tiny, harmless datagram

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            try:
                s.send(payload)
            except OSError:
                # ignore send issues; still try to read
                pass

            try:
                data = s.recv(1024)
                if not data:
                    return "open", None
                return "open", data.decode(errors="ignore").strip()
            except socket.timeout:
                return "open|filtered", None
            except OSError as e:
                # Many OSes report ICMP Port Unreachable as ECONNREFUSED
                if getattr(e, "errno", None) == errno.ECONNREFUSED:
                    return "closed", None
                return "open|filtered", None

    except OSError:
        # couldn't set up the socket/peer cleanly
        return "open|filtered", None


def scan_tcp_range(target_ip: str, low: int, high: int) -> list[int]:
    """
    Scan a TCP port range and print only open results.
    Returns the list of open TCP ports.
    """
    open_udp: list[int] = []
    for port in range(low, high + 1):
        is_open, banner = check_port_with_banner(target_ip, port)
        if is_open:
            line = f"OPEN   tcp/{port}"
            fl = first_line(banner)
            print(line if not fl else f"{line}  |  {fl}")
            open_udp.append((port, fl))
    return open_udp


def scan_tcp_range_threaded(target_ip: str, low: int, high: int, workers: int = MAX_WORKERS) -> list[tuple[int, str]]:
    """
    Concurrently scan [low, high] TCP ports.
    Prints OPEN lines (with first banner line) in sorted order.
    Returns rows suitable for CSV: [(port, banner_first_line), ...]
    """
    def task(port: int) -> tuple[int, str] | None:
        is_open, banner = check_port_with_banner(target_ip, port)
        if not is_open:
            return None
        return (port, first_line(banner))

    # Kick off tasks
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, range(low, high + 1)))

    # Keep only open ports; sort by port
    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])

    # Print clean output
    for port, fl in rows:
        line = f"OPEN   tcp/{port}"
        print(line if not fl else f"{line}  |  {fl}")

    return rows


def scan_udp_range(target_ip: str, low: int, high: int) -> list[int]:
    """
    Scan a UDP port range and print only open results.
    Returns the list of open UDP ports.
    """
    open_rows: list[tuple[int, str]] = []
    for port in range(low, high + 1):
        status, reply = scan_udp_once(target_ip, port, timeout=1.0)
        if status == "open":
            fl = first_line(reply)
            print(
                f"OPEN   udp/{port}" if not fl else f"OPEN   udp/{port}  |  {fl}")
            open_rows.append(port)
        # ignore "closed" and "open|filtered" to keep output clean
    return open_udp


def save_csv(rows: list[tuple[int, str]], target_ip: str, started_iso: str, elapsed_s: float, protocol: str = "tcp") -> str:
    """
    rows: list of (port. banner_first_line)
    Returns the filename written.
    """

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{target_ip}_{ts}.csv"

    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # header
        w.writerow(["target_ip", "protocol", "port",
                   "banner_first_line", "scan_started", "scan_elapsed_s"])
        # rows
        for port, fl in rows:
            w.writerow([target_ip, protocol, port, fl,
                       started_iso, f"{elapsed_s:.2f}"])
    return filename


def main() -> None:
    # ---- input ----
    user_target = input("Enter target (IP or hostname): ").strip()
    try:
        target_ip = resolve_target(user_target)
        print(f"Target resolved to: {target_ip}")
    except ValueError as err:
        print(f"[!] {err}")
        return

    try:
        low, high = parse_port_range(
            input("Enter port range (e.g., 60-120): "))
    except ValueError as err:
        print(f"[!] {err}")
        return

    mode = input("Scan mode (tcp/udp): ").strip().lower()
    if mode not in ("tcp", "udp"):
        print("[!] Please enter 'tcp' or 'udp'.")
        return

    # ---- scan ----
    print(f"[*] Scanning {mode.upper()} ports {low}-{high} on {target_ip} ...")
    start = time.time()
    started_iso = datetime.now().isoformat(timespec="seconds")
    open_count = 0
    results: list[tuple[int, str]] = []

    if mode == "tcp":
        if USE_THREADS:
            rows = scan_tcp_range_threaded(
                target_ip, low, high, workers=MAX_WORKERS)
            open_count = len(rows)
            if rows:
                out_file = save_csv(
                    rows, target_ip, started_iso, time.time() - start)
                print(f"[*] Results saved to {out_file}")

        else:
            open_ports = scan_tcp_range(target_ip, low, high)
    else:
        open_ports = scan_udp_range(target_ip, low, high)

    open_count = len(open_ports)
    elapsed = time.time() - start
    total = high - low + 1
    if open_count == 0:
        print("No open {mode.upper()} ports in this range.")
    if results:
        out_file = save_csv(results, target_ip, started_iso, elapsed)
        print(f"[*] Results saved to {out_file}")

    print(
        f"[*] Done in {elapsed:.2f}s - scanned {total} {mode.upper()} ports - found {open_count} open.")


if __name__ == "__main__":
    main()

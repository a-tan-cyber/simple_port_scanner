#!/usr/bin/env python3

import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time         # to measure scan duration
import socket       # to create network connections
import re           # for regular expressions, to validate user input port ranges
import ipaddress    # to validate user input IP addresses
import errno
import csv

print("\n=== Simple Network Scanner ===")
print("by Tan Amos, Oct 2025\n")

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


if sys.version_info < (3, 10):
    print("[!] Python 3.10+ required.", flush=True)
    raise SystemExit(1)

single_port_or_range = re.compile(r"^\s*(\d+)\s*(?:-\s*(\d+)\s*)?$")

BANNER_TIMEOUT: float = 2.0
TCP_CONNECT_TIMEOUT: float = 0.5
UDP_TIMEOUT: float = 1.0

HTTP_BANNER_PORTS: tuple[int, ...] = (80, 8080, 8000)
COMMON_TCP_PORTS: tuple[int, ...] = (80, 443, 22, 8080, 8000, 3389)
CUSTOM_SERVICES_TCP: dict[int, str] = {
    80: "http",
    8000: "http",
    8080: "http-alt",
}
CUSTOM_SERVICES_UDP: dict[int, str] = {
    53: "domain",
}


MAX_HOSTS: int = 4096
MAX_WORKERS: int = 100


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        print("\n[!] No input available. Exiting.", flush=True)
        raise SystemExit(1)


def prompt_discovery_block() -> str | None:
    """
    Ask for an IP or CIDR. Blank (ENTER/whitespace) returns None to skip discovery.
    Otherwise, keep prompting until a valid (and not-too-large) network is entered.
    """
    while True:
        block = ask(
            "Enter IP or CIDR (e.g., '127.0.0.1' or '192.168.1.0/30') [ENTER to skip]: ").strip()
        if not block:
            return None
        try:
            # Validate format
            net = ipaddress.ip_network(block, strict=False)
            if net.version != 4:
                print(
                    "[!] IPv6 networks are not supported. Enter an IPv4 network, or press ENTER to skip.", flush=True)
                continue
            if net.num_addresses > MAX_HOSTS + 2:  # +2 includes network/broadcast
                print(f"[!] Network too large ({net.num_addresses} addresses). "
                      f"Max is {MAX_HOSTS}. Try a smaller block, or press ENTER to skip.", flush=True)
                continue
            return block
        except ValueError as err:
            print(f"[!] {err}. Try again, or press ENTER to skip.", flush=True)


def prompt_target_ip() -> tuple[str, str | None]:
    """
    Prompt for IP/hostname until valid.
    Returns (target_ip, target_name) where target_name is the original hostname
    if the user entered a hostname; otherwise None.
    """
    while True:
        user_target = ask("Enter target (IP or hostname): ").strip()
        try:
            target_ip = resolve_target(user_target)
            print(f"Target resolved to: {target_ip}", flush=True)
            # If original input was an IP, leave name as None; else keep hostname
            try:
                ipaddress.ip_address(user_target)
                target_name = None
            except ValueError:
                target_name = user_target
            return target_ip, target_name
        except ValueError as err:
            print(f"[!] {err}. Try again.", flush=True)


def prompt_port_range() -> tuple[int, int]:
    while True:
        s = ask("Enter port or range (e.g., 443 or 60-120): ").strip()
        try:
            return parse_port_range(s)
        except ValueError as err:
            print(f"[!] {err}. Try again.", flush=True)


def prompt_mode() -> str:
    while True:
        mode = ask("Scan mode (tcp/udp): ").strip().lower()
        if mode in ("tcp", "udp"):
            return mode
        print("[!] Please enter 'tcp' or 'udp'. Try again.", flush=True)


def prompt_threads(port_count: int) -> tuple[bool, int]:
    use_threads = ask("Use threads? (y/n): ").strip().lower().startswith("y")
    workers = MAX_WORKERS
    if use_threads:
        while True:
            workers_in = ask(
                f"Workers (press ENTER for default {MAX_WORKERS}): ").strip()
            if not workers_in:
                workers = MAX_WORKERS
                break
            try:
                w = int(workers_in)
                if w > 0:
                    if w > port_count:
                        print(f"[*] Note: only {port_count} ports to scan; "
                              f"effective workers will be {port_count}.", flush=True)
                    workers = w
                    break
            except ValueError:
                pass
            print("[!] Invalid worker count. Enter a positive integer.", flush=True)
    return use_threads, workers


def select_hosts(live: list[str]) -> list[str]:
    """
    Show all discovered live hosts and let the user pick any combination,
    including ranges like '1-4,7,9' (or 'all'). No restriction on already
    scanned hosts.
    """
    if not live:
        print("[*] No live hosts to select.", flush=True)
        return []

    print("[*] Live hosts:")
    for i, ip in enumerate(live, 1):
        print(f"  {i}. {ip}", flush=True)

    while True:
        sel = ask("Select hosts (e.g., 1-3,5 or 'all'): ").strip()
        try:
            idxs = parse_index_list(sel, len(live))
            return [live[i - 1] for i in idxs]
        except (ValueError, TypeError):
            print("[!] Invalid selection. Try again.", flush=True)


def parse_port_range(s: str) -> tuple[int, int]:
    m = single_port_or_range.match(s)
    if not m:
        raise ValueError(
            "Use 'low-high' (e.g., 60-120) or a single port (e.g., 443)")
    low = int(m.group(1))
    high = int(m.group(2)) if m.group(2) else low
    if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
        raise ValueError("Ports must be 1–65535 and low <= high.")
    return low, high


def resolve_target(user_input: str) -> str:
    """Return an IPv4 address string from either an IP or a hostname."""
    # 1) If it is already a valid IP, just use it.
    try:
        # raises ValueError if not a valid IP
        ip = ipaddress.ip_address(user_input)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.version != 4:
            raise ValueError(
                "IPv6 addresses are not supported by this scanner.")
        return str(ip)

    # 2) Otherwise, resolve hostname to IPv4
    try:
        return socket.gethostbyname(user_input)  # DNS (or /etc/hosts) lookup
    except socket.gaierror as e:                # gaierror: get address info error
        # "as e" and "from e": Preserve the root cause of error in traceback for debugging
        raise ValueError(
            "Could not resolve hostname to an IPv4 address.") from e


def scan_tcp_once(target_ip: str, port: int, *, timeout: float = TCP_CONNECT_TIMEOUT) -> bool:
    # AF_INET: IPv4; SOCK_STREAM: TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # to prevent hanging forever
        s.settimeout(timeout)
        # try to connect; 0 = success, non-zero = error
        result = s.connect_ex((target_ip, port))
        return result == 0                          # True = open, False = not open


def grab_banner(target_ip: str, port: int, timeout: float = BANNER_TIMEOUT) -> str | None:
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
                if port in HTTP_BANNER_PORTS:
                    # send a safe HTTP request
                    req = f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                    s.sendall(req.encode())
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
    Returns (is_open, banner_or_None).
    """
    # 1) Use the simple TCP check
    is_open = scan_tcp_once(target_ip, port, timeout=TCP_CONNECT_TIMEOUT)

    # 2) If open, try to read a banner (may still be None if service is quiet)
    banner = grab_banner(
        target_ip, port, timeout=BANNER_TIMEOUT) if is_open else None

    # 3) Hand both results back to the caller
    return is_open, banner


def first_line(text: str | None) -> str:
    """Return the first line of a banner (or '' if None)."""
    if not text:
        return ""
    return text.splitlines()[0]


def is_host_up_socket(ip: str, timeout: float = TCP_CONNECT_TIMEOUT) -> bool:
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
    if net.version != 4:
        raise ValueError("IPv6 addresses are not supported by this scanner.")
    if net.num_addresses > MAX_HOSTS + 2:  # +2 for network/broadcast
        raise ValueError(
            f"Network too large ({net.num_addresses} addresses). Try a smaller block.")
    if net.num_addresses == 1:  # e.g., '127.0.0.1' -> /32
        return [str(net.network_address)]
    return [str(ip) for ip in net.hosts()]  # iterate usable host IPs


def discover_live_hosts(block: str) -> list[str]:
    """
    Return IPs that appear alive (TCP connect() returns 0 or ECONNREFUSED)
    """
    ips = expand_ips(block)
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=min(len(ips), MAX_WORKERS)) as ex:
        results = list(ex.map(is_host_up_socket, ips, chunksize=64))
    for ip, ok in zip(ips, results):
        if ok:
            alive.append(ip)
    return alive


def scan_udp_once(target_ip: str, port: int, payload: bytes | None = None, timeout: float = UDP_TIMEOUT) -> tuple[str, str | None]:
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


def svc_name(port: int, proto: str) -> str | None:
    if proto == "tcp" and port in CUSTOM_SERVICES_TCP:
        return CUSTOM_SERVICES_TCP[port]
    if proto == "udp" and port in CUSTOM_SERVICES_UDP:
        return CUSTOM_SERVICES_UDP[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


def scan_tcp_range(target_ip: str, low: int, high: int) -> list[tuple[int, str | None, str]]:
    """
    Scan a TCP port range and print only OPEN results.
    Returns rows: [(port, service, banner_first_line), ...]
    """
    rows: list[tuple[int, str | None, str]] = []
    for port in range(low, high + 1):
        is_open, banner = check_port_with_banner(target_ip, port)
        if is_open:
            svc = svc_name(port, "tcp")
            fl = first_line(banner)
            line = f"OPEN   tcp/{port}" + (f" ({svc})" if svc else "")
            print(line if not fl else f"{line}  |  {fl}", flush=True)
            rows.append((port, svc, fl))
    return rows


def scan_tcp_range_threaded(target_ip: str, low: int, high: int, workers: int = MAX_WORKERS) -> list[tuple[int, str | None, str]]:
    """
    Concurrently scan [low, high] TCP ports.
    Prints OPEN lines (with first banner line) in sorted order.
    Returns rows: [(port, service, banner_first_line), ...]
    """
    def task(port: int) -> tuple[int, str | None, str] | None:
        is_open, banner = check_port_with_banner(target_ip, port)
        if not is_open:
            return None
        return (port, svc_name(port, "tcp"), first_line(banner))

    # Kick off tasks
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, range(low, high + 1), chunksize=64))

    # Keep only open ports; sort by port
    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])

    # Print clean output
    for port, svc, fl in rows:
        line = f"OPEN   tcp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)

    return rows


def scan_udp_range(target_ip: str, low: int, high: int) -> list[tuple[int, str | None, str]]:
    """
    Scan a UDP port range and print only OPEN results.
    Returns rows: [(port, service, banner_first_line), ...]
    """
    rows: list[tuple[int, str | None, str]] = []
    for port in range(low, high + 1):
        status, reply = scan_udp_once(target_ip, port, timeout=UDP_TIMEOUT)
        if status == "open":
            svc = svc_name(port, "udp")
            fl = first_line(reply)
            line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
            print(line if not fl else f"{line}  |  {fl}", flush=True)
            rows.append((port, svc, fl))
        # ignore "closed" and "open|filtered" to keep output clean
    return rows


def scan_udp_range_threaded(target_ip: str, low: int, high: int, workers: int = MAX_WORKERS) -> list[tuple[int, str | None, str]]:
    """
    Concurrently scan [low, high] UDP ports.
    Prints OPEN lines (with first banner line) in sorted order.
    Returns rows: [(port, service, banner_first_line), ...]
    """
    def task(port: int) -> tuple[int, str | None, str] | None:
        status, reply = scan_udp_once(target_ip, port, timeout=UDP_TIMEOUT)
        if status != "open":
            return None
        return (port, svc_name(port, "udp"), first_line(reply))

    # Kick off tasks
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, range(low, high + 1), chunksize=64))

    # Keep only open ports; sort by port
    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])

    # Print clean output
    for port, svc, fl in rows:
        line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)

    return rows


def save_csv(rows: list[tuple[int, str | None, str]], target_ip: str, started_iso: str, elapsed_s: float, protocol: str = "tcp", target_name: str | None = None) -> str:
    """
    rows: list of (port, service, banner_first_line)
    Returns the filename written.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^A-Za-z0-9._-]+', '_', (target_name or '').strip())
    filename = f"scan_{target_ip}{('_' + safe_name) if safe_name else ''}_{ts}.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            # header
            w.writerow(["target_ip", "target_name", "protocol", "port", "service",
                        "banner_first_line", "scan_started", "scan_elapsed_s"])
            # rows
            for port, svc, fl in rows:
                w.writerow([target_ip, (target_name or ""), protocol, port, (svc or ""), fl,
                            started_iso, f"{elapsed_s:.2f}"])
    except OSError as e:
        print(f"[!] Could not write results to '{filename}': {e}", flush=True)
        return "(write_failed)"
    return filename


def run_scan_for_target(target_ip: str, low: int, high: int, mode: str, use_threads: bool, workers: int, target_name: str | None = None) -> None:
    label = f"{target_ip}" if not target_name else f"{target_ip} ({target_name})"
    print(
        f"[*] Scanning {mode.upper()} ports {low}-{high} on {label} ...", flush=True)
    start = time.perf_counter()
    started_iso = datetime.now().isoformat(timespec="seconds")

    # Clamp worker count to number of tasks (ports) and to at least 1
    if use_threads:
        total_tasks = max(1, high - low + 1)
        workers = max(1, min(workers, total_tasks))

    if mode == "tcp":
        rows = (scan_tcp_range_threaded(target_ip, low, high, workers)
                if use_threads else
                scan_tcp_range(target_ip, low, high))
        protocol = "tcp"
    else:  # udp
        rows = (scan_udp_range_threaded(target_ip, low, high, workers)
                if use_threads else
                scan_udp_range(target_ip, low, high))
        protocol = "udp"

    elapsed = time.perf_counter() - start
    total = high - low + 1

    if not rows:
        print(f"No open {mode.upper()} ports in this range.", flush=True)
    else:
        out_file = save_csv(rows, target_ip, started_iso,
                            elapsed, protocol=protocol, target_name=target_name)
        print(f"[*] Results saved to {out_file}", flush=True)

    print(
        f"[*] Done in {elapsed:.2f}s - scanned {total} {mode.upper()} ports - found {len(rows)} open.", flush=True)


def reverse_dns(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, OSError):
        return None


def choose_scan_params() -> tuple[int, int, str, bool, int]:
    low, high = prompt_port_range()
    mode = prompt_mode()
    use_threads, workers = prompt_threads(high - low + 1)
    return low, high, mode, use_threads, workers


def parse_index_list(expr: str, max_n: int) -> list[int]:
    """
    Parse selections like '1-4,7,9' or '3,2,5-6' into 1-based indices.
    Ranges can go up or down (e.g., '4-1'). Returns unique indices in the
    order first mentioned. Raises ValueError on bad input.
    """
    expr = expr.strip().lower()
    if expr in ("a", "all", "*"):
        return list(range(1, max_n + 1))

    tokens = [t.strip() for t in re.split(r"[,\s]+", expr) if t.strip()]
    if not tokens:
        raise ValueError("empty selection")

    raw: list[int] = []
    for tok in tokens:
        m = re.fullmatch(r"(\d+)-(\d+)", tok)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if not (1 <= a <= max_n and 1 <= b <= max_n):
                raise ValueError("range out of bounds")
            step = 1 if a <= b else -1
            raw.extend(list(range(a, b + step, step)))
        else:
            i = int(tok)
            if not (1 <= i <= max_n):
                raise ValueError("index out of bounds")
            raw.append(i)

    # de-duplicate while preserving order
    out: list[int] = []
    seen: set[int] = set()
    for i in raw:
        if i not in seen:
            out.append(i)
            seen.add(i)
    return out


def main() -> None:
    # ---- optional live-host discovery ----
    use_discovery = ask(
        "Discover live hosts first? (y/n): ").strip().lower().startswith("y")
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
                print("[*] No live hosts found in that block.", flush=True)
                choice = ask(
                    "Try discovery again (t) or proceed with manual target entry (m)? [t/m]: ").strip().lower()
                if choice.startswith("t"):
                    # loop back and ask for another block (or ENTER to skip)
                    continue
                else:
                    # proceed to manual path (leave live empty)
                    live = []
                    break

            # We found at least one live host; report and continue as before
            if len(live) == 1:
                preselected_target = live[0]
                preselected_name = reverse_dns(preselected_target)
                if preselected_name:
                    print(
                        f"[*] Found 1 live host: {preselected_target} ({preselected_name})", flush=True)
                else:
                    print(
                        f"[*] Found 1 live host: {preselected_target}", flush=True)
            else:
                print(f"[*] Found {len(live)} live hosts.", flush=True)
            break  # exit the retry loop since we had success

    if preselected_target:
        target_ip = preselected_target
        print(
            f"Target selected: {target_ip}" +
            (f" ({preselected_name})" if preselected_name else ""),
            flush=True
        )
        while True:
            low, high, mode, use_threads, workers = choose_scan_params()
            run_scan_for_target(
                target_ip, low, high, mode, use_threads, workers, preselected_name
            )
            if not ask(
                "Scan the same discovered host again with different settings? (y/n): "
            ).strip().lower().startswith("y"):
                break
        return

    if live and len(live) > 1:
        # multi-host selection loop (can rescan any host anytime)
        while True:
            to_scan = select_hosts(live)
            if not to_scan:
                break

            # choose scan parameters once for this batch
            low, high, mode, use_threads, workers = choose_scan_params()

            for ip in to_scan:
                name = reverse_dns(ip)
                if name:
                    print(f"Target selected: {ip} ({name})", flush=True)
                else:
                    print(f"Target selected: {ip}", flush=True)

                run_scan_for_target(ip, low, high, mode,
                                    use_threads, workers, name)

            if not ask("Scan more hosts from the list? (y/n): ").strip().lower().startswith("y"):
                break
        return

    # --- manual target path ----
    target_ip, target_name = prompt_target_ip()
    while True:
        low, high, mode, use_threads, workers = choose_scan_params()
        run_scan_for_target(target_ip, low, high, mode,
                            use_threads, workers, target_name)
        if not ask("Scan the same host again with different settings? (y/n): ").strip().lower().startswith("y"):
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting cleanly.", flush=True)

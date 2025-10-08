#!/usr/bin/env python3
"""
Simple Network Scanner

Author: Tan Amos (s22)
Institute: Centre for Cybersecurity
Class: CCK3_250714
Trainer: Samson
Date: Oct 2025

Features:
- Optional live-host discovery (IPv4)
- TCP/UDP port scanning (single or range)
- Banners for open TCP ports
- Multi-threaded scanning
- CSV output
"""

from __future__ import annotations

import csv
import errno
import ipaddress
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ----------------------------- Runtime Requirements -----------------------------

if sys.version_info < (3, 10):
    print("[!] Python 3.10+ required.", flush=True)
    raise SystemExit(1)

# --------------------------------- Constants -----------------------------------

PORT_RANGE_RE = re.compile(r"^\s*(\d+)\s*(?:-\s*(\d+)\s*)?$")

BANNER_TIMEOUT: float = 2.0
TCP_CONNECT_TIMEOUT: float = 0.5
UDP_TIMEOUT: float = 1.0

HTTP_BANNER_PORTS: tuple[int, ...] = (80, 8080, 8000, 3128)
COMMON_TCP_PORTS: tuple[int, ...] = (
    22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3128, 3389, 5900, 8000, 8080)

# Prefer our custom names over /etc/services
CUSTOM_SERVICES_TCP: dict[int, str] = {
    21: "ftp",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    445: "microsoft-ds",
    3128: "http-proxy",
    3389: "ms-wbt-server",  # RDP
    5900: "vnc",
    8000: "http",
    8080: "http-alt",
}
CUSTOM_SERVICES_UDP: dict[int, str] = {
    53: "domain",
}

MAX_HOSTS: int = 4096
MAX_WORKERS: int = 100

CHUNKSIZE = 64

# ------------------------------ Prompt Utilities -------------------------------


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        print("\n[!] No input available. Exiting.", flush=True)
        raise SystemExit(1)


def prompt_discovery_block() -> str | None:
    """Ask for an IPv4 (single IP or CIDR). ENTER returns None to skip."""
    while True:
        block = ask(
            "Enter IP or CIDR (e.g., '127.0.0.1' or '192.168.1.0/30') [ENTER to skip]: "
        ).strip()
        if not block:
            return None
        try:
            net = ipaddress.ip_network(block, strict=False)
            if net.version != 4:
                print(
                    "[!] IPv6 not supported. Enter IPv4 or press ENTER.", flush=True)
                continue
            if net.num_addresses > MAX_HOSTS + 2:
                print(
                    f"[!] Network too large ({net.num_addresses}). Max {MAX_HOSTS}.", flush=True)
                continue
            return block
        except ValueError as err:
            print(f"[!] {err}. Try again, or press ENTER to skip.", flush=True)


def prompt_target_ip() -> tuple[str, str | None]:
    """
    Prompt until IP/hostname resolves.
    Returns (target_ip, target_name) where target_name is:
      - the original hostname if the user entered a hostname, or
      - the reverse-DNS name if the user entered an IP and rDNS exists, else None.
    """
    while True:
        user_target = ask("Enter target (IP or hostname): ").strip()
        try:
            target_ip = resolve_target(user_target)

            try:
                # User typed an IP
                ipaddress.ip_address(user_target)
                rdns = reverse_dns(target_ip)
                if rdns:
                    print(f"Target: {target_ip} ({rdns})", flush=True)
                    target_name = rdns
                else:
                    print(f"Target: {target_ip}", flush=True)
                    target_name = None
            except ValueError:
                # User typed a hostname
                rdns = reverse_dns(target_ip)
                if rdns and rdns.lower() != user_target.lower():
                    print(
                        f"Target resolved to: {target_ip} (rDNS: {rdns})", flush=True)
                else:
                    print(f"Target resolved to: {target_ip}", flush=True)
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


def prompt_threads(task_count: int, context: str = "scanning", noun: str = "ports") -> tuple[bool, int]:
    """
    Generic threads prompt for both port scanning and host discovery.

    Args:
      task_count: number of independent tasks (e.g., #ports or #hosts)
      context: text to show in the prompt, e.g. "scanning" or "discovery"
      noun: what we're parallelizing over, e.g. "ports" or "hosts"
    """
    # If there's only one task, threading can't help; skip the prompt.
    if task_count <= 1:
        return False, 1

    use_threads = ask(
        f"Use threads for {context}? (y/n): ").strip().lower().startswith("y")
    if not use_threads:
        return False, 1

    cap = max(1, min(task_count, MAX_WORKERS))
    while True:
        s = ask(
            f"{context.capitalize()} workers (1-{cap}) [ENTER for {cap}]: ").strip()
        if not s:
            return True, cap
        try:
            w = int(s)
            if 1 <= w <= cap:
                return True, w
            print(
                f"[!] Worker count must be between 1 and {cap}. Try again.", flush=True)
        except ValueError:
            print("[!] Invalid worker count. Enter a positive integer.", flush=True)


def choose_scan_params() -> tuple[int, int, str, bool, int]:
    low, high = prompt_port_range()
    mode = prompt_mode()
    use_threads, workers = prompt_threads(high - low + 1)
    print()  # spacer
    return low, high, mode, use_threads, workers


def show_live_hosts(live: list[str], *, with_names: bool = False) -> None:
    print("[*] Live hosts:", flush=True)
    if live:
        if with_names:
            # resolve names (best-effort; don’t block discovery speed with long lookups)
            with ThreadPoolExecutor(max_workers=min(len(live), 50)) as ex:
                names = list(ex.map(reverse_dns, live, chunksize=CHUNKSIZE))
            for i, (ip, name) in enumerate(zip(live, names), 1):
                label = f"{ip} ({name})" if name else ip
                print(f"  {i}. {label}", flush=True)
        else:
            for i, ip in enumerate(live, 1):
                print(f"  {i}. {ip}", flush=True)
    else:
        print("  (none)", flush=True)


def select_hosts(live: list[str], *, show_list: bool = False) -> list[str]:
    """Prompt for a selection of live hosts; accept selections like '1-3,5', and return the chosen IPs"""
    if not live:
        print("[*] No live hosts to select.", flush=True)
        return []

    if show_list:
        show_live_hosts(live, with_names=True)

    while True:
        sel = ask("Select hosts (e.g., 1-3,5 or 'all'): ").strip()
        try:
            idxs = parse_index_list(sel, len(live))
            return [live[i - 1] for i in idxs]
        except (ValueError, TypeError):
            print("[!] Invalid selection. Try again.", flush=True)

# ------------------------------ Parsing Helpers --------------------------------


def parse_port_range(s: str) -> tuple[int, int]:
    m = PORT_RANGE_RE.match(s)
    if not m:
        raise ValueError(
            "Use 'low-high' (e.g., 60-120) or a single port (e.g., 443)")
    low = int(m.group(1))
    high = int(m.group(2)) if m.group(2) else low
    if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
        raise ValueError("Ports must be 1–65535 and low <= high.")
    return low, high


def parse_index_list(expr: str, max_n: int) -> list[int]:
    """
    Parse selections like '1-4,7,9' or '3,2,5-6' into 1-based indices.
    Supports reversed ranges (e.g., '4-1'). De-dupes in first-seen order.
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
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version != 4:
            raise ValueError(
                "IPv6 addresses are not supported by this scanner.")
        return str(ip)
    try:
        return socket.gethostbyname(user_input)
    except socket.gaierror as e:
        raise ValueError(
            "Could not resolve hostname to an IPv4 address.") from e


def reverse_dns(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".")
    except (socket.herror, OSError):
        return None


def is_host_up(ip: str, timeout: float = TCP_CONNECT_TIMEOUT) -> bool:
    """
    Consider host 'up' if any TCP connect_ex returns 0 (open) or ECONNREFUSED (closed but reachable).
    """
    refused_codes = {errno.ECONNREFUSED}
    if sys.platform.startswith("win"):
        refused_codes.add(10061)  # WSAECONNREFUSED on Windows

    for port in COMMON_TCP_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                rc = s.connect_ex((ip, port))
                if rc == 0 or rc in refused_codes:
                    return True
        except OSError:
            pass
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
            results = list(ex.map(is_host_up, ips, chunksize=CHUNKSIZE))
    else:
        results = [is_host_up(ip) for ip in ips]

    alive = [ip for ip, ok in zip(ips, results) if ok]
    alive.sort(key=lambda ip: tuple(int(o) for o in ip.split('.')))
    show_live_hosts(alive, with_names=True)

    elapsed = time.perf_counter() - start
    print(
        f"[*] Discovery finished: {len(alive)}/{task_count} hosts alive in {elapsed:.2f}s.\n", flush=True)
    return alive


# ------------------------------ Scan Primitives --------------------------------


def scan_tcp_once(target_ip: str, port: int, *, timeout: float = TCP_CONNECT_TIMEOUT) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((target_ip, port)) == 0


def grab_banner(target_ip: str, port: int, timeout: float = BANNER_TIMEOUT) -> str | None:
    """Connect and try to coax a short banner from a TCP service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            try:
                if port in HTTP_BANNER_PORTS:
                    req = f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                    s.sendall(req.encode())
                else:
                    s.sendall(b"\r\n")
            except OSError:
                pass
            try:
                data = s.recv(1024)
            except socket.timeout:
                return None
            if not data:
                return None
            return data.decode(errors="ignore").strip()
    except OSError:
        return None


def check_port_with_banner(target_ip: str, port: int) -> tuple[bool, str | None]:
    is_open = scan_tcp_once(target_ip, port, timeout=TCP_CONNECT_TIMEOUT)
    banner = grab_banner(
        target_ip, port, timeout=BANNER_TIMEOUT) if is_open else None
    return is_open, banner


def first_line(text: str | None) -> str:
    return "" if not text else text.splitlines()[0]


def scan_udp_once(target_ip: str, port: int, payload: bytes | None = None, timeout: float = UDP_TIMEOUT) -> tuple[str, str | None]:
    """
    Returns:
      "open" -> reply received (with optional text)
      "closed" -> ICMP port unreachable (ECONNREFUSED)
      "open|filtered" -> no reply (timeout/dropped)
    """
    if payload is None:
        payload = b"\x00"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            try:
                s.send(payload)
            except OSError:
                pass
            try:
                data = s.recv(1024)
                if not data:
                    return "open", None
                return "open", data.decode(errors="ignore").strip()
            except socket.timeout:
                return "open|filtered", None
            except ConnectionRefusedError:
                # POSIX: ICMP port unreachable
                return "closed", None
            except ConnectionResetError as e:
                # Windows: ICMP port unreachable -> WSAECONNRESET (10054)
                if getattr(e, "winerror", None) == 10054:
                    return "closed", None
                return "open|filtered", None
            except OSError as e:
                if getattr(e, "errno", None) == errno.ECONNREFUSED:
                    return "closed", None
                return "open|filtered", None
    except OSError:
        return "open|filtered", None

# ---------------------------- Scan Range Functions -----------------------------


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


def scan_tcp_range_threaded(
    target_ip: str, low: int, high: int, workers: int = MAX_WORKERS
) -> list[tuple[int, str | None, str]]:
    def task(port: int) -> tuple[int, str | None, str] | None:
        is_open, banner = check_port_with_banner(target_ip, port)
        if not is_open:
            return None
        return (port, svc_name(port, "tcp"), first_line(banner))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, range(low, high + 1), chunksize=CHUNKSIZE))

    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])
    for port, svc, fl in rows:
        line = f"OPEN   tcp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)
    return rows


def scan_udp_range(target_ip: str, low: int, high: int) -> list[tuple[int, str | None, str]]:
    rows: list[tuple[int, str | None, str]] = []
    for port in range(low, high + 1):
        status, reply = scan_udp_once(target_ip, port, timeout=UDP_TIMEOUT)
        if status == "open":
            svc = svc_name(port, "udp")
            fl = first_line(reply)
            line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
            print(line if not fl else f"{line}  |  {fl}", flush=True)
            rows.append((port, svc, fl))
    return rows


def scan_udp_range_threaded(
    target_ip: str, low: int, high: int, workers: int = MAX_WORKERS
) -> list[tuple[int, str | None, str]]:
    def task(port: int) -> tuple[int, str | None, str] | None:
        status, reply = scan_udp_once(target_ip, port, timeout=UDP_TIMEOUT)
        if status != "open":
            return None
        return (port, svc_name(port, "udp"), first_line(reply))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(task, range(low, high + 1), chunksize=CHUNKSIZE))

    rows = [r for r in results if r is not None]
    rows.sort(key=lambda t: t[0])
    for port, svc, fl in rows:
        line = f"OPEN   udp/{port}" + (f" ({svc})" if svc else "")
        print(line if not fl else f"{line}  |  {fl}", flush=True)
    return rows

# --------------------------------- Output -------------------------------------


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
    filename = f"scan_{target_ip}{('_' + safe_name) if safe_name else ''}_{ts}.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(
                ["target_ip", "target_name", "protocol", "port", "service",
                 "banner_first_line", "scan_started", "scan_elapsed_s"]
            )
            for port, svc, fl in rows:
                w.writerow(
                    [target_ip, (target_name or ""), protocol, port,
                     (svc or ""), fl, started_iso, f"{elapsed_s:.2f}"]
                )
    except OSError as e:
        print(f"[!] Could not write results to '{filename}': {e}", flush=True)
        return "(write_failed)"
    return filename


def run_scan_for_target(
    target_ip: str,
    low: int,
    high: int,
    mode: str,
    use_threads: bool,
    workers: int,
    target_name: str | None = None,
) -> None:
    label = f"{target_ip}" if not target_name else f"{target_ip} ({target_name})"
    print(f"Target selected: {label}", flush=True)
    port_count = max(1, high - low + 1)

    start = time.perf_counter()
    started_iso = datetime.now().isoformat(timespec="seconds")

    if use_threads:
        if port_count == 1:
            use_threads = False  # force single-thread path
        else:
            workers = max(1, min(workers, port_count, MAX_WORKERS))

    eff_concurrency = (
        f"with {workers} thread(s)" if use_threads else "without threading")
    print(
        f"[*] Scanning {mode.upper()} ports {low}-{high} on {label} {eff_concurrency}...", flush=True)

    if mode == "tcp":
        protocol = "tcp"
        rows = scan_tcp_range_threaded(
            target_ip, low, high, workers) if use_threads else scan_tcp_range(target_ip, low, high)
    else:
        protocol = "udp"
        rows = scan_udp_range_threaded(
            target_ip, low, high, workers) if use_threads else scan_udp_range(target_ip, low, high)

    elapsed = time.perf_counter() - start
    total = high - low + 1

    if not rows:
        print(f"No open {mode.upper()} ports in this range.", flush=True)
    else:
        out_file = save_csv(rows, target_ip, started_iso,
                            elapsed, protocol=protocol, target_name=target_name)
        print(f"[*] Results saved to {out_file}", flush=True)

    print(
        f"[*] Done in {elapsed:.2f}s - scanned {total} {mode.upper()} ports - found {len(rows)} open.\n", flush=True)

# ----------------------------------- Main --------------------------------------


def main() -> None:
    print("\n=== Simple Network Scanner ===")
    print("by Tan Amos, Oct 2025\n")

    # optional live-host discovery
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
                preselected_name = reverse_dns(preselected_target)
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
            low, high, mode, use_threads, workers = choose_scan_params()
            run_scan_for_target(target_ip, low, high, mode,
                                use_threads, workers, preselected_name)
            if not ask("Scan the same discovered host again with different settings? (y/n): ").strip().lower().startswith("y"):
                break
        return

    # multiple discovered hosts path
    if live and len(live) > 1:
        first_prompt = True
        while True:
            to_scan = select_hosts(live, show_list=not first_prompt)
            if not to_scan:
                break

            low, high, mode, use_threads, workers = choose_scan_params()

            for ip in to_scan:
                name = reverse_dns(ip)
                run_scan_for_target(ip, low, high, mode,
                                    use_threads, workers, name)

            first_prompt = False
            if not ask("Scan more hosts from the list? (y/n): ").strip().lower().startswith("y"):
                break
        return

    # manual path
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

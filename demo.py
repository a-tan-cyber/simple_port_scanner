#! /usr/bin/env python3

import socket

def demo_tcp_probe(host, port, timeout=1.0):
    print(f"[1] DNS: resolving {host} ...")
    ip = socket.gethostbyname(host)
    print(f"    -> IP = {ip}")

    print("[2] Creating an IPv4/TCP socket")
    s = socket.socket(socket.AF_INET, )
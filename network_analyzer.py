#!/usr/bin/env python3
"""
Simple network analyzer / port scanner using Python sockets.

Features:
- Scan single host or CIDR subnet
- TCP connect scan for a port range or list
- Basic banner grabbing and simple service probes (HTTP HEAD, simple text probes)
- Concurrent scanning with threads

Usage examples are in README.md
"""
import argparse
import socket
import concurrent.futures
import ipaddress
import ssl
import json
import re
import time
import sys
from typing import List, Dict, Tuple, Any

SERVICE_PROBES = {
    80: "HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8080: "HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    443: "HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    21: "\r\n",
    22: "\r\n",
    25: "HELO example.com\r\n",
    110: "\r\n",
    143: "\r\n",
}

COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    3389: "rdp",
}


def parse_targets(s: str) -> List[str]:
    s = s.strip()
    if "/" in s:
        net = ipaddress.ip_network(s, strict=False)
        return [str(h) for h in net.hosts()]
    if "," in s:
        parts = [p.strip() for p in s.split(",") if p.strip()]
        out = []
        for p in parts:
            out.extend(parse_targets(p))
        return out
    return [s]


def parse_ports(s: str) -> List[int]:
    s = s.strip()
    if not s:
        return list(range(1, 1025))
    parts = [p.strip() for p in s.split(",") if p.strip()]
    out = set()
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(p))
    return sorted(out)


def probe_service(sock: socket.socket, host: str, port: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    data = b""
    try:
        # attempt to receive banner without sending
        data = sock.recv(1024)
    except Exception:
        data = b""

    if data:
        return data

    probe = SERVICE_PROBES.get(port)
    if probe:
        try:
            tosend = probe.format(host=host)
            sock.sendall(tosend.encode())
            data = sock.recv(2048)
            return data
        except Exception:
            return b""
    return b""


def detect_version(host: str, port: int, banner: str) -> str:
    if not banner:
        return ""
    # HTTP Server header
    m = re.search(r"^Server:\s*(.+)$", banner, flags=re.IGNORECASE | re.MULTILINE)
    if m:
        return m.group(1).strip()
    # common first-line banners
    first = banner.splitlines()[0]
    return first.strip()


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, str, str]:
    try:
        if port == 443:
            # try SSL handshake to get server banner
            raw = socket.create_connection((host, port), timeout=timeout)
            context = ssl.create_default_context()
            ss = context.wrap_socket(raw, server_hostname=host)
            try:
                data = probe_service(ss, host, port, timeout)
            finally:
                ss.close()
            banner = data.decode(errors="ignore").strip() if data else ""
            version = detect_version(host, port, banner)
            return port, True, (banner or COMMON_SERVICES.get(port, "")), version

        s = socket.create_connection((host, port), timeout=timeout)
        try:
            banner = probe_service(s, host, port, timeout)
            banner_text = banner.decode(errors="ignore").strip() if banner else ""
            version = detect_version(host, port, banner_text)
            text = banner_text or COMMON_SERVICES.get(port, "")
            return port, True, text, version
        finally:
            s.close()
    except Exception:
        return port, False, "", ""


def scan_host(host: str, ports: List[int], timeout: float, workers: int) -> Dict[int, Tuple[bool, str, str]]:
    results: Dict[int, Tuple[bool, str, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                port, ok, txt, ver = fut.result()
                results[port] = (ok, txt, ver)
            except Exception:
                results[p] = (False, "", "")
    return results


def print_report(host: str, results: Dict[int, Tuple[bool, str, str]]) -> None:
    open_ports = [p for p, (ok, _, _) in results.items() if ok]
    print(f"\nHost: {host} — {len(open_ports)} open ports")
    for p in sorted(open_ports):
        ok, txt, ver = results[p]
        svc = COMMON_SERVICES.get(p, "")
        line = f"{p:5}  {svc or '-':8}  open"
        if ver:
            line += f"  — version: {ver}"
        elif txt:
            line += f"  — {txt.splitlines()[0][:200]}"
        print(line)


def results_to_json(host: str, results: Dict[int, Tuple[bool, str, str]]) -> Dict[str, Any]:
    out = {"host": host, "ports": []}
    for p in sorted(results.keys()):
        ok, txt, ver = results[p]
        out["ports"].append({"port": p, "open": bool(ok), "service": (txt or ""), "version": (ver or "")})
    return out


def main():
    parser = argparse.ArgumentParser(description="Simple network analyzer/port scanner using sockets")
    parser.add_argument("target", help="Target IP/hostname or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports (e.g. 22,80,443 or 1-1024). Default: 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    parser.add_argument("-w", "--workers", type=int, default=200, help="Number of concurrent worker threads")
    parser.add_argument("--per-host-workers", type=int, default=50, help="Workers per host when scanning many hosts")
    parser.add_argument("-sV", action="store_true", help="Enable version detection (simple banner/service probes)")
    parser.add_argument("-oJ", "--json", nargs='?', const='-', help="Write JSON output to file (or '-' for stdout). If omitted, no JSON is written.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    targets = parse_targets(args.target)
    ports = parse_ports(args.ports)

    if args.verbose:
        print(f"Scanning {len(targets)} target(s) with {len(ports)} ports each (timeout={args.timeout}s)")
    else:
        print(f"Scanning {len(targets)} target(s)")

    json_out = []

    # If multiple hosts, limit global concurrency per host to avoid overwhelming network
    for host in targets:
        if args.verbose:
            print(f"\nScanning host {host}")
        results = scan_host(host, ports, args.timeout, args.per_host_workers)
        print_report(host, results)
        if args.json:
            json_out.append(results_to_json(host, results))

    if args.json and json_out:
        j = json.dumps({"scans": json_out, "timestamp": time.time()}, indent=2)
        if args.json == '-':
            print(j)
        else:
            try:
                with open(args.json, 'w', encoding='utf-8') as f:
                    f.write(j)
                print(f"Wrote JSON output to {args.json}")
            except Exception as e:
                print(f"Failed to write JSON output: {e}")


if __name__ == "__main__":
    main()

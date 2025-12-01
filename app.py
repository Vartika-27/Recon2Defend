#!/usr/bin/env python3
"""
Recon2Defend — Scanner Module (MVP)

Performs:
✔ DNS enumeration
✔ Async TCP banner grabbing
✔ JSON output for downstream processing

Usage:
    python starter/app.py scan example.com --ports 80 443
"""

import argparse
import asyncio
import json
import socket
import time
from pathlib import Path

# Output directory for scan results
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "sample_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


# ---------------------------
# Banner Grabbing (Async)
# ---------------------------
async def grab_banner(ip: str, port: int, timeout: int = 3) -> str:
    """
    Attempts to grab service banner from an IP:port.
    """
    try:
        reader, writer = await asyncio.open_connection(ip, port)

        # give the service a moment to talk
        await asyncio.sleep(0.5)

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""

        writer.close()
        await writer.wait_closed()

        return data.decode(errors="ignore").strip()

    except Exception:
        return ""


# ---------------------------
# DNS Resolution
# ---------------------------
def resolve_host(host: str):
    """
    Resolves a domain to IPs (A/AAAA).
    """
    ips = set()
    try:
        results = socket.getaddrinfo(host, None)
        for info in results:
            ip = info[4][0]
            ips.add(ip)
    except Exception:
        pass

    return list(ips)


# ---------------------------
# Main Scan Logic
# ---------------------------
async def scan_target(host: str, ports: list):
    """
    Perform DNS lookup + banner grabbing for each IP/port.
    """

    ips = resolve_host(host)

    results = {
        "target": host,
        "timestamp": int(time.time()),
        "ips": ips,
        "ports": {}
    }

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append((ip, port, asyncio.create_task(grab_banner(ip, port))))

    # Gather banner results
    for ip, port, task in tasks:
        banner = await task
        results["ports"].setdefault(ip, {})[str(port)] = {
            "banner": banner
        }

    return results


# ---------------------------
# Save JSON
# ---------------------------
def save_json(data, filename):
    filepath = OUTPUT_DIR / filename
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return filepath


# ---------------------------
# CLI Entrypoint
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Recon2Defend Scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_cmd = subparsers.add_parser("scan", help="Run recon scan")
    scan_cmd.add_argument("target", help="Domain or IP to scan")
    scan_cmd.add_argument("--ports", nargs="*", type=int, default=[80, 443],
                          help="Ports to banner-scan")
    scan_cmd.add_argument("--outfile", default=None,
                          help="Optional filename override")

    args = parser.parse_args()

    if args.command == "scan":
        data = asyncio.run(scan_target(args.target, args.ports))
        outfile = args.outfile or f"scan_{args.target.replace('.', '_')}.json"
        path = save_json(data, outfile)
        print(f"[+] Scan complete.")
        print(f"[+] Output saved to: {path}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

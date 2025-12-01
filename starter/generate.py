#!/usr/bin/env python3
"""
Recon2Defend — Generator Module (MVP)

Reads:
    scan_output.json

Produces:
    - Suricata-style detection rules
    - HTML report (Jinja2)
    - IOC summary
    - MITRE ATT&CK technique mapping
"""

import argparse
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from starter.utils import load_json, save_text


# -----------------------------------------
# Paths
# -----------------------------------------
ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT / "templates"
OUTPUT_DIR = ROOT / "sample_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))


# -----------------------------------------
# Finding & MITRE Mapping Logic
# -----------------------------------------
def map_findings(scan_data, mitre_map):
    """
    Convert raw scan JSON into structured findings + IOC list.

    Each finding includes:
        - type
        - description
        - MITRE techniques
    """

    findings = []
    iocs = {
        "ips": set(),
        "banners": set(),
        "domains": set()
    }

    # Domain → IP resolution findings
    for ip in scan_data.get("ips", []):
        iocs["ips"].add(ip)
        findings.append({
            "type": "dns_lookup",
            "desc": f"Resolved {scan_data['target']} -> {ip}",
            "mitre": mitre_map.get("dns_enum", [])
        })

    # Banner grabbing findings
    for ip, portdata in scan_data.get("ports", {}).items():
        for port, info in portdata.items():
            banner = info.get("banner", "").strip()

            if banner:
                iocs["banners"].add(banner)
                findings.append({
                    "type": "banner",
                    "desc": f"Banner on {ip}:{port} -> {banner[:200]}",
                    "mitre": mitre_map.get("banner_grab", [])
                })

    # Make IOCs JSON-safe
    iocs = {k: list(v) for k, v in iocs.items()}

    return findings, iocs


# -----------------------------------------
# Rule Generator (Suricata format)
# -----------------------------------------
def generate_rules(target, findings, iocs):
    tmpl = env.get_template("suricata.rule.j2")
    return tmpl.render(target=target, findings=findings, iocs=iocs)


# -----------------------------------------
# HTML Report Generator
# -----------------------------------------
def generate_report(scan_data, findings, iocs, rules_text):
    tmpl = env.get_template("report.html.j2")
    return tmpl.render(
        scan=scan_data,
        findings=findings,
        iocs=iocs,
        rules=rules_text
    )


# -----------------------------------------
# CLI Entrypoint
# -----------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Recon2Defend Generator")
    parser.add_argument("cmd", choices=["generate"])
    parser.add_argument("scanjson", help="Path to scan JSON file")

    args = parser.parse_args()

    # Load files
    scan = load_json(args.scanjson)
    mitre_map = load_json(TEMPLATES_DIR / "mitre_map.json")

    # Build findings + IOCs
    findings, iocs = map_findings(scan, mitre_map)

    # Build Suricata rules
    rules = generate_rules(scan["target"], findings, iocs)

    # Build HTML report
    report_html = generate_report(scan, findings, iocs, rules)

    # Save output
    rules_path = OUTPUT_DIR / f"rules_{scan['target'].replace('.', '_')}.rules"
    report_path = OUTPUT_DIR / f"report_{scan['target'].replace('.', '_')}.html"

    save_text(rules_path, rules)
    save_text(report_path, report_html)

    print(f"[+] Rules written to: {rules_path}")
    print(f"[+] Report written to: {report_path}")


if __name__ == "__main__":
    main()

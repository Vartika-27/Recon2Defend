# Recon2Defend
Recon2Defend — MVP

A safe reconnaissance emulator that converts recon → MITRE mapping → detection rules → HTML reports.

🚀 What is Recon2Defend?

Recon2Defend is a non-destructive, safe recon simulator.
It performs the early-phase attacker actions (DNS lookups + banner grabbing), logs them, maps them to MITRE ATT&CK, and automatically generates:

Suricata-style detection rules

A clean, professional HTML report

IOC summary (IPs, banners, ports)

Everything runs locally and safely inside a tiny Docker lab.

🧠 Why this project?

Security teams need test data for SIEM/SOC pipelines.

You normally need attack traffic to test detection rules — this project gives you synthetic, harmless recon traffic and turns it into ready-to-use detection logic.

This is extremely valuable for:

Students

Detection engineers

SOC analysts

Cybersecurity portfolio projects

🧩 Features (MVP)

✔ DNS Enumeration

✔ Async TCP banner grabbing

✔ JSON scan output

✔ MITRE ATT&CK mapping

✔ Auto Suricata rule generation

✔ HTML reporting via Jinja2

✔ Clean Docker lab

✔ Fully offline-safe

✔ Beginner-friendly codebase



🛠 Installation

Local (no Docker)

python -m venv venv

source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt


🔍 Run the Scanner

python starter/app.py scan example.com --ports 80 443



Output saved to:


sample_outputs/scan_example.com.json

🏗 Generate Rules + Report

python starter/generate.py generate sample_outputs/scan_example.com.json


Outputs:


sample_outputs/rules_example.com.rules

sample_outputs/report_example.com.html


Open the HTML file in your browser.


🐳 Docker Lab (Recommended)

docker compose up --build



The container will auto-run a sample scan and generate a full report.


⚠️ Ethical Use Policy


This tool must only be used on systems you own or have explicit permission to test.


This project does not perform:

❌ exploitation

❌ intrusive scans

❌ destructive actions


It is strictly a safe recon emulator.


📌 Next Steps


Add TLS fingerprinting


Add more ATT&CK mappings


Add HTTP header/title enumeration


Add a web dashboard for reports


⭐ Credits


Built for learning, SOC automation, and detection engineering practice.

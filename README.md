# AUDITORIA

This directory contains the network audit report and the script used to reproduce it.

## Overview

`auditoria_red.py` performs a passive-but-useful network audit of a local LAN or specified CIDR range. It discovers active hosts, checks common network services, inspects exposed ports, identifies likely devices and services, enriches host metadata, and generates a self-contained HTML report with findings and recommendations.

This project is intended for internal or authorized networks only. It is designed for auditing and visibility, not for exploitation or unauthorized scanning.

## Contents

| File | Description |
|---|---|
| `informe_auditoria_2026-10-19.html` | Full audit report dated 19/10/2026, including styles, colors, tables, a summary index and severity badges. Opens in any browser. |
| `auditoria_red.py` | Script that prompts for the target range, scans the network, and generates a fresh HTML report. |
| `informes/` | Reports and JSON summaries produced by the script. |
| `informes/raw/` | Raw XML output from nmap, including discovery, pre-scan, high-port checks and main scan results. |

## Requirements

- Python 3.9 or newer
- `nmap` installed and available in `PATH`
- `curl` (optional, used for checks such as pve-exporter, Promtail, Deluge, etc.)

### Install on Arch Linux

```bash
sudo pacman -S nmap curl
```

### Install on Debian / Ubuntu

```bash
sudo apt install nmap curl
```

## Notes

No root privileges are required. The script uses `nmap -sT` (TCP connect scan), so it works as a normal user. Without root access, OS fingerprinting and UDP scanning are unavailable. In that case, the operating system is inferred from banners and open ports.

## Usage

```bash
cd ~/AUDITORIA
python3 auditoria_red.py
```

The script will prompt for the following:

1. **Range to audit** — defaults to `192.168.1.0/24`. You can change it to values such as `10.0.0.0/24`, `192.168.0.0/24`, etc.
2. **Full scan?** — `s` runs a full TCP scan (all 65535 ports, slower), while `N` uses the quick scan mode.
3. **Open the report?** — asks whether to open the final HTML report after completion.

### Command-line arguments

```bash
# Quick scan without prompting for the browser
python3 auditoria_red.py --range 192.168.1.0/24 --quick --no-browser

# Full scan of all TCP ports
python3 auditoria_red.py --range 192.168.1.0/24 --full --no-browser

# Select a custom output directory
python3 auditoria_red.py --range 10.0.0.0/24 --quick -o ~/AUDITORIA/informes
```

### Useful options

| Option | Effect |
|---|---|
| `-r`, `--range` | CIDR range or IP address to audit. |
| `--quick` | Scans the top 1000 TCP ports plus curated LAN service ports. |
| `--full` | Scans all 65535 TCP ports. |
| `--top-ports N` | Overrides the default top-N port count for quick scans. |
| `--no-scripts` | Disables NSE script execution. |
| `--open` | Opens the generated report when the scan completes. |
| `--no-browser` | Suppresses the browser-opening prompt. |
| `-y`, `--yes` | Skips confirmation for public ranges; use only with proper authorization. |
| `-o`, `--output-dir` | Sets the output directory. |

## What the script does

1. **Host discovery** using `nmap -sn`
2. **Pre-scan of key ports** such as SSH, DNS, HTTP/HTTPS, Proxmox services (`8006`, `3128`, `9221`), Promtail (`9080`), Deluge (`8112`), Jackett (`9117`), CPE/TR-069 (`4008`), plus high-risk or unclassified ports
3. **High-port validation** without slow fingerprinting, to avoid missing devices with unknown services
4. **Main scan** of the top 1000 ports (or all ports with `--full`), excluding ports already seen
5. **Version detection and safe NSE scripts**, including:
   - `banner`
   - `http-title`
   - `http-headers`
   - `ssl-cert`
   - `ssh-hostkey`
   - `rpcinfo`
6. **MAC/OUI enrichment** using `ip neigh` and `/usr/share/nmap/nmap-mac-prefixes` to identify vendors such as Proxmox (`BC:24:11`), ZTE routers and others
7. **Proxmox inventory** without authentication when `pve-exporter` is detected on `:9221`, including cluster data, nodes, versions and guests
8. **Security rule checks**, including:
   - Proxmox VE 8.x end-of-life
   - Promtail 2.x end-of-life and unauthenticated exposure
   - Unauthenticated `pve-exporter`
   - BIND 9.18 end-of-life and known CVEs
   - Older ZTE router firmware exposed over HTTP
   - Deluge and Jackett exposed over HTTP
   - `rpcbind`, CPE/TR-069 and exposed Proxmox management interfaces
   - OpenSSH regreSSHion and outdated builds
   - Ubuntu interim releases nearing EOL
   - Unconfigured Caddy instances and unknown high ports
9. **Generates an HTML report** with embedded styles and a **JSON summary** for automation and further analysis

## Output

Each execution creates the following output:

```text
informes/informe_<range>_<date_time>.html
informes/informe_<range>_<date_time>.json
informes/raw/discovery_<...>.xml
informes/raw/prescan_<...>.xml
informes/raw/unknown_ports_<...>.xml
informes/raw/scan_<...>.xml
```

The HTML report includes:

- Severity summary and counters
- Host inventory with IP, MAC/OUI, OS type, open ports and notes
- Proxmox inventory with cluster, nodes, versions and guests
- Findings with evidence, recommended actions and CVEs
- Passed checks and validation results
- Detailed per-host information including ports, versions and NSE scripts
- Methodology and limitations
- Print-to-PDF friendly output

## Limitations

- Without root privileges, there is no OS fingerprinting (`-O`) and no UDP scan
- OS detection is inferred from banners and port behavior
- EOL and CVE checks are heuristic; always confirm against official vendor advisories
- Exact mapping from IP to Proxmox guest requires DHCP information or API access with valid credentials
- Exposure from the WAN cannot be assessed from inside the LAN
- Discovery depends on hosts responding; a device that blocks all traffic may not appear
- No credentials are tested, no vulnerabilities are exploited, and no system changes are made

## Disclaimer

Use this script only on networks you own or have explicit authorization to audit. Scanning public or unauthorized ranges may be illegal or against policy depending on your jurisdiction.

---

## OVERSEER View

This project also includes a local web viewer in `OVERSEER/`, which aggregates all JSON reports from `informes/` and displays the network in a dark-themed interface.

```bash
cd ~/AUDITORIA_PLUS/OVERSEER
./run.sh
# http://127.0.0.1:8770
```

### Features

- Left column: IP address, OS and device type (`Proxmox`, `LXC/VM?`, `LXC`, `VM`, etc.)
- Central panel: general overview or detailed host view with charts and tabs
- Historical comparison across scans
- Manual LXC/VM classification via `annotations.json`
- Read-only behavior: it does not scan or modify the network

For more details, see [`OVERSEER/README.md`](OVERSEER/README.md).

# OVERSEER

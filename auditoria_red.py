#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auditoria_red.py — Auditoría defensiva de una red local.

Hace, sin privilegios de root:
  1. Descubrimiento de hosts (nmap -sn).
  2. Escaneo TCP + detección de versiones + scripts NSE seguros.
  3. Identificación de Proxmox, guests (MAC BC:24:11), router, Linux, etc.
  4. Comprobaciones de exposición (Promtail, pve-exporter, rpcbind, Deluge, Jackett...).
  5. Reglas heurísticas de EOL/CVE conocidas.
  6. Informe HTML autocontenido y un resumen JSON.

Uso:
    python3 auditoria_red.py
    python3 auditoria_red.py --range 192.168.1.0/24 --quick
    python3 auditoria_red.py --range 10.0.0.0/24 --full --no-browser

Requisitos: nmap, python3. curl es opcional (para comprobaciones HTTP).
No prueba credenciales, no explota vulnerabilidades y no modifica sistemas.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html as html_lib
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path
import xml.etree.ElementTree as ET

VERSION = "1.0.0"
DEFAULT_RANGE = "192.168.1.0/24"

# Puertos que no suelen estar en el top-1000 pero son relevantes en una LAN:
# gestión de Proxmox, exporters, paneles de descargas, TR-069, etc.
CURATED_PORTS = {
    22, 53, 80, 111, 443, 445, 631, 993, 995, 2049, 3000, 3128, 3306, 3389,
    4008, 5000, 5432, 5900, 6379, 8000, 8006, 8080, 8081, 8112, 8443, 9000,
    9080, 9090, 9100, 9117, 9200, 9221, 9443, 10000, 10162, 27017, 44469,
}

# Puertos sin servicio conocido: se detectan en un pase rápido sin -sV
# para que un fingerprint lento no haga expirar el host entero.
SLOW_PORTS = {10162, 44469}

# Etiquetas amigables para puertos que nmap a veces confunde.
KNOWN_PORT_LABELS = {
    443: ("https", "HTTPS"),
    8006: ("https", "Proxmox VE Web UI"),
    3128: ("http", "HTTP proxy / Proxmox SPICE"),
    9221: ("http", "Proxmox VE Exporter"),
    9080: ("http", "Promtail / HTTP"),
    8112: ("http", "Deluge WebUI"),
    9117: ("http", "Jackett"),
    4008: ("http", "CPE-SERVER/TR-069"),
    10162: ("unknown", "Desconocido (sin banner)"),
    44469: ("http", "HTTP/2 h2c/gRPC (no identificado)"),
}

# Puertos donde la etiqueta propia siempre gana a la de nmap.
FORCE_LABELS = {3128, 4008, 8006, 8112, 9080, 9117, 9221, 10162, 44469}

SEV_ORDER = {"CRÍTICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFO": 4}
SEV_CLASS = {"CRÍTICO": "crit", "ALTO": "high", "MEDIO": "med", "BAJO": "low", "INFO": "info"}

CSS = r"""
:root {
  --bg: #070b14;
  --bg2: #0c1322;
  --panel: rgba(18, 27, 45, .88);
  --panel2: #111a2b;
  --text: #e7eefc;
  --muted: #94a3bd;
  --line: #22314c;
  --accent: #7c9cff;
  --accent2: #43e0b0;
  --crit: #ff4d6d;
  --high: #ff8a3d;
  --med: #ffd166;
  --low: #4cc9f0;
  --info: #9aa7bd;
  --ok: #3ddc97;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
  background:
    radial-gradient(1200px 600px at 10% -10%, rgba(124,156,255,.18), transparent 60%),
    radial-gradient(900px 500px at 100% 0%, rgba(67,224,176,.12), transparent 55%),
    linear-gradient(180deg, var(--bg), var(--bg2));
  color: var(--text);
  line-height: 1.65;
  min-height: 100vh;
}
a { color: var(--accent); }
.wrap { max-width: 1180px; margin: 0 auto; padding: 36px 22px 90px; }

.hero {
  background: linear-gradient(135deg, rgba(124,156,255,.14), rgba(67,224,176,.07));
  border: 1px solid var(--line);
  border-radius: 22px;
  padding: 30px 32px;
  box-shadow: 0 18px 60px rgba(0,0,0,.32);
  position: relative;
  overflow: hidden;
}
.hero::after {
  content: "";
  position: absolute;
  inset: auto -80px -140px auto;
  width: 340px;
  height: 340px;
  background: radial-gradient(circle, rgba(124,156,255,.22), transparent 70%);
  pointer-events: none;
}
.kicker {
  color: var(--accent2);
  font-size: .78rem;
  font-weight: 800;
  letter-spacing: .16em;
  text-transform: uppercase;
  margin-bottom: 10px;
}
.hero h1 { margin: 0 0 8px; font-size: clamp(1.7rem, 4vw, 2.6rem); line-height: 1.15; }
.hero h1 .accent { color: var(--accent); }
.hero .sub { margin: 0; color: var(--muted); font-size: 1rem; }
.hero-actions { margin-top: 18px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
.hero-actions button {
  cursor: pointer;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.05);
  color: var(--text);
  padding: 9px 14px;
  border-radius: 10px;
  font: inherit;
  font-size: .88rem;
}
.hero-actions button:hover { border-color: var(--accent); background: rgba(124,156,255,.12); }
.legend { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }

h2 {
  margin: 46px 0 14px;
  font-size: 1.45rem;
  border-bottom: 1px solid var(--line);
  padding-bottom: 8px;
}
h3 { margin: 26px 0 10px; font-size: 1.08rem; }
p { margin: 10px 0; }
.muted { color: var(--muted); }
.accent { color: var(--accent); }
.ok { color: var(--ok); }

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
  gap: 14px;
  margin: 22px 0 10px;
}
.stat {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 16px 18px;
  box-shadow: 0 10px 30px rgba(0,0,0,.18);
}
.stat .num { display: block; font-size: 1.9rem; font-weight: 800; line-height: 1; }
.stat .lbl { color: var(--muted); font-size: .79rem; text-transform: uppercase; letter-spacing: .08em; }
.stat.crit .num { color: var(--crit); }
.stat.high .num { color: var(--high); }
.stat.med .num { color: var(--med); }
.stat.low .num { color: var(--low); }

.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: 14px;
  margin: 18px 0 26px;
  background: var(--panel2);
}
table { width: 100%; border-collapse: collapse; font-size: .92rem; }
thead th {
  background: #16213a;
  color: #cdd9f4;
  text-align: left;
  padding: 11px 13px;
  font-size: .76rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}
tbody td {
  padding: 10px 13px;
  border-bottom: 1px solid rgba(34,49,76,.6);
  vertical-align: top;
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:nth-child(even) { background: rgba(255,255,255,.018); }
tbody tr:hover { background: rgba(124,156,255,.06); }
td.scripts { min-width: 240px; }
td.scripts code { white-space: pre-wrap; word-break: break-word; font-size: .78rem; }

code {
  font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
  background: rgba(255,255,255,.055);
  border: 1px solid rgba(255,255,255,.06);
  padding: 1px 5px;
  border-radius: 5px;
  font-size: .88em;
}
pre {
  background: #080d18;
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 12px 14px;
  overflow-x: auto;
  font-size: .82rem;
  line-height: 1.5;
}
pre code { background: none; border: 0; padding: 0; }

.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: .70rem;
  font-weight: 800;
  letter-spacing: .06em;
  text-transform: uppercase;
  vertical-align: middle;
  white-space: nowrap;
}
.badge.crit { background: rgba(255,77,109,.16); color: #ff9aac; border: 1px solid rgba(255,77,109,.48); }
.badge.high { background: rgba(255,138,61,.16); color: #ffb37c; border: 1px solid rgba(255,138,61,.48); }
.badge.med  { background: rgba(255,209,102,.14); color: #ffe09a; border: 1px solid rgba(255,209,102,.45); }
.badge.low  { background: rgba(76,201,240,.14); color: #92e3ff; border: 1px solid rgba(76,201,240,.45); }
.badge.info { background: rgba(154,167,189,.14); color: #c3cddd; border: 1px solid rgba(154,167,189,.38); }

.finding {
  background: var(--panel);
  border: 1px solid var(--line);
  border-left: 4px solid var(--info);
  border-radius: 14px;
  padding: 17px 19px;
  margin: 14px 0;
  box-shadow: 0 10px 30px rgba(0,0,0,.14);
}
.finding.crit { border-left-color: var(--crit); }
.finding.high { border-left-color: var(--high); }
.finding.med  { border-left-color: var(--med); }
.finding.low  { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding-head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.finding-head h3 { margin: 0; font-size: 1.02rem; }
.host-chip {
  margin-left: auto;
  font-family: "JetBrains Mono", ui-monospace, monospace;
  font-size: .78rem;
  color: var(--muted);
  background: rgba(255,255,255,.04);
  border: 1px solid var(--line);
  padding: 2px 8px;
  border-radius: 999px;
}
.finding p { margin: 6px 0; }
.finding .cves { color: var(--muted); font-size: .86rem; }

details.host {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 13px 17px;
  margin: 12px 0;
}
details.host summary {
  cursor: pointer;
  font-weight: 700;
  list-style: none;
}
details.host summary::-webkit-details-marker { display: none; }
details.host summary::before { content: "▸ "; color: var(--accent); }
details.host[open] summary::before { content: "▾ "; }
details.host summary span { color: var(--muted); font-weight: 400; font-size: .9rem; }
details.host .inner { margin-top: 12px; }

blockquote {
  border-left: 4px solid var(--accent);
  background: rgba(124,156,255,.08);
  margin: 18px 0;
  padding: 12px 18px;
  border-radius: 0 10px 10px 0;
  color: #cdd9f4;
}
hr { border: 0; border-top: 1px solid var(--line); margin: 32px 0; }

.top {
  position: fixed;
  right: 18px;
  bottom: 18px;
  width: 42px;
  height: 42px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  background: var(--panel);
  border: 1px solid var(--line);
  color: var(--accent);
  text-decoration: none;
  font-size: 1.2rem;
  box-shadow: 0 10px 30px rgba(0,0,0,.35);
}
.top:hover { border-color: var(--accent); background: rgba(124,156,255,.12); }

footer {
  margin-top: 46px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-size: .84rem;
}

@media (max-width: 640px) {
  .wrap { padding: 20px 14px 70px; }
  .hero { padding: 22px 20px; border-radius: 16px; }
  .finding-head h3 { width: 100%; }
  .host-chip { margin-left: 0; }
}

@media print {
  body { background: #fff; color: #111; }
  .wrap { max-width: none; padding: 0; }
  .hero, .stat, .finding, details.host, .table-wrap {
    box-shadow: none;
    background: #fff;
    border-color: #ccc;
  }
  .hero::after, .top, .hero-actions { display: none; }
  a { color: #111; }
  h2 { page-break-after: avoid; }
  .finding, details.host { page-break-inside: avoid; }
  .badge { border: 1px solid #999; color: #111; }
}
"""


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def ask(prompt: str, default: str = "") -> str:
    try:
        value = input(prompt).strip()
    except EOFError:
        value = ""
    return value or default


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    try:
        value = input(prompt).strip().lower()
    except EOFError:
        return default
    if not value:
        return default
    return value in ("s", "si", "sí", "y", "yes")


def run_stream(cmd: list[str], prefix: str = "  ") -> int:
    """Ejecuta un comando mostrando su salida en tiempo real."""
    display = " ".join(cmd)
    if len(display) > 320:
        display = display[:320] + " …"
    print(f"\n$ {display}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print(f"ERROR: no se encontró el ejecutable {cmd[0]!r}.")
        return 127

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        # Los fingerprints de nmap son enormes y no aportan al informe.
        if line.startswith(("SF:", "SF-")) or "NEXT SERVICE FINGERPRINT" in line:
            continue
        print(prefix + line)
    return proc.wait()


def http_get(url: str, timeout: int = 6) -> str:
    """GET HTTP(S) tolerante a errores. Devuelve '' si falla."""
    if not shutil.which("curl"):
        return ""
    try:
        result = subprocess.run(
            ["curl", "-sk", "-m", str(timeout), url],
            capture_output=True,
            text=True,
            timeout=timeout + 4,
        )
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def http_status(url: str, timeout: int = 6) -> str:
    """Código HTTP sin descargar el cuerpo. Devuelve '' si falla."""
    if not shutil.which("curl"):
        return ""
    try:
        result = subprocess.run(
            [
                "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", str(timeout), url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 4,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def parse_nmap(xml_path: Path) -> list[dict]:
    """Convierte un XML de nmap en una lista de hosts."""
    hosts: list[dict] = []
    try:
        root = ET.parse(xml_path).getroot()
    except Exception as exc:
        print(f"  [!] No se pudo leer {xml_path}: {exc}")
        return hosts

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr: dict[str, str] = {}
        vendor = ""
        for item in host.findall("address"):
            kind = item.get("addrtype", "")
            value = item.get("addr", "")
            if value:
                addr[kind] = value
            if kind == "mac":
                vendor = item.get("vendor", "") or ""

        ip = addr.get("ipv4") or addr.get("ipv6")
        if not ip:
            continue

        hostnames = [
            h.get("name", "")
            for h in host.findall("hostnames/hostname")
            if h.get("name")
        ]

        ports: list[dict] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            scripts: dict[str, str] = {}
            for script in port.findall("script"):
                scripts[script.get("id", "?")] = script.get("output", "") or ""

            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            extrainfo = svc.get("extrainfo", "") if svc is not None else ""
            name = svc.get("name", "") if svc is not None else ""

            entry = {
                "port": int(port.get("portid", "0")),
                "proto": port.get("protocol", "tcp"),
                "name": name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "service_str": " ".join(x for x in (product, version, extrainfo) if x) or name,
                "scripts": scripts,
            }
            if entry["port"] in KNOWN_PORT_LABELS:
                friendly_name, friendly_label = KNOWN_PORT_LABELS[entry["port"]]
                if (
                    entry["port"] in FORCE_LABELS
                    or not entry["product"]
                    or entry["name"] in ("unknown", "tcpwrapped", "", "wpl-analytics", "http")
                ):
                    entry["name"] = friendly_name
                    entry["service_str"] = friendly_label
            ports.append(entry)

        ports.sort(key=lambda p: p["port"])

        hostscripts: dict[str, str] = {}
        for script in host.findall("hostscript/script"):
            hostscripts[script.get("id", "?")] = script.get("output", "") or ""

        hosts.append(
            {
                "ip": ip,
                "mac": addr.get("mac", ""),
                "vendor": vendor,
                "hostnames": hostnames,
                "ports": ports,
                "hostscripts": hostscripts,
            }
        )

    return hosts


def ip_sort_key(host: dict) -> tuple[int, int, int, int]:
    try:
        return tuple(int(x) for x in host["ip"].split("."))  # type: ignore[return-value]
    except Exception:
        return (999, 999, 999, 999)


def merge_hosts(discovered: list[dict], scanned: list[dict]) -> list[dict]:
    by_ip: dict[str, dict] = {h["ip"]: h for h in discovered}
    for host in scanned:
        ip = host["ip"]
        if ip not in by_ip:
            by_ip[ip] = host
            continue

        base = by_ip[ip]
        for key, value in host.items():
            if key == "ports":
                continue
            if key == "hostscripts":
                base.setdefault("hostscripts", {}).update(value)
                continue
            if key in ("mac", "vendor", "hostnames") and not value:
                continue
            base[key] = value

        # Unión de puertos: un host puede aparecer en varios pases.
        existing = {p["port"]: p for p in base.get("ports", [])}
        for port in host.get("ports", []):
            old = existing.get(port["port"])
            if old is None:
                existing[port["port"]] = port
                continue
            score_new = sum(bool(port.get(k)) for k in ("name", "product", "version", "extrainfo")) + len(port.get("scripts", {}))
            score_old = sum(bool(old.get(k)) for k in ("name", "product", "version", "extrainfo")) + len(old.get("scripts", {}))
            if score_new > score_old:
                existing[port["port"]] = port
        base["ports"] = sorted(existing.values(), key=lambda p: p["port"])

    return sorted(by_ip.values(), key=ip_sort_key)


def neighbor_macs() -> dict[str, str]:
    """MACs vistas por el kernel (no requiere root)."""
    result: dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in proc.stdout.splitlines():
            match = re.search(r"^(\S+).*lladdr\s+([0-9a-fA-F:]{17})", line)
            if match:
                result[match.group(1)] = match.group(2).lower()
    except Exception:
        pass
    if not result:
        try:
            proc = subprocess.run(
                ["arp", "-n"], capture_output=True, text=True, timeout=5,
            )
            for line in proc.stdout.splitlines():
                match = re.search(r"^(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})", line)
                if match:
                    result[match.group(1)] = match.group(2).lower()
        except Exception:
            pass
    return result


def local_ipv4_addresses() -> set[str]:
    """IPv4 del equipo auditor (para etiquetarlo en el informe)."""
    result: set[str] = set()
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in proc.stdout.splitlines():
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                result.add(match.group(1))
    except Exception:
        pass
    return result


def load_oui_prefixes() -> dict[str, str]:
    prefixes: dict[str, str] = {}
    path = Path("/usr/share/nmap/nmap-mac-prefixes")
    if not path.exists():
        return prefixes
    try:
        for line in path.read_text(errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                prefixes[parts[0].upper()] = parts[1].strip()
    except OSError:
        pass
    return prefixes


def enrich_macs(hosts: list[dict]) -> None:
    neighbors = neighbor_macs()
    prefixes = load_oui_prefixes()
    for host in hosts:
        mac = host.get("mac") or neighbors.get(host["ip"], "")
        if not mac:
            continue
        host["mac"] = mac
        prefix = mac.replace(":", "").upper()[:6]
        if not host.get("vendor"):
            host["vendor"] = prefixes.get(prefix, "")


def curated_port_list() -> str:
    return ",".join(str(port) for port in sorted(CURATED_PORTS))


def top_port_list(top_n: int, exclude: set[int] | None = None) -> str:
    """Top-N puertos TCP, opcionalmente excluyendo los ya escaneados."""
    if top_n <= 0:
        return ""
    services = Path("/usr/share/nmap/nmap-services")
    rows: list[tuple[float, int]] = []
    if services.exists():
        try:
            for line in services.read_text(errors="ignore").splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                port_proto = parts[1]
                if not port_proto.endswith("/tcp"):
                    continue
                try:
                    port = int(port_proto.split("/")[0])
                    freq = float(parts[2])
                except ValueError:
                    continue
                rows.append((freq, port))
        except OSError:
            rows = []
    rows.sort(reverse=True)
    ports = {port for _, port in rows[:top_n]}
    if exclude:
        ports -= exclude
    return ",".join(str(port) for port in sorted(ports))


# ---------------------------------------------------------------------------
# Clasificación y hallazgos
# ---------------------------------------------------------------------------

def guess_os_ssh(host: dict) -> str:
    for port in host["ports"]:
        text = f"{port['product']} {port['version']} {port['extrainfo']}".lower()
        if port["name"] == "ssh" or "openssh" in text:
            if "ubuntu" in text:
                if "8.9p1" in text:
                    return "Ubuntu 22.04 LTS"
                if "9.6p1" in text:
                    return "Ubuntu 24.04 LTS"
                if "9.9p1" in text:
                    return "Ubuntu 25.04/25.10 (interim)"
                return "Ubuntu (versión por confirmar)"
            if "debian" in text:
                return "Debian (probable 12)"
    return ""


def guess_os_http(host: dict) -> str:
    text = " ".join(
        " ".join(port["scripts"].values()) for port in host["ports"]
    ).lower()
    if "caddy" in text:
        return "Linux (Caddy)"
    if "deluge" in text:
        return "Linux (Deluge)"
    if "jackett" in text:
        return "Linux (Jackett/.NET)"
    if "promtail" in text:
        return "Linux (Promtail)"
    return ""


def classify(host: dict) -> None:
    if host.get("auditor"):
        host["type"] = "Equipo auditor (este host)"
        host["os"] = "Este equipo"
        return
    ports = {p["port"]: p for p in host["ports"]}
    text = " ".join(
        (p["service_str"] + " " + " ".join(p["scripts"].values()))
        for p in host["ports"]
    ).lower()
    mac = (host.get("mac") or "").upper()

    if 8006 in ports or 3128 in ports or "pve-api-daemon" in text or "proxmox" in text:
        host["type"] = "Nodo Proxmox"
        host["os"] = "Debian 12 + Proxmox VE"
    elif mac.startswith("BC:24:11"):
        host["type"] = "Guest Proxmox (LXC/VM)"
        host["os"] = guess_os_ssh(host) or "Linux (guest Proxmox)"
    elif "zte web server" in text or "h3600p" in text:
        host["type"] = "Router"
        host["os"] = "Firmware ZTE (Linux)"
    elif not host["ports"]:
        host["type"] = "Equipo cliente / IoT"
        host["os"] = "Desconocido (sin puertos TCP)"
    elif (
        len(host["ports"]) == 1
        and host["ports"][0]["port"] >= 10000
        and not host["ports"][0]["product"]
    ):
        host["type"] = "Dispositivo no identificado"
        host["os"] = "Desconocido (sin banner)"
    else:
        host["type"] = "Servidor / servicio"
        host["os"] = guess_os_ssh(host) or guess_os_http(host) or "Linux / desconocido"


def add_finding(
    findings: list[dict],
    severity: str,
    title: str,
    host: str,
    evidence: str,
    recommendation: str,
    cves: list[str] | None = None,
) -> None:
    if any(f["host"] == host and f["title"] == title for f in findings):
        return
    findings.append(
        {
            "severity": severity,
            "title": title,
            "host": host,
            "evidence": evidence,
            "recommendation": recommendation,
            "cves": cves or [],
        }
    )


def analyze_host(host: dict, findings: list[dict], good: list[str], proxmox: dict) -> None:
    if host.get("auditor"):
        return
    ip = host["ip"]
    ports = {p["port"]: p for p in host["ports"]}
    host_text = " ".join(
        (p["service_str"] + " " + " ".join(p["scripts"].values()))
        for p in host["ports"]
    ).lower()
    mac = (host.get("mac") or "").upper()

    # --- pve-exporter ------------------------------------------------------
    if 9221 in ports:
        body = http_get(f"http://{ip}:9221/pve?cluster=1")
        version = None
        if body:
            match = re.search(r'pve_version_info\{[^}]*version="([^"]+)"', body)
            if match:
                version = match.group(1)
        if body:
            evidence = f"HTTP 200 en http://{ip}:9221/pve?cluster=1 sin credenciales."
            if version:
                evidence += f" pve_version_info={version}."
            add_finding(
                findings, "ALTO", "pve-exporter sin autenticación", ip,
                evidence,
                "Escuchar en 127.0.0.1, filtrar 9221 o poner un reverse proxy con autenticación.",
            )
            if version and version.startswith("8."):
                add_finding(
                    findings, "ALTO", "Proxmox VE 8.x EOL", ip,
                    f"El exporter reporta Proxmox VE {version}; la rama 8 alcanzó EOL el 2026-08-31.",
                    "Actualizar a Proxmox VE 9.2 (Debian 13) tras backup y ventana de mantenimiento; mientras tanto, aislar la gestión.",
                )
            if re.search(r'pve_cluster_info\{[^}]*quorate="1"', body):
                good.append(f"{ip}: el clúster Proxmox reporta quórum correcto.")

            # Inventario del clúster (métricas de pve-exporter).
            cluster_match = re.search(r'pve_cluster_info\{([^}]+)\}', body)
            if cluster_match:
                attrs = dict(re.findall(r'(\w+)="([^"]*)"', cluster_match.group(1)))
                proxmox["cluster"] = attrs.get("id", "").replace("cluster/", "")
                proxmox["nodes_count"] = attrs.get("nodes", "")
                proxmox["quorate"] = attrs.get("quorate", "")
                proxmox["version"] = version or ""
                proxmox["source_ip"] = ip
            for node_match in re.finditer(r'pve_node_info\{([^}]+)\}', body):
                attrs = dict(re.findall(r'(\w+)="([^"]*)"', node_match.group(1)))
                if attrs.get("name") and all(n.get("name") != attrs["name"] for n in proxmox["nodes"]):
                    proxmox["nodes"].append(attrs)
            for guest_match in re.finditer(r'pve_guest_info\{([^}]+)\}', body):
                attrs = dict(re.findall(r'(\w+)="([^"]*)"', guest_match.group(1)))
                if attrs.get("id") and all(g.get("id") != attrs["id"] for g in proxmox["guests"]):
                    proxmox["guests"].append(attrs)
        else:
            add_finding(
                findings, "INFO", "pve-exporter detectado (comprobar autenticación)", ip,
                "El puerto 9221 está abierto; no se pudo leer /pve sin credenciales o no respondió.",
                "Verificar si el exporter exige autenticación y si necesita estar expuesto a la LAN.",
            )

    # --- Promtail ----------------------------------------------------------
    if 9080 in ports:
        body = http_get(f"http://{ip}:9080/config")
        title = " ".join(ports[9080].get("scripts", {}).values()).lower()
        looks_like_promtail = (
            "promtail" in body.lower()
            or "clients:" in body.lower()
            or "server:" in body.lower()
            or "promtail" in title
        )
        if looks_like_promtail:
            add_finding(
                findings, "ALTO", "Promtail EOL y sin autenticación", ip,
                f"El puerto 9080 sirve la UI/config de Promtail sin login; /config es accesible. Promtail 2.x alcanzó EOL el 2026-03-02.",
                "Detener/eliminar Promtail, migrar a Grafana Alloy y filtrar 9080 (o escuchar solo en localhost).",
            )
        else:
            add_finding(
                findings, "INFO", "Puerto 9080 abierto (posible Promtail)", ip,
                "El puerto 9080 está abierto, pero no se confirmó la firma de Promtail.",
                "Identificar el servicio con ss -lntp y cerrarlo si no se usa.",
            )

    # --- BIND --------------------------------------------------------------
    for port in host["ports"]:
        version_text = f"{port['product']} {port['version']} {port['extrainfo']}".strip()
        lower = version_text.lower()
        if ("bind" in lower or port["name"] == "domain") and "9.18" in lower:
            match = re.search(r"9\.18\.(\d+)", lower)
            patch = int(match.group(1)) if match else 0
            cves: list[str] = []
            if patch < 50:
                cves = [
                    "CVE-2025-13878", "CVE-2026-1519", "CVE-2026-3039",
                    "CVE-2026-3592", "CVE-2026-5946", "CVE-2026-5950",
                ]
            add_finding(
                findings, "ALTO", "BIND 9.18 EOL y vulnerable", ip,
                f"{version_text} en {port['port']}/tcp. La rama 9.18 alcanzó EOL el 2026-07-01 (última 9.18.50).",
                "Actualizar el firmware del router (o el paquete BIND); desactivar DNS recursivo en WAN y usar un resolver interno.",
                cves,
            )
            break

    # --- Router ZTE --------------------------------------------------------
    if "zte web server" in host_text or "h3600p" in host_text:
        add_finding(
            findings, "MEDIO", "Router ZTE: administración HTTP y firmware antiguo", ip,
            "Panel HTTP en :80 y HTTPS con certificado autofirmado en :443; servidor ZTE web 1.0 (2015). Los CVE-2024-45413/45414/45415/45416 se confirmaron en otros modelos ZTE, no específicamente en H3600P.",
            "Usar solo HTTPS, contraseña de administrador fuerte y única, desactivar gestión WAN y actualizar firmware con el ISP.",
            ["CVE-2024-45413", "CVE-2024-45414", "CVE-2024-45415", "CVE-2024-45416"],
        )
        if 53 in ports:
            add_finding(
                findings, "MEDIO", "DNS recursivo del router accesible desde la LAN", ip,
                "El puerto 53/tcp responde a consultas recursivas desde la LAN.",
                "Desactivar recursión en WAN, bloquear 53 desde fuera y usar un resolver interno (p. ej. AdGuard/Unbound).",
            )

    # --- Gestión de Proxmox ------------------------------------------------
    if host.get("type") == "Nodo Proxmox":
        mgmt = [p for p in (8006, 3128, 22) if p in ports]
        if mgmt:
            add_finding(
                findings, "MEDIO", "Gestión de Proxmox expuesta a la LAN", ip,
                f"Puertos de gestión abiertos: {', '.join(map(str, mgmt))}.",
                "Segmentar en VLAN de administración, activar 2FA en PVE, usar SSH solo con claves y limitar el origen.",
            )
        if 8006 in ports:
            status = http_status(f"https://{ip}:8006/")
            if status == "401":
                good.append(f"{ip}: la API de Proxmox en 8006 devuelve 401 sin credenciales.")

    # --- rpcbind -----------------------------------------------------------
    if 111 in ports:
        add_finding(
            findings, "MEDIO", "rpcbind expuesto", ip,
            "El puerto 111/tcp está abierto; rpcinfo solo muestra rpcbind (sin exports NFS visibles).",
            "Si no se usa NFS, deshabilitar rpcbind o filtrar 111/tcp y 111/udp.",
        )

    # --- CPE / TR-069 ------------------------------------------------------
    if 4008 in ports:
        add_finding(
            findings, "BAJO", "CPE-SERVER/TR-069 expuesto", ip,
            "El puerto 4008/tcp responde como CPE-SERVER/1.0 (gestión TR-069/CWMP).",
            "Verificar que solo escuche en la LAN y que el ISP no lo exponga a WAN.",
        )

    # --- Descargas por HTTP ------------------------------------------------
    downloads: list[str] = []
    if 8112 in ports:
        downloads.append("Deluge")
    if 9117 in ports:
        downloads.append("Jackett")
    if downloads:
        text = " y ".join(downloads)
        add_finding(
            findings, "MEDIO", f"{text} por HTTP", ip,
            f"Puertos {', '.join(str(p) for p in (8112, 9117) if p in ports)}/tcp sirven la interfaz por HTTP sin TLS; exigen login, pero las credenciales/cookies viajan en claro por la LAN.",
            "Poner detrás de Caddy con TLS y autenticación, cambiar contraseñas y limitar a LAN/VPN. En Deluge, verificar que no use la contraseña por defecto 'deluge'.",
        )
        if 8112 in ports:
            body = http_get(f"http://{ip}:8112/")
            if "login" in body.lower():
                good.append(f"{ip}: Deluge exige login (no se probaron credenciales).")
        if 9117 in ports:
            body = http_get(f"http://{ip}:9117/")
            if "login" in body.lower():
                good.append(f"{ip}: Jackett exige login.")

    # --- Caddy sin sitio ---------------------------------------------------
    if 80 in ports and "caddy" in host_text:
        add_finding(
            findings, "BAJO", "Caddy sin sitio configurado", ip,
            "Todas las rutas devuelven 404 con Server: Caddy.",
            "Retirar Caddy si no se usa o configurar TLS y rutas si actúa como reverse proxy.",
        )

    # --- OpenSSH -----------------------------------------------------------
    ssh_port = None
    for port in host["ports"]:
        if port["name"] == "ssh" or "openssh" in port["product"].lower():
            ssh_port = port
            break
    if ssh_port:
        vtext = ssh_port["service_str"].lower()
        if "ubuntu" in vtext and "8.9p1" in vtext:
            match = re.search(r"3ubuntu0\.(\d+)", vtext)
            patch = int(match.group(1)) if match else 0
            if patch < 10:
                add_finding(
                    findings, "ALTO", "OpenSSH 8.9p1 vulnerable a regreSSHion", ip,
                    f"{ssh_port['service_str']} (build anterior a 3ubuntu0.10).",
                    "apt update && apt upgrade openssh-server; reiniciar sshd.",
                    ["CVE-2024-6387"],
                )
            elif patch < 18:
                add_finding(
                    findings, "BAJO", "OpenSSH algo atrasado", ip,
                    f"{ssh_port['service_str']} (hay builds más recientes, p. ej. 3ubuntu0.18).",
                    "apt update && apt upgrade openssh-server.",
                )
            else:
                good.append(f"{ip}: {ssh_port['service_str']} incluye el parche de regreSSHion.")
        elif "ubuntu" in vtext and "9.6p1" in vtext:
            match = re.search(r"3ubuntu13\.(\d+)", vtext)
            patch = int(match.group(1)) if match else 0
            if patch < 3:
                add_finding(
                    findings, "ALTO", "OpenSSH 9.6p1 vulnerable a regreSSHion", ip,
                    f"{ssh_port['service_str']} (build anterior a 3ubuntu13.3).",
                    "apt update && apt upgrade openssh-server; reiniciar sshd.",
                    ["CVE-2024-6387"],
                )
            elif patch < 20:
                add_finding(
                    findings, "BAJO", "OpenSSH algo atrasado", ip,
                    f"{ssh_port['service_str']} (hay builds más recientes, p. ej. 3ubuntu13.20).",
                    "apt update && apt upgrade openssh-server.",
                )
            else:
                good.append(f"{ip}: {ssh_port['service_str']} incluye el parche de regreSSHion.")
        elif "debian" in vtext and "9.2p1" in vtext:
            match = re.search(r"deb12u(\d+)", vtext)
            patch = int(match.group(1)) if match else 0
            if patch < 3:
                add_finding(
                    findings, "ALTO", "OpenSSH 9.2p1 vulnerable a regreSSHion", ip,
                    f"{ssh_port['service_str']} (build anterior a 2+deb12u3).",
                    "apt update && apt upgrade openssh-server; reiniciar sshd.",
                    ["CVE-2024-6387"],
                )
            else:
                good.append(f"{ip}: {ssh_port['service_str']} incluye el parche de regreSSHion.")
        elif "ubuntu" in vtext and "9.9p1" in vtext:
            add_finding(
                findings, "MEDIO", "Ubuntu intermedio (25.04/25.10) EOL", ip,
                f"{ssh_port['service_str']} corresponde a una Ubuntu interim, no LTS; su soporte termina antes.",
                "Migrar a Ubuntu 24.04 LTS o 26.04 LTS; confirmar con lsb_release -a.",
            )

    # --- Puertos altos no identificados ------------------------------------
    if 44469 in ports:
        add_finding(
            findings, "MEDIO", "Servicio no identificado en 44469", ip,
            "Acepta HTTP/2 h2c/gRPC y no se ha identificado; superficie desconocida.",
            "Identificar con ss -lntp en el nodo y cerrar en firewall si no es necesario.",
        )
    unknown_high = [
        p for p in host["ports"]
        if p["port"] >= 10000
        and p["port"] != 44469
        and (
            p["name"] in ("unknown", "tcpwrapped", "")
            or "?" in p["name"]
            or not p["product"]
        )
    ]
    if unknown_high:
        port_list = ", ".join(str(p["port"]) for p in unknown_high)
        if len(host["ports"]) == 1 and not host.get("hostnames"):
            add_finding(
                findings, "MEDIO", "Dispositivo no identificado con puerto abierto", ip,
                f"MAC {mac or 'desconocida'}; único puerto abierto: {port_list}/tcp, sin banner HTTP/TLS.",
                "Identificar el dispositivo (DHCP/ARP/UI del router) y cerrar el puerto si no se usa.",
            )
        else:
            add_finding(
                findings, "INFO", "Puerto alto no identificado", ip,
                f"Puertos abiertos sin servicio identificado: {port_list}/tcp.",
                "Identificar con ss -lntp y documentar o cerrar.",
            )

    # --- Guest Proxmox -----------------------------------------------------
    if mac.startswith("BC:24:11"):
        add_finding(
            findings, "INFO", "Guest de Proxmox (LXC/VM)", ip,
            f"MAC {mac}, prefijo BC:24:11 asignado por Proxmox.",
            "Confirmar si es LXC o VM, su función y que no exponga servicios innecesarios.",
        )

    # --- Sin puertos -------------------------------------------------------
    if not host["ports"]:
        add_finding(
            findings, "INFO", "Sin puertos TCP abiertos", ip,
            "No se detectaron puertos TCP abiertos en el escaneo.",
            "Sin acción; probablemente equipo cliente con firewall local.",
        )


# ---------------------------------------------------------------------------
# Informe HTML
# ---------------------------------------------------------------------------

def is_locally_administered(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02)
    except Exception:
        return False


def build_html(
    target: str,
    scanned_at: str,
    hosts: list[dict],
    findings: list[dict],
    good: list[str],
    proxmox: dict,
) -> str:
    e = html_lib.escape
    open_ports = sum(len(h["ports"]) for h in hosts)
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEV_ORDER}

    inventory_rows: list[str] = []
    for host in hosts:
        mac = host.get("mac") or "—"
        vendor = host.get("vendor") or ""
        mac_html = e(mac)
        if vendor:
            mac_html += f"<br><span class='muted'>{e(vendor)}</span>"
        if host.get("mac") and is_locally_administered(host["mac"]):
            mac_html += "<br><span class='muted'>MAC local/aleatoria</span>"

        ports_html = ", ".join(
            f"{p['port']}/{e(p['name'] or '?')}" for p in host["ports"]
        ) or "—"

        notes: list[str] = []
        if host.get("hostnames"):
            notes.append("DNS: " + ", ".join(host["hostnames"]))
        if host.get("vendor"):
            notes.append(host["vendor"])
        notes_html = "<br>".join(e(n) for n in notes) if notes else "—"

        inventory_rows.append(
            "<tr>"
            f"<td><strong>{e(host['ip'])}</strong></td>"
            f"<td>{mac_html}</td>"
            f"<td>{e(host.get('type', '—'))}<br><span class='muted'>{e(host.get('os', '—'))}</span></td>"
            f"<td>{ports_html}</td>"
            f"<td>{notes_html}</td>"
            "</tr>"
        )

    finding_cards: list[str] = []
    for finding in findings:
        cls = SEV_CLASS.get(finding["severity"], "info")
        cves = ""
        if finding.get("cves"):
            cves = (
                "<p class='cves'><strong>CVEs:</strong> "
                + ", ".join(f"<code>{e(c)}</code>" for c in finding["cves"])
                + "</p>"
            )
        finding_cards.append(
            f"<article class='finding {cls}'>"
            "<div class='finding-head'>"
            f"<span class='badge {cls}'>{e(finding['severity'])}</span>"
            f"<h3>{e(finding['title'])}</h3>"
            f"<span class='host-chip'>{e(finding['host'])}</span>"
            "</div>"
            f"<p><strong>Evidencia:</strong> {e(finding['evidence'])}</p>"
            f"<p><strong>Recomendación:</strong> {e(finding['recommendation'])}</p>"
            f"{cves}"
            "</article>"
        )
    if not finding_cards:
        finding_cards.append(
            "<p class='ok'>No se han detectado hallazgos con las reglas actuales. "
            "Revisa igualmente el detalle de puertos y versiones.</p>"
        )

    host_details: list[str] = []
    for host in hosts:
        rows: list[str] = []
        for port in host["ports"]:
            scripts_html = "—"
            if port.get("scripts"):
                blocks: list[str] = []
                for script_id, output in port["scripts"].items():
                    output = output.strip()
                    if len(output) > 600:
                        output = output[:600] + "…"
                    blocks.append(
                        f"<strong>{e(script_id)}</strong>:<br><code>{e(output)}</code>"
                    )
                scripts_html = "<br>".join(blocks)
            rows.append(
                "<tr>"
                f"<td>{port['port']}/{e(port['proto'])}</td>"
                f"<td>{e(port['name'] or '—')}</td>"
                f"<td>{e(port['service_str'] or '—')}</td>"
                f"<td class='scripts'>{scripts_html}</td>"
                "</tr>"
            )

        if rows:
            table = (
                "<div class='table-wrap'><table>"
                "<thead><tr><th>Puerto</th><th>Servicio</th><th>Versión / banner</th><th>Scripts NSE</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table></div>"
            )
        else:
            table = "<p class='muted'>Sin puertos TCP abiertos.</p>"

        hostscripts = ""
        if host.get("hostscripts"):
            blocks = []
            for script_id, output in host["hostscripts"].items():
                output = output.strip()
                if len(output) > 800:
                    output = output[:800] + "…"
                blocks.append(f"<strong>{e(script_id)}</strong>:<br><code>{e(output)}</code>")
            hostscripts = (
                "<details><summary>Scripts de host</summary>"
                f"<pre>{'<br>'.join(blocks)}</pre></details>"
            )

        host_details.append(
            f"<details class='host'><summary>{e(host['ip'])} "
            f"<span>· {e(host.get('type', '—'))} · {e(host.get('os', '—'))} · "
            f"{len(host['ports'])} puerto(s)</span></summary>"
            f"<div class='inner'>{table}{hostscripts}</div></details>"
        )

    good_html = ""
    if good:
        good_html = (
            "<h2>Comprobaciones que salieron bien</h2><ul>"
            + "".join(f"<li>{e(item)}</li>" for item in good)
            + "</ul>"
        )

    proxmox_html = ""
    if proxmox.get("cluster") or proxmox.get("guests"):
        cluster = e(proxmox.get("cluster") or "—")
        pve_version = e(proxmox.get("version") or "—")
        nodes_count = e(proxmox.get("nodes_count") or "—")
        quorum = "OK" if str(proxmox.get("quorate")) == "1" else "revisar"
        source_line = (
            f" · exportado por {e(proxmox.get('source_ip', ''))}"
            if proxmox.get("source_ip") else ""
        )
        nodes = ", ".join(
            f"{e(n.get('name', '?'))} (nodeid {e(n.get('nodeid', '?'))})"
            for n in proxmox.get("nodes", [])
        ) or "—"

        guest_rows: list[str] = []
        guests = sorted(
            proxmox.get("guests", []),
            key=lambda g: int(g.get("id", "0/0").split("/")[-1])
            if g.get("id", "0/0").split("/")[-1].isdigit() else 0,
        )
        for guest in guests:
            gid = guest.get("id", "")
            kind, _, vmid = gid.partition("/")
            guest_rows.append(
                "<tr>"
                f"<td>{e(vmid)}</td>"
                f"<td>{e(guest.get('name', '—'))}</td>"
                f"<td>{e(guest.get('node', '—'))}</td>"
                f"<td>{e((kind or guest.get('type', '—')).upper())}</td>"
                f"<td>{e(guest.get('tags', '') or '—')}</td>"
                "</tr>"
            )
        guest_table = ""
        if guest_rows:
            guest_table = (
                "<div class='table-wrap'><table>"
                "<thead><tr><th>VMID</th><th>Nombre</th><th>Nodo</th><th>Tipo</th><th>Tags</th></tr></thead>"
                f"<tbody>{''.join(guest_rows)}</tbody></table></div>"
            )

        proxmox_html = f"""
  <h2>Inventario Proxmox</h2>
  <p>Clúster <strong>{cluster}</strong> · {nodes_count} nodos · quórum {quorum} · Proxmox VE {pve_version}{source_line}</p>
  <p class="muted">Nodos: {nodes}. Guests definidos: {len(guests)} (el exporter no indica estado running).</p>
  {guest_table}
"""

    counts_cards = "".join(
        f"<div class='stat {SEV_CLASS[sev]}'><span class='num'>{counts[sev]}</span>"
        f"<span class='lbl'>{sev.lower()}s</span></div>"
        for sev in ("CRÍTICO", "ALTO", "MEDIO", "BAJO")
    )

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoría de red {e(target)}</title>
<style>{CSS}</style>
</head>
<body id="top">
<div class="wrap">
  <header class="hero">
    <div class="kicker">Auditoría defensiva de red</div>
    <h1>Informe de red <span class="accent">{e(target)}</span></h1>
    <p class="sub">Generado el {e(scanned_at)} · {len(hosts)} hosts · {open_ports} puertos abiertos · {len(findings)} hallazgos</p>
    <div class="legend">
      <span class="badge crit">Crítico</span>
      <span class="badge high">Alto</span>
      <span class="badge med">Medio</span>
      <span class="badge low">Bajo</span>
      <span class="badge info">Info</span>
    </div>
    <div class="hero-actions">
      <button onclick="window.print()">Imprimir / guardar PDF</button>
    </div>
  </header>

  <h2>Resumen</h2>
  <div class="stats">
    <div class="stat"><span class="num">{len(hosts)}</span><span class="lbl">hosts</span></div>
    <div class="stat"><span class="num">{open_ports}</span><span class="lbl">puertos abiertos</span></div>
    <div class="stat"><span class="num">{len(findings)}</span><span class="lbl">hallazgos</span></div>
    {counts_cards}
  </div>

  <h2>Inventario de hosts</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th>IP</th><th>MAC / OUI</th><th>Tipo / SO (inferido)</th><th>Puertos TCP</th><th>Notas</th></tr></thead>
      <tbody>{''.join(inventory_rows) if inventory_rows else '<tr><td colspan="5" class="muted">No se encontraron hosts activos.</td></tr>'}</tbody>
    </table>
  </div>

  {proxmox_html}

  <h2>Hallazgos de seguridad</h2>
  {''.join(finding_cards)}

  {good_html}

  <h2>Detalle por host</h2>
  {''.join(host_details) if host_details else '<p class="muted">Sin hosts que mostrar.</p>'}

  <h2>Metodología y limitaciones</h2>
  <p>Escaneo TCP no autenticado con <code>nmap -sT -sV</code> y scripts NSE seguros
  (<code>banner,http-title,http-headers,ssl-cert,ssh-hostkey,rpcinfo</code>).
  No se probaron credenciales, no se explotaron vulnerabilidades y no se modificó ningún sistema.</p>
  <ul>
    <li>Sin root no hay <em>OS fingerprint</em> ni escaneo UDP; el SO es una inferencia por banners y puertos.</li>
    <li>Las reglas EOL/CVE son heurísticas y deben confirmarse con los avisos oficiales del fabricante.</li>
    <li>La asignación exacta IP → guest Proxmox requiere DHCP o la API de Proxmox con credenciales.</li>
    <li>La exposición desde WAN no se puede verificar desde dentro de la LAN.</li>
  </ul>
  <p class="muted">Comandos principales: <code>nmap -sn</code> y
  <code>nmap -sT -sV -Pn -T4 --open</code>; el modo rápido usa el top-N de
  <code>nmap-services</code> más puertos curados (Proxmox, exporters, paneles,
  TR-069...). El modo completo usa <code>-p-</code>.
  Los XML crudos se guardan junto al informe en <code>raw/</code>.</p>

  <footer>
    Generado por <strong>auditoria_red.py</strong> v{VERSION} · Solo para redes propias o con autorización expresa.
  </footer>
</div>
<a href="#top" class="top" title="Volver arriba">↑</a>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Auditoría defensiva de una red local con nmap e informe HTML.",
    )
    parser.add_argument("-r", "--range", dest="target_range", help="Rango CIDR o IP (ej. 192.168.1.0/24)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="Escanear los 65535 puertos TCP")
    mode.add_argument("--quick", action="store_true", help="Escanear solo los top-ports")
    parser.add_argument("--top-ports", type=int, default=1000, help="Top-ports TCP del modo rápido (default: 1000)")
    parser.add_argument("--no-scripts", action="store_true", help="No ejecutar scripts NSE")
    parser.add_argument("--open", action="store_true", help="Abrir el informe al terminar")
    parser.add_argument("--no-browser", action="store_true", help="No preguntar por abrir el navegador")
    parser.add_argument("-y", "--yes", action="store_true", help="No pedir confirmación para rangos públicos")
    parser.add_argument("-o", "--output-dir", default=None, help="Directorio de salida (default: ./informes)")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        print("ERROR: nmap no está instalado.")
        print("  Arch:          sudo pacman -S nmap")
        print("  Debian/Ubuntu: sudo apt install nmap")
        return 1
    if not shutil.which("curl"):
        print("[!] curl no está instalado: se omitirán las comprobaciones HTTP (pve-exporter, Promtail, etc.).")

    raw_target = args.target_range
    if not raw_target:
        raw_target = ask(f"Rango a auditar [{DEFAULT_RANGE}]: ", DEFAULT_RANGE)

    while True:
        try:
            network = ipaddress.ip_network(raw_target, strict=False)
            break
        except ValueError as exc:
            print(f"  Rango no válido: {exc}")
            raw_target = ask(f"Rango a auditar [{DEFAULT_RANGE}]: ", DEFAULT_RANGE)

    target = str(network)
    if not network.is_private and not args.yes:
        print("\n⚠  El rango no es privado (RFC1918). Un escaneo a Internet puede ser ilegal o molesto.")
        if ask("Escribe SI para continuar: ").upper() != "SI":
            print("Cancelado.")
            return 1

    if args.full:
        full = True
    elif args.quick:
        full = False
    else:
        full = ask_yes_no("¿Escaneo completo de los 65535 puertos TCP? (mucho más lento) [s/N]: ", False)

    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else Path(__file__).resolve().parent / "informes"
    )
    raw_dir = output_dir / "raw"
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    now = dt.datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    scanned_at = now.strftime("%Y-%m-%d %H:%M:%S")
    slug = re.sub(r"[^0-9A-Za-z]+", "_", target).strip("_") or "red"
    prefix = f"{slug}_{timestamp}"

    print("\n" + "=" * 68)
    print(f" Auditoría de red — {target}")
    print(f" Fecha: {scanned_at}")
    print(f" Modo: {'completo (65535 TCP)' if full else f'top-ports ({args.top_ports})'}")
    print(f" Salida: {output_dir}")
    print("=" * 68)

    # 1. Descubrimiento
    discovery_xml = raw_dir / f"discovery_{prefix}.xml"
    print("\n[*] Descubrimiento de hosts...")
    run_stream(["nmap", "-sn", "-oX", str(discovery_xml), target])
    discovered = parse_nmap(discovery_xml) if discovery_xml.exists() else []

    # Completar con IPs vistas en la tabla ARP/neigh: un host que no responde
    # al descubrimiento pero tiene MAC cacheada puede seguir siendo escaneable.
    neighbors = neighbor_macs()
    known_ips = {h["ip"] for h in discovered}
    for ip, mac in neighbors.items():
        if ip in known_ips:
            continue
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.version != network.version or address not in network:
            continue
        discovered.append(
            {"ip": ip, "mac": mac, "vendor": "", "hostnames": [], "ports": [], "hostscripts": {}}
        )
        known_ips.add(ip)

    # 2. Preescaneo de puertos clave (rápido y fiable incluso en hosts filtrados)
    scan_targets = [h["ip"] for h in discovered] or [target]
    pre_ports = sorted(CURATED_PORTS - SLOW_PORTS)
    pre_xml = raw_dir / f"prescan_{prefix}.xml"
    pre_cmd = ["nmap", "-sT", "-sV", "-Pn", "-T4", "--open", "-oX", str(pre_xml)]
    if not args.no_scripts:
        pre_cmd += [
            "--script",
            "banner,http-title,http-headers,ssl-cert,ssh-hostkey,rpcinfo",
            "--script-timeout", "30s",
        ]
    pre_cmd += [
        "-p", ",".join(str(p) for p in pre_ports),
        "--min-rate", "300", "--max-retries", "1",
        "--host-timeout", "300s",
    ]
    pre_cmd += scan_targets
    print(f"\n[*] Preescaneo de puertos clave ({len(scan_targets)} host(s))...")
    run_stream(pre_cmd)
    pre_hosts = parse_nmap(pre_xml) if pre_xml.exists() else []

    # 2b. Puertos sin servicio conocido: solo comprobar si están abiertos.
    unknown_xml = raw_dir / f"unknown_ports_{prefix}.xml"
    unknown_ports = ",".join(str(p) for p in sorted(SLOW_PORTS))
    unknown_cmd = [
        "nmap", "-sT", "-Pn", "-T4", "--open", "-oX", str(unknown_xml),
        "-p", unknown_ports, "--max-retries", "1", "--host-timeout", "60s",
    ] + scan_targets
    print("\n[*] Comprobación de puertos altos no identificados...")
    run_stream(unknown_cmd)
    unknown_hosts = parse_nmap(unknown_xml) if unknown_xml.exists() else []

    # 3. Escaneo principal
    scan_xml = raw_dir / f"scan_{prefix}.xml"
    print(f"\n[*] Escaneo principal y detección de versiones ({len(scan_targets)} host(s))...")
    cmd = ["nmap", "-sT", "-sV", "-Pn", "-T4", "--open", "-oX", str(scan_xml)]
    if not args.no_scripts:
        cmd += [
            "--script",
            "banner,http-title,http-headers,ssl-cert,ssh-hostkey,rpcinfo",
            "--script-timeout", "30s",
        ]
    if full:
        cmd += [
            "-p-", "--exclude-ports", curated_port_list(),
            "--min-rate", "1000", "--max-retries", "2",
            "--host-timeout", "300s",
        ]
        print("    (el escaneo completo puede tardar varios minutos)")
    else:
        top_ports = top_port_list(args.top_ports, exclude=CURATED_PORTS)
        if not top_ports:
            print("    (sin puertos top adicionales; se usa solo el preescaneo)")
            cmd = []
        else:
            cmd += [
                "-p", top_ports,
                "--min-rate", "300", "--max-retries", "1",
                "--host-timeout", "120s",
            ]
    if cmd:
        cmd += scan_targets
        run_stream(cmd)
        scanned = parse_nmap(scan_xml) if scan_xml.exists() else []
    else:
        scanned = []

    hosts = merge_hosts(
        merge_hosts(merge_hosts(discovered, pre_hosts), unknown_hosts),
        scanned,
    )
    enrich_macs(hosts)
    local_ips = local_ipv4_addresses()
    for host in hosts:
        if host["ip"] in local_ips:
            host["auditor"] = True
    print(f"\n[+] Hosts activos: {len(hosts)}")

    # 3. Análisis
    findings: list[dict] = []
    good: list[str] = []
    proxmox: dict = {
        "cluster": "", "nodes_count": "", "quorate": "",
        "version": "", "source_ip": "", "nodes": [], "guests": [],
    }
    for host in hosts:
        classify(host)
        analyze_host(host, findings, good, proxmox)

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["host"], f["title"]))

    sensitive_ports = {445, 3306, 5432, 6379, 27017, 9200}
    if not any(p["port"] in sensitive_ports for h in hosts for p in h["ports"]):
        good.append("No se detectaron puertos de SMB, bases de datos ni Redis expuestos.")

    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEV_ORDER}
    print(
        "    Hallazgos: "
        + ", ".join(f"{counts[s]} {s.lower()}" for s in ("CRÍTICO", "ALTO", "MEDIO", "BAJO"))
    )

    # 4. Informe
    html_doc = build_html(target, scanned_at, hosts, findings, good, proxmox)
    html_path = output_dir / f"informe_{prefix}.html"
    json_path = output_dir / f"informe_{prefix}.json"
    html_path.write_text(html_doc, encoding="utf-8")

    summary = {
        "target": target,
        "scanned_at": scanned_at,
        "mode": "full" if full else f"top-ports-{args.top_ports}",
        "hosts": hosts,
        "findings": findings,
        "good_checks": good,
        "proxmox": proxmox,
        "counts": counts,
    }
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n[+] Informe HTML: {html_path}")
    print(f"[+] Resumen JSON: {json_path}")
    print(f"[+] XML crudo:    {scan_xml}")

    if args.open:
        webbrowser.open(html_path.as_uri())
    elif not args.no_browser:
        if ask_yes_no("¿Abrir el informe en el navegador? [s/N]: ", False):
            webbrowser.open(html_path.as_uri())

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelado por el usuario.")
        sys.exit(130)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OVERSEER — visor local de los informes de auditoria_red2.py.

Lee todos los JSON de ../informes/, los agrega por IP y sirve una UI web.
Sin dependencias externas: solo la biblioteca estándar de Python.

Uso:
    python3 server.py
    python3 server.py --port 8770 --open
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import threading
import webbrowser
from collections import Counter
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR.parent / "informes"
ANNOTATIONS_PATH = BASE_DIR / "annotations.json"

SEV_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]
SEV_WEIGHT = {"CRÍTICO": 30, "ALTO": 15, "MEDIO": 6, "BAJO": 2, "INFO": 0}
TYPE_OPTIONS = [
    "",
    "Nodo Proxmox",
    "LXC",
    "VM",
    "Router",
    "Servidor",
    "Cliente / IoT",
    "Dispositivo",
    "Este equipo",
]

LOCK = threading.Lock()


def load_annotations() -> dict:
    try:
        data = json.loads(ANNOTATIONS_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_annotations(data: dict) -> None:
    tmp = ANNOTATIONS_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(ANNOTATIONS_PATH)


def read_reports() -> list[dict]:
    reports: list[dict] = []
    if not REPORTS_DIR.is_dir():
        return reports
    for path in REPORTS_DIR.glob("informe_*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict) or "hosts" not in data:
            continue
        data["_file"] = path.name
        reports.append(data)
    reports.sort(key=lambda r: str(r.get("scanned_at", "")))
    return reports


def ip_key(value: str):
    try:
        ip = ipaddress.ip_address(value)
        return (ip.version, int(ip))
    except ValueError:
        return (99, value)


def risk_score(ip: str, findings: list[dict]) -> int:
    return min(
        100,
        sum(
            SEV_WEIGHT.get(f.get("severity", ""), 0)
            for f in findings
            if f.get("host") == ip
        ),
    )


def risk_meta(score: int, counts: dict, total: int) -> dict:
    crit = counts.get("CRÍTICO", 0)
    if total == 0:
        label, cls = "Sin hallazgos", "ok"
    elif score >= 70 and crit > 0:
        label, cls = "Crítico", "crit"
    elif score >= 70:
        label, cls = "Muy alto", "high"
    elif crit > 0 or score >= 40:
        label, cls = "Alto", "high"
    elif score >= 20:
        label, cls = "Medio", "med"
    elif score > 0:
        label, cls = "Bajo", "low"
    else:
        label, cls = "Informativo", "info"
    return {"score": score, "label": label, "cls": cls}


def effective_type(host: dict) -> str:
    return host.get("type_override") or host.get("type") or "Desconocido"


def build_payload() -> dict:
    reports = read_reports()
    annotations = load_annotations()

    host_map: dict[str, dict] = {}
    for rep in reports:
        scanned = str(rep.get("scanned_at", ""))
        findings = rep.get("findings", []) or []
        for host in rep.get("hosts", []) or []:
            ip = host.get("ip")
            if not ip:
                continue
            entry = host_map.setdefault(
                ip, {"ip": ip, "history": [], "first_seen": scanned}
            )
            if not any(h["scanned_at"] == scanned for h in entry["history"]):
                entry["history"].append(
                    {
                        "scanned_at": scanned,
                        "file": rep.get("_file", ""),
                        "target": rep.get("target", ""),
                        "mode": rep.get("mode", ""),
                        "type": host.get("type", ""),
                        "os": host.get("os", ""),
                        "ports": len(host.get("ports", []) or []),
                        "risk": risk_score(ip, findings),
                    }
                )
            if scanned >= entry.get("last_seen", ""):
                entry["last_seen"] = scanned
                entry["host"] = host
                entry["findings"] = [
                    f for f in findings if f.get("host") == ip
                ]

    hosts: list[dict] = []
    for ip, entry in host_map.items():
        host = dict(entry.get("host") or {})
        host["ip"] = ip
        ann = annotations.get(ip) or {}
        if ann.get("type"):
            host["type_override"] = ann["type"]
        if ann.get("name"):
            host["name"] = ann["name"]

        host_findings = entry.get("findings", []) or []
        counts = {
            sev: sum(1 for f in host_findings if f.get("severity") == sev)
            for sev in SEV_ORDER
        }
        score = risk_score(ip, host_findings)
        host["findings"] = host_findings
        host["severity_counts"] = counts
        host["max_severity"] = next((s for s in SEV_ORDER if counts[s] > 0), None)
        host["risk"] = score
        host["risk_meta"] = risk_meta(score, counts, len(host_findings))
        host["history"] = sorted(
            entry.get("history", []), key=lambda h: h.get("scanned_at", "")
        )
        host["first_seen"] = entry.get("first_seen", "")
        host["last_seen"] = entry.get("last_seen", "")
        host["seen_count"] = len(host["history"])
        hosts.append(host)

    hosts.sort(key=lambda h: ip_key(h["ip"]))

    latest = reports[-1] if reports else {}
    latest_hosts = latest.get("hosts", []) or []
    latest_findings = latest.get("findings", []) or []
    counts = latest.get("counts") or {
        sev: sum(1 for f in latest_findings if f.get("severity") == sev)
        for sev in SEV_ORDER
    }
    total_findings = len(latest_findings)
    global_score = min(
        100, sum(SEV_WEIGHT.get(f.get("severity", ""), 0) for f in latest_findings)
    )

    port_counter: Counter[int] = Counter()
    port_names: dict[int, str] = {}
    service_counter: Counter[str] = Counter()
    for host in latest_hosts:
        for port in host.get("ports", []) or []:
            num = port.get("port")
            if num is None:
                continue
            port_counter[num] += 1
            if port.get("name"):
                port_names.setdefault(num, port["name"])
        for port in host.get("ports", []) or []:
            service_counter[port.get("name") or "desconocido"] += 1

    type_counter = Counter(effective_type(h) for h in hosts)

    global_data = {
        "target": latest.get("target", ""),
        "scanned_at": latest.get("scanned_at", ""),
        "mode": latest.get("mode", ""),
        "file": latest.get("_file", ""),
        "counts": counts,
        "total_findings": total_findings,
        "risk": risk_meta(global_score, counts, total_findings),
        "total_hosts": len(latest_hosts),
        "hosts_with_ports": sum(1 for h in latest_hosts if h.get("ports")),
        "total_ports": sum(len(h.get("ports", []) or []) for h in latest_hosts),
        "unique_services": len(
            {p.get("name") for h in latest_hosts for p in h.get("ports", []) if p.get("name")}
        ),
        "type_counts": dict(type_counter.most_common()),
        "top_ports": [
            {"port": num, "count": count, "name": port_names.get(num, "?")}
            for num, count in port_counter.most_common(10)
        ],
        "top_services": [
            {"name": name, "count": count}
            for name, count in service_counter.most_common(10)
        ],
        "top_hosts": [
            {
                "ip": h["ip"],
                "risk": h["risk"],
                "risk_meta": h["risk_meta"],
                "type": effective_type(h),
                "os": h.get("os", ""),
                "severity_counts": h["severity_counts"],
                "findings": len(h["findings"]),
            }
            for h in sorted(hosts, key=lambda x: (-x["risk"], ip_key(x["ip"])))[:10]
            if h["risk"] > 0
        ],
        "findings": latest_findings,
        "good_checks": latest.get("good_checks", []) or [],
        "proxmox": latest.get("proxmox", {}) or {},
    }

    scans = [
        {
            "file": rep.get("_file", ""),
            "scanned_at": rep.get("scanned_at", ""),
            "target": rep.get("target", ""),
            "mode": rep.get("mode", ""),
            "hosts": len(rep.get("hosts", []) or []),
            "findings": len(rep.get("findings", []) or []),
        }
        for rep in reports
    ]

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reports_count": len(reports),
        "reports_dir": str(REPORTS_DIR),
        "scans": scans,
        "latest": {
            "scanned_at": latest.get("scanned_at", ""),
            "target": latest.get("target", ""),
            "mode": latest.get("mode", ""),
            "file": latest.get("_file", ""),
        },
        "global": global_data,
        "hosts": hosts,
        "annotations": annotations,
        "type_options": TYPE_OPTIONS,
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, fmt, *args):  # silencio en consola
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/data":
            try:
                self.send_json(200, build_payload())
            except Exception as exc:  # noqa: BLE001
                self.send_json(500, {"error": str(exc)})
            return
        if path == "/api/health":
            self.send_json(200, {"ok": True, "reports": len(read_reports())})
            return
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/annotations":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 10000:
                raise ValueError("cuerpo inválido")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            ip = str(body.get("ip", "")).strip()
            ipaddress.ip_address(ip)
            type_value = str(body.get("type", "")).strip()
            name = str(body.get("name", "")).strip()[:80]
            if type_value and type_value not in TYPE_OPTIONS:
                raise ValueError("tipo no permitido")
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)})
            return

        with LOCK:
            annotations = load_annotations()
            current = dict(annotations.get(ip) or {})
            if type_value:
                current["type"] = type_value
            else:
                current.pop("type", None)
            if name:
                current["name"] = name
            else:
                current.pop("name", None)
            if current:
                annotations[ip] = current
            else:
                annotations.pop(ip, None)
            save_annotations(annotations)

        self.send_json(200, {"ok": True, "annotations": annotations})


def main() -> int:
    parser = argparse.ArgumentParser(description="OVERSEER — visor de auditorías de red")
    parser.add_argument("--port", type=int, default=8770, help="puerto local (default 8770)")
    parser.add_argument("--host", default="127.0.0.1", help="interfaz de escucha (default 127.0.0.1)")
    parser.add_argument("--open", action="store_true", help="abrir el navegador al arrancar")
    args = parser.parse_args()

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        print(f"ERROR: no se pudo abrir {args.host}:{args.port} — {exc}")
        print("Prueba con otro puerto: python3 server.py --port 8771")
        return 1

    url = f"http://{args.host}:{args.port}/"
    print("=" * 62)
    print("  OVERSEER — network intelligence")
    print(f"  Informes: {REPORTS_DIR}")
    print(f"  Abre:     {url}")
    print("  Ctrl+C para parar")
    print("=" * 62)
    if args.open:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

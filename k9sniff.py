#!/usr/bin/env python3
"""
K9Sniff — Lightweight Web/API Triage Scanner
- HTTP security header checks + banner leak + basic TLS reachability
- Optional Nmap service scan (if 'nmap' is available)
- Optional Nuclei ingestion (if 'nuclei' is available)
- Reports: reports/report.html, reports/summary.json, reports/junit.xml

Usage:
  python k9sniff.py --targets https://example.com,https://juice.shop --out ./reports
  python k9sniff.py --targets https://example.com --with-nmap --with-nuclei

Exit codes:
  0: no High/Critical findings
  1: at least one High/Critical finding
"""
from __future__ import annotations
import argparse
import json
import re
import socket
import ssl
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from jinja2 import Environment, FileSystemLoader, select_autoescape

# ----------------------- Models -----------------------
@dataclass
class Evidence:
    key: str
    value: Any

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # info|low|medium|high|critical
    cvss: float
    description: str
    remediation: str
    evidence: List[Evidence]
    target: str

@dataclass
class TargetResult:
    target: str
    findings: List[Finding]
    services: List[Dict[str, Any]]
    nuclei: List[Dict[str, Any]]

# ----------------------- Utils ------------------------
SEC_HEADERS = [
    ("strict-transport-security", "HSTS preload recommended"),
    ("content-security-policy", "Define CSP to mitigate XSS/injection"),
    ("x-frame-options", "Prevent clickjacking"),
    ("x-content-type-options", "MIME sniffing protection"),
    ("referrer-policy", "Limit referer leakage"),
    ("permissions-policy", "Limit powerful features"),
]

def _which(cmd: str) -> bool:
    from shutil import which as _w
    return _w(cmd) is not None

def _norm_target(t: str) -> str:
    return t if re.match(r"^https?://", t, re.I) else f"http://{t}"

def _host_from_target(t: str) -> str:
    u = urlparse(_norm_target(t))
    return u.hostname or t

def _ensure_outdir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def _mkfinding(target: str, title: str, severity: str, cvss: float,
               desc: str, remediation: str, ev: Dict[str, Any]) -> Finding:
    evid = [Evidence(key=k, value=v) for k, v in ev.items()]
    # Stable-ish id per (target,title)
    fid = f"K9-{abs(hash((target, title))) % 100000}"
    return Finding(fid, title, severity, cvss, desc, remediation, evid, target)

# -------------------- HTTP checks ---------------------
def _https_supported(host: str, port: int = 443) -> bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False

def http_scan(target: str, timeout: float = 8.0) -> List[Finding]:
    turl = _norm_target(target)
    u = urlparse(turl)
    out: List[Finding] = []
    try:
        r = requests.get(turl, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}

        # Security headers
        for h, why in SEC_HEADERS:
            if h not in headers:
                sev, score = ("medium", 6.0) if h != "content-security-policy" else ("high", 7.5)
                out.append(_mkfinding(
                    turl, f"Missing security header: {h}", sev, score,
                    f"The response does not include '{h}' ({why}).",
                    f"Add appropriate '{h}' header per best practices.",
                    {"status_code": r.status_code, "observed_headers": list(headers.keys())[:60]},
                ))

        # Server banner
        if "server" in headers and headers["server"]:
            out.append(_mkfinding(
                turl, "Server banner exposed", "low", 3.1,
                "The 'Server' header reveals server software/version.",
                "Remove/minimize the banner or use a generic value.",
                {"server": headers["server"]},
            ))

        # TLS reachability (if plain HTTP)
        tls_ok = _https_supported(u.hostname or "")
        if not tls_ok and u.scheme == "http":
            out.append(_mkfinding(
                turl, "No HTTPS on default port", "medium", 5.3,
                "Target did not accept TLS on 443.",
                "Enable TLS with modern config; redirect HTTP→HTTPS.",
                {},
            ))
    except requests.RequestException as e:
        out.append(_mkfinding(
            turl, "HTTP request failed", "info", 0.0,
            "Network error or timeout during HTTP request.",
            "Verify target availability/firewall and URL correctness.",
            {"error": str(e)},
        ))
    return out

# --------------------- Nmap phase ---------------------
def nmap_scan(host: str) -> List[Dict[str, Any]]:
    """
    Runs: nmap -Pn -sV -T4 -oX - <host>
    Returns list of {port, proto, state, service, product, version}
    """
    if not _which("nmap"):
        return []
    try:
        cmd = ["nmap", "-Pn", "-sV", "-T4", "-oX", "-", host]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        if res.returncode != 0 or not res.stdout.strip():
            return []
        import xml.etree.ElementTree as ET
        root = ET.fromstring(res.stdout)
        items: List[Dict[str, Any]] = []
        for host_el in root.findall("host"):
            for port_el in host_el.findall("./ports/port"):
                portid = port_el.attrib.get("portid")
                proto = port_el.attrib.get("protocol")
                state = (port_el.find("./state") or {}).attrib.get("state", "")
                svc_el = port_el.find("./service")
                svc = svc_el.attrib.get("name", "") if svc_el is not None else ""
                prod = svc_el.attrib.get("product", "") if svc_el is not None else ""
                ver = svc_el.attrib.get("version", "") if svc_el is not None else ""
                items.append({"port": portid, "proto": proto, "state": state,
                              "service": svc, "product": prod, "version": ver})
        return items
    except Exception:
        return []

# -------------------- Nuclei phase --------------------
def nuclei_scan(url: str) -> tuple[List[Dict[str, Any]], List[Finding]]:
    """
    Runs: nuclei -u <url> -json -silent
    Returns (raw_json_lines, derived_findings)
    """
    if not _which("nuclei"):
        return [], []
    raw: List[Dict[str, Any]] = []
    findings: List[Finding] = []
    try:
        cmd = ["nuclei", "-u", url, "-json", "-silent"]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                raw.append(obj)
                sev = (obj.get("info", {}).get("severity") or "info").lower()
                sev_map = {"info": ("info", 0.0), "low": ("low", 3.1), "medium": ("medium", 5.5),
                           "high": ("high", 7.5), "critical": ("critical", 9.0)}
                s, cv = sev_map.get(sev, ("info", 0.0))
                findings.append(_mkfinding(
                    url,
                    title=obj.get("info", {}).get("name", obj.get("template-id", "Nuclei match")),
                    severity=s, cvss=cv,
                    desc=f"Nuclei template {obj.get('template-id','?')} matched.",
                    remediation="Review template guidance and apply fixes.",
                    ev=obj
                ))
        return raw, findings
    except Exception:
        return raw, findings

# --------------------- Reporting ----------------------
def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def write_junit(path: Path, high_crit_count: int) -> None:
    from xml.etree.ElementTree import Element, SubElement, tostring
    from xml.dom import minidom
    ts = Element("testsuite", name="K9Sniff", tests="1", failures=str(int(high_crit_count > 0)))
    tc = SubElement(ts, "testcase", classname="K9Sniff", name="triage")
    if high_crit_count > 0:
        fail = SubElement(tc, "failure", message=f"{high_crit_count} high/critical findings")
        fail.text = f"High/Critical: {high_crit_count}"
    pretty = minidom.parseString(tostring(ts)).toprettyxml(indent="  ")
    path.write_text(pretty, encoding="utf-8")

def write_html(template_path: Path, out_path: Path, summary: Dict[str, Any], results: List[TargetResult]) -> None:
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape()
    )
    tpl = env.get_template(template_path.name)
    html = tpl.render(summary=summary, results=[{
        "target": r.target,
        "findings": [asdict(f) | {"evidence": [asdict(e) for e in f.evidence]} for f in r.findings],
        "services": r.services,
        "nuclei": r.nuclei,
    } for r in results])
    out_path.write_text(html, encoding="utf-8")

# ---------------------- Runner ------------------------
def run(targets: List[str], outdir: Path, use_nmap: bool, use_nuclei: bool,
        timeout: float) -> int:
    outdir = _ensure_outdir(outdir)
    results: List[TargetResult] = []
    high_or_critical = 0

    for t in targets:
        turl = _norm_target(t)
        r = TargetResult(target=turl, findings=[], services=[], nuclei=[])

        # HTTP checks
        fnds = http_scan(turl, timeout=timeout)
        r.findings.extend(fnds)
        high_or_critical += sum(1 for f in fnds if f.severity in ("high", "critical"))

        # Nmap
        if use_nmap:
            r.services = nmap_scan(_host_from_target(turl))

        # Nuclei
        if use_nuclei:
            raw, nfnds = nuclei_scan(turl)
            r.nuclei = raw
            r.findings.extend(nfnds)
            high_or_critical += sum(1 for f in nfnds if f.severity in ("high", "critical"))

        results.append(r)

    summary = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "targets": targets,
        "counts": {
            "targets": len(targets),
            "findings_total": sum(len(r.findings) for r in results),
            "high_or_critical": high_or_critical,
        },
        "tools": {
            "nmap_used": use_nmap and _which("nmap"),
            "nuclei_used": use_nuclei and _which("nuclei"),
        },
    }

    # Artifacts
    write_json(outdir / "summary.json", {
        "summary": summary,
        "results": [{
            "target": r.target,
            "findings": [asdict(f) | {"evidence": [asdict(e) for e in f.evidence]} for f in r.findings],
            "services": r.services,
            "nuclei": r.nuclei,
        } for r in results]
    })
    write_html(Path(__file__).parent / "report_template.html",
               outdir / "report.html", summary, results)
    write_junit(outdir / "junit.xml", high_or_critical)

    return 1 if high_or_critical > 0 else 0

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="K9Sniff — Lightweight Web/API Triage Scanner")
    ap.add_argument("--targets", required=True, help="Comma-separated URLs/hosts")
    ap.add_argument("--out", default="./reports", help="Output directory")
    ap.add_argument("--with-nmap", action="store_true", help="Run Nmap (if available)")
    ap.add_argument("--with-nuclei", action="store_true", help="Run Nuclei (if available)")
    ap.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout (seconds)")
    return ap.parse_args()

def main() -> None:
    args = parse_args()
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    code = run(targets, Path(args.out), args.with_nmap, args.with_nuclei, args.timeout)
    raise SystemExit(code)

if __name__ == "__main__":
    main()

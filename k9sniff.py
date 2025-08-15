#!/usr/bin/env python3
import argparse, json, os, shlex, subprocess, sys
from datetime import datetime
from urllib.parse import urlparse
from jinja2 import Template

REPORT_TMPL = os.path.join(os.path.dirname(__file__), "report_template.html")

def run_cmd(cmd: str):
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def nmap_scan(host: str):
    code, out, err = run_cmd(f"nmap -sV -Pn -T4 {shlex.quote(host)}")
    if code != 0:
        return []
    services = []
    for line in out.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) < 2 or parts[1] != "open":
                continue
            try:
                port, proto = parts[0].split("/")
            except Exception:
                continue
            service = parts[2] if len(parts) > 2 else ""
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            services.append({"port": port, "proto": proto, "service": service, "version": version})
    return services

def nuclei_scan(target: str):
    code, _, _ = run_cmd("which nuclei")
    if code != 0:
        return []
    code, out, err = run_cmd(f"nuclei -u {shlex.quote(target)} -severity low,medium,high,critical -silent")
    if code != 0:
        return []
    findings = []
    for line in out.splitlines():
        sev = "low"
        if "[critical]" in line: sev = "critical"
        elif "[high]" in line: sev = "high"
        elif "[medium]" in line: sev = "medium"
        findings.append({
            "tool": "nuclei",
            "title": line.strip()[:120],
            "severity": sev,
            "severity_class": "high" if sev in ("high","critical") else ("med" if sev=="medium" else "low"),
            "description": line.strip()
        })
    return findings

def normalize_target(t: str) -> str:
    return t if "://" in t else f"http://{t}"

def render_html(target, services, findings, out_dir):
    with open(REPORT_TMPL, "r", encoding="utf-8") as f:
        html = Template(f.read()).render(
            target=target,
            timestamp=datetime.utcnow().isoformat() + "Z",
            services=services,
            findings=findings
        )
    os.makedirs(out_dir, exist_ok=True)
    outp = os.path.join(out_dir, "sample_report.html")
    with open(outp, "w", encoding="utf-8") as w:
        w.write(html)
    return outp

def main():
    ap = argparse.ArgumentParser(description="K9Sniff - lightweight vulnerability triage")
    ap.add_argument("--target", required=True, help="Domain/IP/URL (authorized targets only)")
    ap.add_argument("--out", default="./examples", help="Output directory")
    args = ap.parse_args()

    target = normalize_target(args.target)
    host = urlparse(target).hostname or target

    services = nmap_scan(host)
    findings = nuclei_scan(target)

    os.makedirs(args.out, exist_ok=True)
    json_path = os.path.join(args.out, "sample_findings.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"target": target, "services": services, "findings": findings}, f, indent=2)

    html_path = render_html(target, services, findings, args.out)
    print(f"[+] Wrote: {json_path}")
    print(f"[+] Wrote: {html_path}")
    print("[!] Use only on authorized, intentionally vulnerable targets.")

if __name__ == "__main__":
    main()

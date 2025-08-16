````markdown
# K9Sniff — Lightweight Web/API Triage Scanner

**K9Sniff** quickly triages web/API targets for common issues:
- HTTP(S) security headers, banner leakage, basic TLS reachability
- Optional **Nmap** service scan (if installed)
- Optional **Nuclei** run & JSONL ingestion (if installed)

Outputs:
- `reports/report.html` (human-readable)
- `reports/summary.json` (machine-readable)
- `reports/junit.xml` (CI gate)

> Use only on authorized systems and training labs (e.g., Juice Shop/crAPI). Missing tools are skipped gracefully.

---

## Requirements
- Python **3.10+**
- Optional: `nmap` and/or `nuclei` available on `PATH` for extra phases

## Install
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
# .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
````

## Quick Start

```bash
# Multiple targets (comma-separated)
python k9sniff.py --targets https://example.com,https://juice.shop --out ./reports
```

Enable optional phases (if installed):

```bash
# With Nmap
python k9sniff.py --targets https://example.com --with-nmap

# With Nuclei
python k9sniff.py --targets https://example.com --with-nuclei

# Both + custom timeout (seconds)
python k9sniff.py --targets https://example.com --with-nmap --with-nuclei --timeout 10 --out ./reports
```

**Exit codes**

* `0` — No High/Critical findings
* `1` — ≥1 High/Critical finding (suitable to fail CI)

---

## Command-Line Options

```
--targets        Comma-separated URLs/hosts (required)
--out            Output directory (default: ./reports)
--with-nmap      Run Nmap service scan (if nmap is available)
--with-nuclei    Run Nuclei templates and ingest JSONL (if nuclei is available)
--timeout        HTTP timeout in seconds (default: 8.0)
```

---

## Artifacts

* **HTML**: `reports/report.html` shows per-target findings, optional Nmap services, and (if enabled) raw Nuclei lines.
* **JSON**: `reports/summary.json` includes summary + per-target details (findings, services, nuclei).
* **JUnit**: `reports/junit.xml` marks the job failed if any High/Critical findings are present.

---

## CI (GitHub Actions)

Create `.github/workflows/k9sniff.yml`:

```yaml
name: K9Sniff
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: |
          python -m venv .venv
          source .venv/bin/activate
          pip install -r requirements.txt
          python k9sniff.py --targets https://example.com --out ./reports
      - uses: actions/upload-artifact@v4
        with:
          name: k9sniff-reports
          path: reports/
```

---

## Notes & Tips

* You can pass plain hosts (e.g., `example.com`); they are normalized to `http://example.com`.
* HTML is rendered from `report_template.html`. Customize styling or add evidence links if needed.
* To attach screenshots/raw bodies, modify `k9sniff.py` to save files under `reports/evidence/` and add their paths to finding `evidence`.

---

## Ethics

Run K9Sniff only on systems you own or have explicit permission to test. It is a **triage** tool; validate findings before remediation.

---

```
::contentReference[oaicite:0]{index=0}
```

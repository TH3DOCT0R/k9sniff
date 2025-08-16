```markdown
# K9Sniff — Lightweight Web/API Triage Scanner

K9Sniff quickly triages web/API targets for common misconfigurations and produces **HTML**, **JSON**, and **JUnit** artifacts that you can use locally or in CI to gate pull requests.

> Use only on systems you own or have explicit authorization to test.

---

## Features

- **HTTP triage**: security headers, banner exposure, basic TLS reachability.
- **Optional tool hooks** (auto-skip if missing):
  - **Nmap** — service discovery (`-sV` XML parsed).
  - **Nuclei** — JSONL ingestion into findings.
- **Reports**
  - `reports/report.html` (human)
  - `reports/summary.json` (machine)
  - `reports/junit.xml` (CI gate; fails on High/Critical)
- **Zero-crash philosophy**: missing tools/timeouts do not break the run.

---

## Directory

<details>
<summary><b>Show tree</b></summary>
<pre>
.
├─ .github/workflows/        # Optional CI workflow(s)
├─ examples/                 # Demo targets and fabricated sample outputs
├─ k9sniff.py                # Entry point (CLI)
├─ report_template.html      # HTML Jinja template
├─ requirements.txt          # Minimal deps
├─ README.md                 # This file
└─ LICENSE
</pre>
</details>

---

## Requirements

- Python **3.10+**
- Optional: `nmap` and/or `nuclei` available on `PATH` for extra phases

Install:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
# .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Single target
python k9sniff.py --target https://example.com --out ./reports

# Multiple targets (comma-separated)
python k9sniff.py --targets https://one.com,https://two.com --out ./reports
```

Enable optional phases (auto-skip if the tool isn’t installed):

```bash
# With Nmap
python k9sniff.py --targets https://example.com --with-nmap

# With Nuclei
python k9sniff.py --targets https://example.com --with-nuclei

# Both + custom timeout
python k9sniff.py --targets https://example.com --with-nmap --with-nuclei --timeout 10 --out ./reports
```

**Exit codes**
- `0` — No High/Critical findings
- `1` — ≥1 High/Critical finding (suitable to fail CI)

---

## CLI Options

```
--targets / --target   Comma-separated URLs/hosts (required)
--out                  Output directory (default: ./reports)
--with-nmap            Run Nmap service scan (if available)
--with-nuclei          Run Nuclei templates and ingest JSONL (if available)
--timeout              HTTP timeout in seconds (default: 8.0)
```

---

## Outputs

- **HTML**: `reports/report.html` — per-target findings, optional Nmap services, optional raw Nuclei lines (collapsed).
- **JSON**: `reports/summary.json` — summary + detailed per-target data (findings, services, nuclei).
- **JUnit**: `reports/junit.xml` — marks the job failed if any High/Critical findings are present.

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

## Examples

See `examples/`:
- `targets.txt` — demo target list (labs).
- `k9sniff_demo.sh` — drops fabricated sample artifacts into `./reports/`.
- `sample_report.html`, `sample_summary.json`, `junit_example.xml` — visual/machine examples.

---

## Ethics

Use K9Sniff only on authorized systems and training labs (e.g., Juice Shop/crAPI). It’s a **triage** aid; validate before remediation.

---

## License

MIT (see `LICENSE`).
```
MIT License

Copyright (c) 2025 Sajal Saraswat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
---



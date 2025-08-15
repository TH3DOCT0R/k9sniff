# K9Sniff — Lightweight Vulnerability Scanner (Academic, Reconstructed & Maintained)
**Stack:** Python 3.x, Nmap CLI (optional), Nuclei (optional), Jinja2

K9Sniff takes a domain/IP, runs a focused Nmap service scan, optionally calls Nuclei if present, and produces JSON + HTML triage reports.

> Use only on systems you own or are expressly authorized to test (e.g., OWASP Juice Shop/crAPI labs).

## Quick start
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python k9sniff.py --target http://example.com --out ./examples
open ./examples/sample_report.html
```

## Notes
- If **nmap** is not installed, scan gracefully skips (report still generated).
- If **nuclei** is not installed, nuclei phase is skipped.
- Output files land under `--out` (default `./examples`).

## Outputs
- `examples/sample_findings.json`
- `examples/sample_report.html`

## License
MIT

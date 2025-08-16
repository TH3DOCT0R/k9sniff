# K9Sniff Examples

This folder demonstrates how to run K9Sniff locally and in CI and what the outputs look like.
All outputs here are **fabricated** for illustration only—do not treat them as live scan results.

## What’s inside
- `targets.txt` — demo targets (authorized labs only).
- `k9sniff_demo.sh` — one-shot runner that produces artifacts under `./reports/`.
- `github_actions_demo.yml` — CI workflow you can copy to `.github/workflows/k9sniff.yml`.
- `sample_report.html` — a fully rendered, **visual** example report (fabricated).
- `sample_summary.json` — machine-readable example (fabricated).
- `junit_example.xml` — CI gate example when High/Critical findings exist.

## Quick use

```bash
# From repo root
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the demo (safe; uses fabricated outputs for samples)
bash examples/k9sniff_demo.sh
To scan real, authorized targets:

bash
Copy
Edit
python k9sniff.py --targets "$(tr '\n' ',' < examples/targets.txt | sed 's/,$//')" --with-nmap --with-nuclei --out ./reports
Ethics: Only run K9Sniff on systems you own or have explicit permission to test. Prefer public training labs like OWASP Juice Shop or crAPI for demonstrations.

yaml
Copy
Edit

---

### `examples/targets.txt`
```text
https://juice.shop
https://owasp.org
https://httpbin.org

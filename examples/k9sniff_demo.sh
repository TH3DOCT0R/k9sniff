#!/usr/bin/env bash
# K9Sniff demo runner — creates ./reports and drops example artifacts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/reports"

mkdir -p "$OUT"

echo "[demo] Writing fabricated artifacts to $OUT"
cp "$HERE/sample_report.html" "$OUT/report.html"
cp "$HERE/sample_summary.json" "$OUT/summary.json"
cp "$HERE/junit_example.xml" "$OUT/junit.xml"

echo "[demo] Done. Open $OUT/report.html"

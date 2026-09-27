#!/usr/bin/env bash
# Runs the E2B compatibility suite (unmodified Python and JS SDKs) against the
# stack the E2B_* environment variables point at, writes JUnit reports and
# prints the pass rate. Exits non-zero below WEFT_COMPAT_MIN_PASS_RATE
# (percent, default 100).
#
#   source .weft/dev/e2b.env && packages/compat-tests/run.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPORTS="${WEFT_COMPAT_REPORTS:-$HERE/reports}"
VENV="${WEFT_COMPAT_VENV:-$HERE/../../.weft/compat-venv}"
MIN="${WEFT_COMPAT_MIN_PASS_RATE:-100}"
mkdir -p "$REPORTS"

: "${E2B_API_URL:?set E2B_API_URL (see scripts/dev-stack.sh)}"
: "${E2B_API_KEY:?set E2B_API_KEY}"

if [[ ! -x "$VENV/bin/pytest" ]]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$HERE/python/requirements.txt"
fi

(cd "$HERE/python" && "$VENV/bin/pytest" -q -p no:warnings --junitxml="$REPORTS/python.xml")
(cd "$HERE" && npx vitest run --reporter=default --reporter=junit --outputFile.junit="$REPORTS/js.xml")

python3 - "$REPORTS" "$MIN" <<'PY'
import sys, xml.etree.ElementTree as ET
reports, minimum = sys.argv[1], float(sys.argv[2])
rows, total_passed, total_run = [], 0, 0
for name in ("python", "js"):
    try:
        root = ET.parse(f"{reports}/{name}.xml").getroot()
    except (FileNotFoundError, ET.ParseError):
        rows.append((name, 0, 0, 0, "missing report"))
        total_run += 1
        continue
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    tests = sum(int(s.get("tests", 0)) for s in suites)
    bad = sum(int(s.get("failures", 0)) + int(s.get("errors", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    run = tests - skipped
    rows.append((name, run - bad, run, skipped, ""))
    total_passed += run - bad
    total_run += run
rate = 100.0 * total_passed / total_run if total_run else 0.0
print("\nE2B compatibility suite")
for name, passed, run, skipped, note in rows:
    print(f"  {name:<7} {passed}/{run} passed" + (f", {skipped} skipped" if skipped else "") + (f" ({note})" if note else ""))
print(f"  pass rate {rate:.1f}% (minimum {minimum:.0f}%)")
sys.exit(0 if rate >= minimum else 1)
PY

"""CLI:  python -m triage DATA_DIR [-o report.md] [--json out.json]"""
import argparse
import json
import sys
from pathlib import Path

from .pipeline import analyse


def main() -> int:
    ap = argparse.ArgumentParser(description="Orbit Logistics security incident triage")
    ap.add_argument("data", nargs="?", default="data", help="folder with the logs and reference files")
    ap.add_argument("-o", "--out", default="incident_report.md")
    ap.add_argument("--json", help="also write the structured analysis as JSON")
    a = ap.parse_args()
    try:
        an = analyse(a.data)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(an.report_md)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(an.to_json(), f, indent=2)
    for i in an.incidents:
        print(f"{i.id}  {i.severity or 'undecided':6}  {i.title}")
    print(f"{len(an.dismissed)} alert(s) dismissed as approved changes; {len(an.gaps) + len(an.coverage.gaps)} log gap(s); report -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

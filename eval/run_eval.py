"""Red-team evaluation of the Q&A layer. Usage: python eval/run_eval.py [data_dir]

Checks each answer for required phrases, forbidden phrases and a verified citation to the
expected file. Works with or without an LLM key (without a key it scores the fallback).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from triage.pipeline import analyse  # noqa: E402
from triage.qa import Index, answer  # noqa: E402

data = sys.argv[1] if len(sys.argv) > 1 else "data"
an = analyse(data)
idx = Index(an)
cases = [json.loads(l) for l in open(Path(__file__).parent / "redteam.jsonl") if l.strip()]
passed = 0
for c in cases:
    r = answer(an, idx, c["q"])
    low = r["answer"].lower()
    ok_any = any(m in low for m in c.get("must_any", [])) if c.get("must_any") else True
    ok_not = not any(m in low for m in c.get("must_not", []))
    ok_cite = any(c["must_cite"] in x for x in r["citations"]) if c.get("must_cite") else True
    ok = ok_any and ok_not and ok_cite
    passed += ok
    print(f"{'PASS' if ok else 'FAIL'}  {c['q'][:70]:72} any={ok_any} not={ok_not} cite={ok_cite}  ({r['model']})")
print(f"\n{passed}/{len(cases)} passed")

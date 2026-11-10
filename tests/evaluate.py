#!/usr/bin/env python3
"""Evaluate the rules against the EVTX-ATTACK-SAMPLES corpus with Chainsaw.

Every rule must fire on exactly the samples listed for it in tests/expected.yml:
a missed sample is a lost detection, an unlisted one is new noise (or a new true
positive that should be reviewed and added). Either way the run fails, so the
expected file is the reviewed baseline and CI catches regressions.

    python tests/evaluate.py --chainsaw chainsaw --mapping sigma-event-logs-all.yml \
        --data EVTX-ATTACK-SAMPLES [--report results.md] [--print-hits]
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_rules(rules_dir: Path) -> dict:
    rules = {}
    for path in sorted(rules_dir.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules[rule["id"]] = {"title": rule["title"], "level": rule["level"], "file": path.name}
    return rules


def hunt(chainsaw: str, data: Path, rules_dir: Path, mapping: Path) -> dict:
    cmd = [chainsaw, "hunt", str(data), "-s", str(rules_dir), "--mapping", str(mapping), "--json", "-q"]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8").stdout
    hits = defaultdict(lambda: defaultdict(int))  # rule id -> sample -> matching events
    for detection in json.loads(out) if out.strip() else []:
        sample = Path(detection["document"]["path"]).resolve().relative_to(data.resolve()).as_posix()
        hits[detection["id"]][sample] += 1
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chainsaw", required=True, help="path to the chainsaw binary")
    parser.add_argument("--mapping", required=True, type=Path, help="chainsaw sigma-event-logs-all.yml")
    parser.add_argument("--data", required=True, type=Path, help="EVTX-ATTACK-SAMPLES checkout")
    parser.add_argument("--rules", type=Path, default=ROOT / "rules")
    parser.add_argument("--expected", type=Path, default=ROOT / "tests" / "expected.yml")
    parser.add_argument("--report", type=Path, help="write a Markdown results table here")
    parser.add_argument("--print-hits", action="store_true", help="print every matched sample")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    hits = hunt(args.chainsaw, args.data, args.rules, args.mapping)
    expected = yaml.safe_load(args.expected.read_text(encoding="utf-8")) or {}
    corpus = len(list(args.data.rglob("*.evtx")))

    failed = False
    rows = []
    for rule_id, meta in rules.items():
        got = hits.get(rule_id, {})
        want = set((expected.get(rule_id) or {}).get("samples", []))
        missing, extra = sorted(want - set(got)), sorted(set(got) - want)
        status = "ok" if not missing and not extra else "FAIL"
        failed |= status == "FAIL"
        rows.append((meta, len(got), sum(got.values()), status))
        print(f"[{status}] {meta['title']} ({meta['level']}): {len(got)} samples, {sum(got.values())} events")
        for sample in missing:
            print(f"    missing expected sample: {sample}")
        for sample in extra:
            print(f"    unexpected sample:       {sample}  ({got[sample]} events)")
        if args.print_hits:
            for sample, count in sorted(got.items()):
                print(f"    hit: {sample}  ({count} events)")

    if args.report:
        lines = [
            f"Corpus: {corpus} EVTX files from EVTX-ATTACK-SAMPLES, evaluated with Chainsaw.",
            "",
            "| Rule | Level | Samples matched | Events matched | Matches reviewed baseline |",
            "|---|---|---|---|---|",
        ]
        for meta, samples, events, status in rows:
            lines.append(f"| [{meta['title']}](rules/{meta['file']}) | {meta['level']} | {samples} | {events} | {status} |")
        args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

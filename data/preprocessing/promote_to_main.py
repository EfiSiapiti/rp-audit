#!/usr/bin/env python3
"""
promote_to_main.py — copy selected entries from a screening ledger into the agent repo's
data/ledger.json (../rp-audit-agent/data/ledger.json) (as `pending`, keeping their gate / http_probe blocks). Backs the main ledger up first.
Existing rp_ids are never overwritten.

Usage:
  python data/preprocessing/promote_to_main.py --http-label http-friendly            # dry run
  python data/preprocessing/promote_to_main.py --http-label http-friendly --apply
  python data/preprocessing/promote_to_main.py --rp smh.com.au dashlane.com --apply
"""
import argparse, json, shutil
from datetime import datetime, timezone
from pathlib import Path

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--src", default="data/ledger_fidentikit.json")
ap.add_argument("--main", default="../rp-audit-agent/data/ledger.json",
                help="the AGENT repo's ledger (written on --apply); run from the rp-audit root")
ap.add_argument("--http-label", nargs="+", help="select by http_probe.label")
ap.add_argument("--gate-label", nargs="+", help="select by gate.label")
ap.add_argument("--rp", nargs="+", help="select explicit rp_ids")
ap.add_argument("--exclude", nargs="+", default=[], help="rp_ids to leave out")
ap.add_argument("--apply", action="store_true")
a = ap.parse_args()
if not (a.http_label or a.gate_label or a.rp):
    ap.error("choose at least one of --http-label / --gate-label / --rp")

src = json.load(open(a.src, encoding="utf-8"))["entries"]
main = json.load(open(a.main, encoding="utf-8"))

sel = [k for k, e in src.items()
       if k not in a.exclude
       and ((a.rp and k in a.rp)
            or (a.http_label and (e.get("http_probe") or {}).get("label") in a.http_label)
            or (a.gate_label and (e.get("gate") or {}).get("label") in a.gate_label))]
new = [k for k in sel if k not in main["entries"]]
print(f"selected {len(sel)}; {len(sel) - len(new)} already in main ledger; {len(new)} to add")
for k in new:
    print("  +", k)
if not a.apply:
    print("\n(dry run — add --apply to write)"); raise SystemExit

backup = Path(a.main).with_suffix(f".backup-{datetime.now():%Y%m%d-%H%M%S}.json")
shutil.copy2(a.main, backup); print("backup ->", backup)
now = datetime.now(timezone.utc).isoformat()
for k in new:
    e = dict(src[k])
    e["history"] = e.get("history", []) + [{"at": now, "state": "pending", "note": "promoted from fidentikit screening"}]
    main["entries"][k] = e
json.dump(main, open(a.main, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print(f"added {len(new)} -> {a.main} (total {len(main['entries'])})")

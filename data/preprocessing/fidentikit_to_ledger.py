#!/usr/bin/env python3
"""
fidentikit_to_ledger.py — turn a FidentiKit archive CSV into a *separate* screening
ledger that portal_probe.py can batch over, without touching data/ledger.json.

Usage:
  python data/preprocessing/fidentikit_to_ledger.py ARCHIVE.csv
  python data/preprocessing/fidentikit_to_ledger.py ARCHIVE.csv --min-confidence MEDIUM
  python data/preprocessing/fidentikit_to_ledger.py ARCHIVE.csv --out data/ledger_fidentikit.json

Then:
  python data/preprocessing/portal_probe.py --ledger data/ledger_fidentikit.json --limit 300
"""
import argparse, csv, json, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import tldextract

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from portal_probe import structural   # .edu / .gov suffix exclusion

# Offline PSL: use the snapshot packaged with tldextract, no network calls.
extract = tldextract.TLDExtract(suffix_list_urls=())

CONF_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def etld1(host):
    e = extract(host)
    return e.top_domain_under_public_suffix if hasattr(e, "top_domain_under_public_suffix") else e.registered_domain


def origin(url, fallback_host):
    p = urlparse(url or "")
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    return f"https://{fallback_host}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="FidentiKit archive CSV (semicolon-delimited)")
    ap.add_argument("--out", default="data/ledger_fidentikit.json")
    ap.add_argument("--main-ledger", default="../rp-audit-agent/data/ledger.json",
                    help="the AGENT repo's ledger: drop rp_ids already present there (run from the rp-audit root)")
    ap.add_argument("--min-confidence", default="HIGH", choices=list(CONF_ORDER))
    ap.add_argument("--keep-structural", action="store_true", help="keep .edu/.gov instead of dropping")
    a = ap.parse_args()

    floor = CONF_ORDER[a.min_confidence]
    existing = set()
    mp = Path(a.main_ledger)
    if mp.exists():
        existing = set(json.load(open(mp, encoding="utf-8")).get("entries", {}))

    drops = Counter()
    kept = {}   # rp_id -> (rank, entry)
    with open(a.csv, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f, delimiter=";"):
            domain = (r.get("domain") or "").strip().lower()
            if not domain:
                drops["no-domain"] += 1; continue
            if (r.get("reachable") or "").upper() != "TRUE":
                drops["unreachable"] += 1; continue
            if (r.get("passkey_detected") or "").upper() != "TRUE":
                drops["passkey-not-detected"] += 1; continue
            conf = (r.get("passkey_confidence") or "").upper()
            if CONF_ORDER.get(conf, -1) < floor:
                drops[f"below-{a.min_confidence}"] += 1; continue
            # Key by where the domain actually lands: CDN/alias domains (googlevideo.com,
            # google.de, fbcdn.net) redirect to a real site, so they collapse onto it and
            # then dedupe / drop against the main ledger instead of being probed as junk.
            rp_id = etld1((r.get("resolved_domain") or "").strip().lower() or domain)
            if not rp_id:
                drops["no-etld1"] += 1; continue
            if rp_id in existing:
                drops["already-in-main-ledger"] += 1; continue
            if not a.keep_structural and structural(rp_id):
                drops["edu-gov"] += 1; continue
            try:
                rank = int(float(r.get("rank") or 0)) or 10**9
            except ValueError:
                rank = 10**9
            if rp_id in kept and kept[rp_id][0] <= rank:
                drops["duplicate-etld1"] += 1; continue
            if rp_id in kept:
                drops["duplicate-etld1"] += 1
            now = datetime.now(timezone.utc).isoformat()
            origin_url = origin(r.get("resolved_url"), r.get("resolved_domain") or domain)
            kept[rp_id] = (rank, {
                "rp_id": rp_id,
                "canonical_origin": origin_url,
                "entity": "",
                "signup_url": origin_url,
                "state": "pending",
                "attempts": 0,
                "source": f"fidentikit-{r.get('run') or 'unknown'}",
                "fidentikit": {
                    "domain": domain,
                    "rank": None if rank == 10**9 else rank,
                    "passkey_confidence": conf,
                    "passkey_detection_methods": r.get("passkey_detection_methods") or "",
                    "idp_names": r.get("idp_names") or "",
                },
                "history": [{"at": now, "state": "pending", "note": "initialized from fidentikit"}],
            })

    entries = {k: v[1] for k, v in sorted(kept.items(), key=lambda kv: kv[1][0])}
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"version": 1, "entries": entries}, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    print(f"wrote {len(entries)} entries -> {out} (min confidence {a.min_confidence}, sorted by rank)")
    for k, n in drops.most_common():
        print(f"  dropped {n:5d}  {k}")


if __name__ == "__main__":
    main()

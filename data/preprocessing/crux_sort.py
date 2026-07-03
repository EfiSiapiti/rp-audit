#!/usr/bin/env python3
"""
Attach CrUX popularity rank to a ledger and sort by it.

CrUX ranks are coarse magnitude buckets on a log10 half-step scale
(1k / 5k / 10k / 50k / 100k / 500k / 1M). Lower = more popular. The
zakird/crux-top-lists dump carries the full half-steps, same granularity as
BigQuery's experimental.popularity.rank. There is NO ordinal rank inside a
bucket, so within-bucket ties are broken by your own signals
(snapshot_count, cluster_size) then origin name.

Match strategy: CrUX origins include subdomains (news.google.com,
smt.docomo.ne.jp), so we reduce every CrUX origin to its registrable domain
(eTLD+1) via the Public Suffix List, take the MIN rank per domain, and join on
the ledger's `etld1` column. That absorbs www/apex/subdomain mismatches in one
shot. Both sides use the same offline tldextract snapshot for consistency.

Usage: python3 crux_sort.py
"""
import sys
import gzip
import shutil
import urllib.request
import urllib.error
from pathlib import Path

import pandas as pd
import tldextract

# --- args ----------------------------------------------------------------
ledger_path = sys.argv[1] if len(sys.argv) > 1 else "../targets.csv"
out_path    = sys.argv[2] if len(sys.argv) > 2 else "../targets_ranked.csv"

# --- pinned CrUX snapshot (matches the corpus's well-known scan month) ----
HERE = Path(__file__).resolve().parent
DATA = HERE / "data"; DATA.mkdir(exist_ok=True)
YYYYMM = "202604"
CRUX = DATA / f"crux_global_{YYYYMM}.csv"
URL = (f"https://raw.githubusercontent.com/zakird/crux-top-lists/"
       f"main/data/global/{YYYYMM}.csv.gz")

def ensure_crux() -> str:
    """Download + cache the pinned CrUX month; fail loudly if unavailable."""
    if CRUX.exists() and CRUX.stat().st_size > 0:
        return str(CRUX)
    gz = CRUX.with_suffix(".csv.gz")
    try:
        urllib.request.urlretrieve(URL, gz)
    except urllib.error.HTTPError as e:
        raise SystemExit(
            f"CrUX month {YYYYMM} not fetchable ({e.code} at {URL}).\n"
            f"Check available months in the mirror or pull it from BigQuery "
            f"(chrome-ux-report.experimental.global, yyyymm={YYYYMM})."
        )
    try:
        with gzip.open(gz, "rb") as i, open(CRUX, "wb") as o:
            shutil.copyfileobj(i, o)
    except (OSError, EOFError) as e:
        gz.unlink(missing_ok=True); CRUX.unlink(missing_ok=True)
        raise SystemExit(f"Downloaded {YYYYMM} dump is not valid gzip: {e}")
    finally:
        gz.unlink(missing_ok=True)
    # sanity-check the header so a stray HTML/error page can't slip through
    with open(CRUX, "r") as f:
        if f.readline().strip() != "origin,rank":
            CRUX.unlink(missing_ok=True)
            raise SystemExit(f"Unexpected CrUX schema in {YYYYMM} dump.")
    return str(CRUX)

crux_path = ensure_crux()

# Offline PSL: use the snapshot packaged with tldextract, no network calls.
extract = tldextract.TLDExtract(suffix_list_urls=())

def etld1_of(origin: str) -> str:
    return extract(str(origin)).top_domain_under_public_suffix

# --- CrUX: min rank per registrable domain -------------------------------
crux = pd.read_csv(crux_path)                      # columns: origin, rank
crux["etld1"] = crux["origin"].map(etld1_of)
crux_rank = (crux.groupby("etld1")["rank"].min()
                 .rename("crux_rank").reset_index())

# --- Ledger: left-join, preserve everything ------------------------------
# The ledger CSV may be comma- or semicolon-delimited (Excel/locale exports
# often use ';'). Let pandas sniff the separator so either works.
led = pd.read_csv(ledger_path, sep=None, engine="python")
if "etld1" not in led.columns:
    raise SystemExit(
        f"{ledger_path} has no 'etld1' column — found: {list(led.columns)}.\n"
        f"Check the file's delimiter and header row."
    )
led = led.merge(crux_rank, on="etld1", how="left")
led["crux_rank"] = led["crux_rank"].astype("Int64")   # nullable int, no .0

# Human-readable bucket label
LABELS = {1000:"top 1k",5000:"top 5k",10000:"top 10k",50000:"top 50k",
          100000:"top 100k",500000:"top 500k",1000000:"top 1M"}
def bucket(r):
    return "unranked" if pd.isna(r) else LABELS.get(int(r), f"top {int(r)}")
led["crux_bucket"] = led["crux_rank"].map(bucket)

# --- Sort: rank asc (unranked last), then your own prevalence signals -----
led["_rank_key"] = led["crux_rank"].fillna(10**18)    # push NA to the bottom
sort_cols = ["_rank_key", "snapshot_count", "cluster_size", "canonical_origin"]
ascending = [True,        False,            False,          True]
keep = [c in led.columns for c in sort_cols]
sort_cols = [c for c, k in zip(sort_cols, keep) if k]
ascending = [a for a, k in zip(ascending, keep) if k]
led = led.sort_values(sort_cols, ascending=ascending).drop(columns="_rank_key")

led.to_csv(out_path, index=False)

# --- Report --------------------------------------------------------------
total = len(led); matched = int(led["crux_rank"].notna().sum())
print(f"CrUX {YYYYMM} | rows: {total}   in top-1M: {matched} "
      f"({matched/total:.0%})   unranked: {total-matched}")
print(led["crux_bucket"].value_counts().reindex(
      ["top 1k","top 5k","top 10k","top 50k","top 100k","top 500k",
       "top 1M","unranked"]).dropna().to_string())
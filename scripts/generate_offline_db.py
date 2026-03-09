#!/usr/bin/env python3
# ============================================================
# OFFLINE CPE -> CVE ENRICHER
# Sources: NVD / EUVD / OSV (OFFLINE dumps)
# Fichier pour fonctionnement de pga CPE LIst /!\ verfier date des export 
# ============================================================

import csv
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data"

INPUT_CSV = DATA / "list_cpe.csv"
NVD_JSON  = DATA / "nvd_dump.json"
EUVD_JSON = DATA / "euvd_dump.json"
OSV_JSON  = DATA / "osv_dump.json"

OUT_JSON  = DATA / "offline_cpe_db.json"
OUT_CSV   = DATA / "offline_cpe_db.csv"


# ------------------------------------------------------------
# Utils
# ------------------------------------------------------------

def normalize_cpe(cpe: str) -> str:
    return (
        cpe.strip()
           .replace("\\*", "*")
           .rstrip(",")
    )

def parse_cpe(cpe: str) -> dict:
    p = cpe.split(":")
    return {
        "vendor": p[3] if len(p) > 3 else None,
        "product": p[4] if len(p) > 4 else None,
        "version": p[5] if len(p) > 5 else None,
    }


def load_json(path: Path):
    if not path.exists():
        print(f"[WARN] dump absent: {path.name}")
        return []
    with path.open(encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------------
# Chargement CPE
# ------------------------------------------------------------

def load_cpes():
    cpes = set()
    with INPUT_CSV.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cpe = normalize_cpe(row.get("CPE", ""))
            if cpe.startswith("cpe:2.3:"):
                cpes.add(cpe)
    print(f"[OK] CPE chargés: {len(cpes)}")
    return sorted(cpes)


# ------------------------------------------------------------
# Indexation des CVE par CPE
# ------------------------------------------------------------

def index_by_cpe(records, cpe_field):
    idx = defaultdict(list)
    for r in records:
        for cpe in r.get(cpe_field, []):
            idx[normalize_cpe(cpe)].append(r)
    return idx


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    cpes = load_cpes()

    nvd  = load_json(NVD_JSON)
    euvd = load_json(EUVD_JSON)
    osv  = load_json(OSV_JSON)

    nvd_idx  = index_by_cpe(nvd,  "cpe")
    euvd_idx = index_by_cpe(euvd, "cpe")

    osv_idx = defaultdict(list)
    for o in osv:
        for a in o.get("affected", []):
            c = a.get("cpe")
            if c:
                osv_idx[normalize_cpe(c)].append(o)

    entries = []

    for cpe in cpes:
        parsed = parse_cpe(cpe)
        cves = {}

        # --- NVD + EUVD ---
        for src in (nvd_idx[cpe] + euvd_idx[cpe]):
            cid = src["cve_id"]
            cves.setdefault(cid, {
                "id": cid,
                "cvss": src.get("cvss"),
                "cwe": src.get("cwe", []),
                "kev": src.get("kev", False),
                "published": src.get("published"),
                "epss": None
            })

        # --- OSV (EPSS) ---
        for o in osv_idx[cpe]:
            cid = o["id"]
            if cid in cves:
                cves[cid]["epss"] = o.get("epss")

        # --- Summary ---
        cvss_vals = [c["cvss"] for c in cves.values() if c["cvss"] is not None]
        epss_vals = [c["epss"] for c in cves.values() if c["epss"] is not None]

        summary = {
            "cve_count": len(cves),
            "cvss_max": max(cvss_vals) if cvss_vals else None,
            "epss_max": max(epss_vals) if epss_vals else None,
            "kev": any(c["kev"] for c in cves.values()),
            "cwe": sorted({cw for c in cves.values() for cw in c["cwe"]})
        }

        entries.append({
            "cpe": cpe,
            **parsed,
            "summary": summary,
            "cves": list(cves.values())
        })

    # --------------------------------------------------------
    # Output JSON
    # --------------------------------------------------------

    out = {
        "_meta": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "cpe_count": len(entries),
            "sources": ["NVD", "EUVD", "OSV"]
        },
        "cpe_entries": entries
    }

    OUT_JSON.write_text(json.dumps(out, indent=2), encoding="utf-8")

    # --------------------------------------------------------
    # Output CSV (synthèse)
    # --------------------------------------------------------

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow([
            "CPE", "Vendor", "Product", "Version",
            "CVE_COUNT", "CVSS_MAX", "EPSS_MAX", "KEV", "CWE"
        ])
        for e in entries:
            w.writerow([
                e["cpe"],
                e["vendor"],
                e["product"],
                e["version"],
                e["summary"]["cve_count"],
                e["summary"]["cvss_max"],
                e["summary"]["epss_max"],
                e["summary"]["kev"],
                ",".join(e["summary"]["cwe"])
            ])

    print(f"[OK] JSON généré: {OUT_JSON}")
    print(f"[OK] CSV généré : {OUT_CSV}")


if __name__ == "__main__":
    main()

import json
import re
from pathlib import Path
import urllib.request

# URL officielle (STIX EMB3D v2.0.1)
# La page Data indique que EMB3D est dispo en STIX 2.1 et détaille le champ CWE dans le Threat. [1](https://mindmapai.app/mind-mapping/cartographie-des-menaces-avec-mitre-attck)
EMB3D_STIX_URL = "https://emb3d.mitre.org/assets/emb3d-stix-v2.0.1.json" 
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

def download_json(url: str):
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode("utf-8"))

def extract_tid(obj: dict):
    # Dans EMB3D STIX, le TID est souvent dans external_references.external_id
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id", "")
        if isinstance(ext_id, str) and ext_id.startswith("TID-"):
            return ext_id
    # fallback : cherche TID dans le name/description
    for field in ("name", "description"):
        txt = obj.get(field) or ""
        if isinstance(txt, str):
          m = TID_RE.search(txt)
          if m: return m.group(0)
    return None

def extract_cwes(obj: dict):
    cwes = set()

    # ✅ Champ dédié EMB3D (markdown bullet list) : x_mitre_emb3d_threat_CWEs [1](https://mindmapai.app/mind-mapping/cartographie-des-menaces-avec-mitre-attck)
    md = obj.get("x_mitre_emb3d_threat_CWEs")
    if isinstance(md, str) and md.strip():
        for line in md.splitlines():
            line = line.replace("-", "").strip()
            if line.upper().startswith("CWE-"):
                cwes.add(line.upper())
            else:
                # fallback regex sur la ligne
                for m in CWE_RE.findall(line):
                    cwes.add(m.upper())

    # fallback : regex sur description
    desc = obj.get("description") or ""
    if isinstance(desc, str):
        for m in CWE_RE.findall(desc):
            cwes.add(m.upper())

    return cwes

def main():
    stix = download_json(EMB3D_STIX_URL)
    objs = stix.get("objects", []) if isinstance(stix, dict) else []

    cwe_to_tid = {}

    for obj in objs:
        if not isinstance(obj, dict):
            continue

        # Threats EMB3D = STIX vulnerability objects [1](https://mindmapai.app/mind-mapping/cartographie-des-menaces-avec-mitre-attck)
        if obj.get("type") != "vulnerability":
            continue

        tid = extract_tid(obj)
        if not tid:
            continue

        cwes = extract_cwes(obj)
        for cwe in cwes:
            cwe_to_tid.setdefault(cwe, set()).add(tid)

    # Convert set -> sorted list
    out = {cwe: sorted(list(tids)) for cwe, tids in cwe_to_tid.items()}

    Path("data").mkdir(exist_ok=True)
    with open("data/cwe_to_tid.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"Generated data/cwe_to_tid.json with {len(out)} CWEs")

if __name__ == "__main__":
    main()

import json
import re
from pathlib import Path
import urllib.request
import urllib.error

DATA_PAGE_URL = "https://emb3d.mitre.org/subtabs/data.html"  # page qui liste les STIX [1](https://emb3d.mitre.org/subtabs/data.html)

TID_RE = re.compile(r"\bTID-\d+\b")
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

def http_get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode("utf-8", errors="replace")

def http_get_json(url: str):
    txt = http_get_text(url)
    return json.loads(txt)

def discover_stix_url_from_data_page() -> str:
    """
    Télécharge la page 'Data' EMB3D et extrait un lien .json STIX.
    On prend en priorité v2.0.1 puis v2.0 si trouvé. [1](https://emb3d.mitre.org/subtabs/data.html)[2](https://emb3d.mitre.org/subtabs/version-history.html)
    """
    html = http_get_text(DATA_PAGE_URL)

    # Cherche toutes les URL JSON dans la page (href="...json")
    # On capture aussi les liens relatifs.
    candidates = re.findall(r'href="([^"]+?\.json)"', html, flags=re.IGNORECASE)

    # Normalise vers URL absolues
    abs_urls = []
    for u in candidates:
        if u.startswith("http"):
            abs_urls.append(u)
        elif u.startswith("/"):
            abs_urls.append("https://emb3d.mitre.org" + u)
        else:
            abs_urls.append("https://emb3d.mitre.org/" + u)

    # Priorité: v2.0.1 puis v2.0 puis n'importe quel .json
    preferred = []
    for key in ["v2.0.1", "2.0.1", "v2.0", "2.0"]:
        preferred.extend([u for u in abs_urls if key in u])

    # dédoublonne en gardant l'ordre
    seen = set()
    ordered = []
    for u in preferred + abs_urls:
        if u not in seen:
            ordered.append(u)
            seen.add(u)

    if not ordered:
        raise RuntimeError("Aucun lien .json trouvé sur la page DATA EMB3D.")

    return ordered[0]

def fetch_stix_bundle():
    """
    Stratégie robuste:
    1) Essayer des chemins courants (si tu veux en garder)
    2) Sinon: découvrir automatiquement l'URL depuis la page DATA [1](https://emb3d.mitre.org/subtabs/data.html)
    """
    common_urls = [
        # Si un de ces chemins existe, on le prend.
        "https://emb3d.mitre.org/assets/stix/emb3d-stix-v2.0.1.json",
        "https://emb3d.mitre.org/assets/stix/emb3d-stix-v2.0.json",
        "https://emb3d.mitre.org/assets/emb3d-stix-v2.0.1.json",
        "https://emb3d.mitre.org/assets/emb3d-stix-v2.0.json",
    ]

    last_err = None
    for url in common_urls:
        try:
            return http_get_json(url), url
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code != 404:
                raise
        except Exception as e:
            last_err = e

    # fallback: discovery
    stix_url = discover_stix_url_from_data_page()
    return http_get_json(stix_url), stix_url

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
            if m:
                return m.group(0)
    return None

def extract_cwes(obj: dict):
    """
    La page Data précise que le champ CWE est: x_mitre_emb3d_threat_CWEs (bullet list markdown). [1](https://emb3d.mitre.org/subtabs/data.html)
    """
    cwes = set()

    md = obj.get("x_mitre_emb3d_threat_CWEs")
    if isinstance(md, str) and md.strip():
        for line in md.splitlines():
            line = line.replace("-", "").strip()
            if line.upper().startswith("CWE-"):
                cwes.add(line.upper())
            else:
                for m in CWE_RE.findall(line):
                    cwes.add(m.upper())

    # fallback regex sur description
    desc = obj.get("description") or ""
    if isinstance(desc, str):
        for m in CWE_RE.findall(desc):
            cwes.add(m.upper())

    return cwes

def main():
    stix, used_url = fetch_stix_bundle()
    objs = stix.get("objects", []) if isinstance(stix, dict) else []

    cwe_to_tid = {}

    for obj in objs:
        if not isinstance(obj, dict):
            continue

        # La page Data dit que les Threats sont exprimés en 'vulnerability' [1](https://emb3d.mitre.org/subtabs/data.html)
        if obj.get("type") != "vulnerability":
            continue

        tid = extract_tid(obj)
        if not tid:
            continue

        for cwe in extract_cwes(obj):
            cwe_to_tid.setdefault(cwe, set()).add(tid)

    out = {cwe: sorted(list(tids)) for cwe, tids in cwe_to_tid.items()}

    Path("data").mkdir(exist_ok=True)
    with open("data/cwe_to_tid.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"STIX source used: {used_url}")
    print(f"Generated data/cwe_to_tid.json with {len(out)} CWEs")

if __name__ == "__main__":
    main()

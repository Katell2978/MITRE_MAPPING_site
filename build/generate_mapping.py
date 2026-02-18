import json
import re
from pathlib import Path
import urllib.request
import urllib.error

# Page officielle MITRE qui liste les datasets EMB3D STIX
DATA_PAGE_URL = "https://emb3d.mitre.org/subtabs/data.html"

# Regex utilitaires
TID_RE = re.compile(r"\bTID-\d+\b")
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

# ------------------------------------------------------------
# HTTP helpers
# ------------------------------------------------------------
def http_get_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (GitHub Actions)"}
    )
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode("utf-8", errors="replace")

def http_get_json(url: str):
    return json.loads(http_get_text(url))

# ------------------------------------------------------------
# Discover STIX URL dynamically (anti-404)
# ------------------------------------------------------------
def discover_stix_url() -> str:
    """
    Récupère dynamiquement l'URL du fichier STIX EMB3D
    depuis la page DATA officielle.
    """
    html = http_get_text(DATA_PAGE_URL)

    # Trouve tous les liens .json
    matches = re.findall(r'href="([^"]+?\.json)"', html, flags=re.IGNORECASE)


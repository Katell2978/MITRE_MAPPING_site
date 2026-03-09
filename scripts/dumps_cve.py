#!/usr/bin/env bash
# ==========================================================
# OFFLINE vulnerability dumps downloader
# Sources: NVD / OSV / EUVD (agrégé)
# ==========================================================

set -e

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$BASE_DIR/data"

mkdir -p "$DATA_DIR/nvd" "$DATA_DIR/osv" "$DATA_DIR/euvd"

echo "[INFO] Téléchargement NVD (JSON 2.0)…"

# -------- NVD --------
# Années à récupérer (adapter si besoin)
YEARS=$(seq 2002 2026)

for Y in $YEARS; do
  URL="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${Y}.json.gz"
  OUT="$DATA_DIR/nvd/nvdcve-2.0-${Y}.json.gz"
  if [ ! -f "$OUT" ]; then
    echo "  - $Y"
    curl -fsSL "$URL" -o "$OUT"
  fi
done

# Fichier "modified" (mise à jour incrémentale)
curl -fsSL \
  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz \
  -o "$DATA_DIR/nvd/nvdcve-2.0-modified.json.gz"

echo "[OK] NVD téléchargé."

# -------- OSV --------
echo "[INFO] Téléchargement OSV (dump global)…"

OSV_ZIP="$DATA_DIR/osv/osv_all.zip"
OSV_URL="https://storage.googleapis.com/osv-vulnerabilities/all.zip"

if [ ! -f "$OSV_ZIP" ]; then
  curl -fsSL "$OSV_URL" -o "$OSV_ZIP"
fi

echo "[OK] OSV téléchargé."

# -------- EUVD --------
echo "[INFO] Téléchargement EUVD (agrégateur open)…"

# EUVD n’expose pas encore de dump officiel global.
# On utilise un export open agrégé (OpenNVD / vuln-lookup style)
# Exemple générique (à adapter si tu choisis une source précise).

EUVD_URL="https://raw.githubusercontent.com/opennvd-org/opennvd-core/main/data/euvd/euvd_dump.json"
EUVD_OUT="$DATA_DIR/euvd/euvd_dump.json"

curl -fsSL "$EUVD_URL" -o "$EUVD_OUT" || echo "[WARN] EUVD non disponible via cette URL"

echo "[OK] Téléchargement terminé."

echo
echo "[SUMMARY]"
echo "NVD  : $DATA_DIR/nvd"
echo "OSV  : $DATA_DIR/osv"
echo "EUVD : $DATA_DIR/euvd"

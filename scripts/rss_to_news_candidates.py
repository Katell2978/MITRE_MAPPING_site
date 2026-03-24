"""
RSS → news-candidates.json

Objectif :
- Lire des flux RSS OFFICIELS
- Extraire les publications récentes
- Générer un JSON "à valider" pour la veille
- AUCUN scraping
- AUCUNE interprétation métier lourde

Ce fichier est conçu pour être exécuté
par GitHub Actions (cron).
"""

import json
import os
from datetime import datetime, timedelta, timezone

import feedparser
from dateutil import parser as dateparser

# ---------------------------------------------------------------------
# Paramètres généraux
# ---------------------------------------------------------------------

OUTPUT_FILE = "data/news-candidates.json"

# Fenêtre de fraîcheur (en jours)
WINDOW_DAYS = 7
since_date = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)

# ---------------------------------------------------------------------
# Flux RSS OFFICIELS / PROXIES RSS LÉGITIMES
# ---------------------------------------------------------------------

RSS_FEEDS = [
    {
        "source": "Android Security Bulletin",
        "vendor": "Android / AAOS",
        "type": "Platform Bulletin",
        # Proxy RSS public vers Android Security Bulletins
        "url": "https://app.folo.is/share/feeds/156000891791099904"
    },
    # Tu pourras en ajouter d'autres ici plus tard
]

# ---------------------------------------------------------------------
# Chargement de l'existant (pour éviter les doublons)
# ---------------------------------------------------------------------

existing = []
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        try:
            existing = json.load(f)
        except Exception:
            existing = []

existing_links = {e.get("link") for e in existing}

# ---------------------------------------------------------------------
# Collecte RSS
# ---------------------------------------------------------------------

new_items = []

for feed in RSS_FEEDS:
    parsed = feedparser.parse(feed["url"])

    for entry in parsed.entries:
        # Date de publication
        if not hasattr(entry, "published"):
            continue

        published = dateparser.parse(entry.published)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)

        if published < since_date:
            continue

        link = entry.get("link")
        if not link or link in existing_links:
            continue

        item = {
            "date": published.date().isoformat(),
            "source": feed["source"],
            "type": feed["type"],
            "vendor": feed["vendor"],
            "title": entry.get("title", "").strip(),
            "link": link,
            # statut volontairement "à valider"
            "status": "to-review",
            # traçabilité de l'origine
            "origin": "RSS"
        }

        new_items.append(item)

# ---------------------------------------------------------------------
# Fusion + tri
# ---------------------------------------------------------------------

merged = existing + new_items
merged.sort(key=lambda x: x.get("date", ""), reverse=True)

# ---------------------------------------------------------------------
# Écriture JSON
# ---------------------------------------------------------------------

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(merged, f, indent=2, ensure_ascii=False)

print(f"✅ RSS aggregation done: {len(new_items)} new items added")

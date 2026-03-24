#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RSS -> data/news-candidates.json

But:
- Agréger des flux RSS/Atom institutionnels (FR/EU/DE/UK/NL/BE/AT) + quelques sources CN exploitables
- Garder une fenêtre "fresh" (par défaut 7 jours)
- Réduire le bruit via un filtre de mots-clés orienté cyber & automotive
- Écrire un JSON "to-review" (semi-auto) consommé par veille.html sur GitHub Pages
- Pas de scraping HTML: RSS/Atom uniquement.

Sortie:
- data/news-candidates.json (liste d'objets)
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone

import feedparser
from dateutil import parser as dateparser


# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------

OUTPUT_FILE = "data/news-candidates.json"

# Fenêtre "news fraîches"
WINDOW_DAYS = 7

# Limite de taille du fichier JSON (pour éviter un fichier qui grossit sans fin)
MAX_ITEMS_TOTAL = 600

# Anti-bruit : mots-clés "automotive-friendly"
# (tu peux ajuster sans risque)
KEYWORDS = [
    # plateformes / automotive
    "automotive", "aaos", "android automotive", "infotainment", "ivi",
    "telematics", "ota", "gateway", "autosar", "qnx",
    # fournisseurs / composants
    "qualcomm", "renesas", "nvidia", "mediatek", "unisoc", "arm",
    "bluetooth", "wifi", "cellular", "modem", "baseband",
    # sécurité
    "cve", "rce", "remote code execution", "code execution",
    "zero-day", "0day", "poc", "exploit", "actively exploited",
    "firmware", "bootloader", "secure boot", "tee", "trusted execution",
    "vulnerability", "vuln", "漏洞", "安全公告", "通报", "预警"
]

# Pour certains flux (CERT/CSIRT) très denses, on applique le filtre KEYWORDS
# Pour d’autres (déjà très ciblés advisories), on peut laisser filtrer quand même;
# ici on garde un filtre par défaut pour tout, mais on autorise par feed.
DEFAULT_KEYWORD_FILTER = True

# ---------------------------------------------------------------------
# FEEDS (URLs DIRECTES RSS/ATOM)
# ---------------------------------------------------------------------
# Sources:
# - CERT-FR alertes/avis: RSS directs [1](https://www.renesas.com/en/support/renesas-psirt)[2](https://www.cnnvd.org.cn/home/warn)
# - CERT-EU advisories / threat intel: RSS directs [3](https://grouperenault-my.sharepoint.com/personal/catherine_tanguy_renault_com/Documents/Fichiers%20Microsoft%20Copilot%20Chat/veille%20(1).html?web=1)[4](https://grouperenault.sharepoint.com/sites/RAMSES/_layouts/15/Doc.aspx?sourcedoc=%7B8AE6621D-6B92-4919-A873-96C333927EA3%7D&file=change%20the%20field%20attribute%20on%20the%20metadata.docx&action=default&mobileredirect=true&DefaultItemOpen=1)
# - BSI WID: RSS direct [5](https://github.com/renesas/fsp/security)
# - NCSC UK: RSS directs [6](https://grouperenault.sharepoint.com/sites/XDOCK/_layouts/15/Doc.aspx?sourcedoc=%7B457482A0-1D0B-4131-9FDF-6E0A911B6BE2%7D&file=Sample_JSON_File.docx&action=default&mobileredirect=true&DefaultItemOpen=1)[7](https://grouperenault.sharepoint.com/:fl:/r/contentstorage/x8FNO-xtskuCRX2_fMTHLcPJi9EvtDdHskL4HwplK1w/Document%20Library/Copilot/index.html%20%E2%80%93%20version%20avec%20cadre%20Actualit%C3%A9s.page?d=wd38316dde27e476e84aa49485ceff9c2&csf=1&web=1&nav=cz0lMkZjb250ZW50c3RvcmFnZSUyRng4Rk5PLXh0c2t1Q1JYMl9mTVRITGNQSmk5RXZ0RGRIc2tMNEh3cGxLMXcmZD1iITNScnRDbEFhZ2txdk50bUpvSWUzbTJvc0UyZXc2bHRNaldVcFZDdWJwbVpaTF9kUWdzVnlRNmdkaERVV1JHSTMmZj0wMUNGT0pTSFc1QzJCNUc3WENOWkRZSktTSkpCT083Nk9DJmM9JTJGJmZsdWlkPTEmcD0lNDBmbHVpZHglMkZsb29wLXBhZ2UtY29udGFpbmVy)
# - NCSC NL advisories RSS: [8](https://advisories.ncsc.nl/rss/advisories)
# - CCB Belgium RSS (news/advisories) listé dans certrss: [9](https://github.com/pulsedive/certrss)
# - CERT.at feed: [10](https://cert.at/en/services/feeds/)
# - 360 Netlab + Anquanke listés comme feeds: [11](https://github.com/xmpf/qualcomm-bulletins)

FEEDS = [
    # ---------------- FR ----------------
    {
        "source": "CERT-FR",
        "region": "FR",
        "trust": "Government",
        "category": "Alertes",
        "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "keyword_filter": True,
    },
    {
        "source": "CERT-FR",
        "region": "FR",
        "trust": "Government",
        "category": "Avis",
        "url": "https://cert.ssi.gouv.fr/avis/feed/",
        "keyword_filter": True,
    },

    # ---------------- EU ----------------
    {
        "source": "CERT-EU",
        "region": "EU",
        "trust": "Institutional",
        "category": "Security Advisories",
        "url": "https://cert.europa.eu/publications/security-advisories-rss",
        "keyword_filter": True,
    },
    {
        "source": "CERT-EU",
        "region": "EU",
        "trust": "Institutional",
        "category": "Threat Intelligence",
        "url": "https://www.cert.europa.eu/publications/threat-intelligence-rss",
        "keyword_filter": True,
    },

    # ---------------- DE ----------------
    {
        "source": "BSI CERT-Bund (WID)",
        "region": "DE",
        "trust": "Government",
        "category": "Security Advisories",
        "url": "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
        "keyword_filter": True,
    },

    # ---------------- UK ----------------
    {
        "source": "NCSC UK",
        "region": "UK",
        "trust": "Government",
        "category": "All",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        "keyword_filter": True,
    },
    {
        "source": "NCSC UK",
        "region": "UK",
        "trust": "Government",
        "category": "News",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
        "keyword_filter": True,
    },

    # ---------------- NL ----------------
    {
        "source": "NCSC NL",
        "region": "NL",
        "trust": "Government",
        "category": "Security Advisories",
        "url": "https://advisories.ncsc.nl/rss/advisories",
        "keyword_filter": True,
    },

    # ---------------- BE ----------------
    # Via certrss list: news.xml + advisories.xml [9](https://github.com/pulsedive/certrss)
    {
        "source": "CCB Belgium",
        "region": "BE",
        "trust": "Government",
        "category": "Advisories",
        "url": "https://ccb.belgium.be/advisories.xml",
        "keyword_filter": True,
    },
    {
        "source": "CCB Belgium",
        "region": "BE",
        "trust": "Government",
        "category": "News",
        "url": "https://ccb.belgium.be/news.xml",
        "keyword_filter": True,
    },

    # ---------------- AT ----------------
    {
        "source": "CERT.at",
        "region": "AT",
        "trust": "Government",
        "category": "Blog",
        "url": "https://www.cert.at/cert-at.en.blog.rss_2.0.xml",
        "keyword_filter": True,
    },

    # ---------------- CN ----------------
    {
        "source": "360 Netlab",
        "region": "CN",
        "trust": "Research Lab",
        "category": "Threat Research",
        "url": "https://blog.netlab.360.com/rss",
        "keyword_filter": True,
    },
    {
        "source": "Anquanke",
        "region": "CN",
        "trust": "Security Media",
        "category": "Cyber News",
        "url": "https://api.anquanke.com/data/v1/rss",
        "keyword_filter": True,
    },
]


# ---------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------

def utc_now():
    return datetime.now(timezone.utc)

def since_utc():
    return utc_now() - timedelta(days=WINDOW_DAYS)

def safe_text(x):
    return (x or "").strip()

def keyword_match(text: str) -> bool:
    """Match keywords in a tolerant way (lowercase)."""
    t = (text or "").lower()
    return any(k.lower() in t for k in KEYWORDS)

def parse_entry_datetime(entry) -> datetime | None:
    """
    RSS/Atom date extraction:
    - published / updated (string)
    - published_parsed / updated_parsed (struct_time)
    """
    # 1) string dates
    for attr in ("published", "updated", "created"):
        if hasattr(entry, attr):
            val = getattr(entry, attr)
            if val:
                try:
                    dt = dateparser.parse(val)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except Exception:
                    pass

    # 2) struct_time
    for attr in ("published_parsed", "updated_parsed", "created_parsed"):
        if hasattr(entry, attr):
            st = getattr(entry, attr)
            if st:
                try:
                    dt = datetime(*st[:6], tzinfo=timezone.utc)
                    return dt
                except Exception:
                    pass

    return None

def load_existing(path: str):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def dump_json(path: str, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def build_dedupe_key(item: dict) -> str:
    """Dedup primarily by link; fallback by title+source if link missing."""
    link = safe_text(item.get("link"))
    title = safe_text(item.get("title"))
    source = safe_text(item.get("source"))
    if link:
        return f"link::{link}"
    return f"title::{source}::{title}"

def extract_cves(text: str):
    """Extract CVE IDs for later enrichment in UI if you want."""
    return sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text or "", re.IGNORECASE)))

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------

def main():
    since = since_utc()

    # Load existing candidates to keep state (status changes etc.)
    existing = load_existing(OUTPUT_FILE)

    # Index existing for dedupe
    seen = set(build_dedupe_key(x) for x in existing)

    new_items = []

    for feed in FEEDS:
        url = feed["url"]
        parsed = feedparser.parse(url)

        # Robustness: if the feed is malformed, skip but continue
        if getattr(parsed, "bozo", 0) == 1 and not getattr(parsed, "entries", None):
            continue

        for entry in (parsed.entries or []):
            dt = parse_entry_datetime(entry)
            if not dt:
                continue
            if dt < since:
                continue

            title = safe_text(entry.get("title"))
            link = safe_text(entry.get("link"))
            summary = safe_text(entry.get("summary"))

            # Keyword filter (reduces noise)
            do_filter = feed.get("keyword_filter", DEFAULT_KEYWORD_FILTER)
            if do_filter:
                haystack = f"{title} {summary}"
                if not keyword_match(haystack):
                    continue

            item = {
                "date": dt.date().isoformat(),
                "datetime_utc": dt.isoformat(),
                "source": feed["source"],
                "region": feed.get("region", ""),
                "trust": feed.get("trust", ""),
                "category": feed.get("category", "RSS"),
                "title": title,
                "link": link,
                "summary": summary[:600],   # évite de gonfler le JSON
                "cves": extract_cves(f"{title} {summary}"),
                "status": "to-review",
                "origin": "RSS",
            }

            k = build_dedupe_key(item)
            if k in seen:
                continue

            seen.add(k)
            new_items.append(item)

    # Merge while preserving existing entries (and their potential status edits)
    merged = existing + new_items

    # Sort newest first
    merged.sort(key=lambda x: x.get("datetime_utc", x.get("date", "")), reverse=True)

    # Hard cap to keep repo tidy
    if len(merged) > MAX_ITEMS_TOTAL:
        merged = merged[:MAX_ITEMS_TOTAL]

    dump_json(OUTPUT_FILE, merged)

    print(f"✅ RSS aggregation done: {len(new_items)} new items added")
    print(f"✅ Total candidates now: {len(merged)}")

if __name__ == "__main__":
    main()

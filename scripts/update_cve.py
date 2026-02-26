import json
import os
from datetime import datetime, timezone, timedelta
import requests

# Chemin du fichier JSON (aligné avec ton schéma actuel)
JSON_PATH = "data/vuln-watch.json"

# APIs
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TIMEOUT = 15


def now_iso_utc():
    """ISO-8601 en UTC (format Z)"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_get(d, *keys, default=None):
    """Accès safe à un dict imbriqué"""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def ensure_dict(d, key):
    if key not in d or not isinstance(d[key], dict):
        d[key] = {}
    return d[key]


def is_remote_exploitable(vuln):
    """
    Heuristique simple basée sur exploitation_conditions.attack_vector :
    True si contient 'remote' ou 'network' (insensible à la casse).
    """
    av = str(safe_get(vuln, "exploitation_conditions", "attack_vector", default="")).lower()
    return ("remote" in av) or ("network" in av)


def fetch_epss(cve_id):
    """Retourne (epss_score, percentile) ou (None, None) si indisponible."""
    try:
        r = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=TIMEOUT)
        r.raise_for_status()
        payload = r.json()
        recs = payload.get("data") or []
        if not recs:
            return None, None
        rec = recs[0]
        epss = float(rec.get("epss")) if rec.get("epss") is not None else None
        pct = float(rec.get("percentile")) if rec.get("percentile") is not None else None
        return epss, pct
    except Exception as e:
        print(f"[EPSS] Erreur pour {cve_id}: {e}")
        return None, None


def fetch_kev_catalog():
    """
    Retourne un dict mapping:
      cveID -> dateAdded (ou None)
    """
    try:
        r = requests.get(KEV_URL, timeout=TIMEOUT)
        r.raise_for_status()
        payload = r.json()
        kev_map = {}
        for v in payload.get("vulnerabilities", []) or []:
            if isinstance(v, dict) and v.get("cveID"):
                kev_map[v["cveID"]] = v.get("dateAdded")
        return kev_map
    except Exception as e:
        print(f"[KEV] Erreur récupération catalogue: {e}")
        return {}


def compute_priority(remote, kev, epss):
    """
    Score automatique “Remote + KEV + EPSS”
    - EPSS: 0..1 → points 0..5 (epss*5)
    - Remote: +2
    - KEV: +3
    total capé à 10

    Niveaux:
    - CRITICAL: score >= 8  OU (KEV et remote) OU (KEV et EPSS>=0.20)
    - HIGH:     score >= 6
    - MEDIUM:   score >= 3
    - LOW:      sinon
    """
    epss_val = float(epss) if isinstance(epss, (int, float)) else 0.0
    epss_val = max(0.0, min(1.0, epss_val))

    score = epss_val * 5.0 + (2.0 if remote else 0.0) + (3.0 if kev else 0.0)
    score = round(min(10.0, score), 2)

    if score >= 8.0 or (kev and remote) or (kev and epss_val >= 0.20):
        level = "CRITICAL"
    elif score >= 6.0:
        level = "HIGH"
    elif score >= 3.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def review_frequency_days(level, status):
    """
    Fréquence de revue selon priorité.
    - mitigated/closed => 90 jours
    - CRITICAL => 7
    - HIGH => 14
    - MEDIUM => 30
    - LOW => 60
    """
    st = str(status or "").lower()
    if st in ("closed", "mitigated"):
        return 90, "Status mitigated/closed: revue espacée (archivage/monitoring)."
    if level == "CRITICAL":
        return 7, "CRITICAL: Remote/KEV/EPSS élevé → revue hebdomadaire."
    if level == "HIGH":
        return 14, "HIGH: revue toutes les 2 semaines."
    if level == "MEDIUM":
        return 30, "MEDIUM: revue mensuelle."
    return 60, "LOW: revue bimestrielle."


def update_json():
    if not os.path.exists(JSON_PATH):
        print(f"Fichier JSON introuvable: {JSON_PATH}")
        return

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Schéma attendu: data["vulnerabilities"] est un dict
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, dict):
        raise ValueError("Schéma invalide: racine 'vulnerabilities' absente ou non objet")

    # Meta (optionnel)
    meta = ensure_dict(data, "meta")
    meta["generated_at"] = now_iso_utc()

    kev_map = fetch_kev_catalog()
    now = datetime.now(timezone.utc)

    has_changed = False

    for cve_key, vuln in vulns.items():
        if not isinstance(vuln, dict):
            continue

        cve_id = vuln.get("cve_id") or cve_key
        vuln["cve_id"] = cve_id  # normalisation

        # Dates
        dates = ensure_dict(vuln, "dates")
        if not dates.get("monitoring_start"):
            dates["monitoring_start"] = now_iso_utc()
            has_changed = True
        dates["last_check"] = now_iso_utc()

        # Metrics scaffolding
        metrics = ensure_dict(vuln, "metrics")
        epss_obj = ensure_dict(metrics, "epss")
        kev_obj = ensure_dict(metrics, "kev_status")

        # EPSS update
        epss_score, epss_pct = fetch_epss(cve_id)
        if epss_score is not None:
            # initial si absent
            if epss_obj.get("initial") in (None, "", 0):
                epss_obj["initial"] = round(float(epss_score), 4)
                has_changed = True

            old_epss = epss_obj.get("current")
            new_epss = round(float(epss_score), 4)
            if old_epss != new_epss:
                epss_obj["current"] = new_epss
                has_changed = True

            if epss_pct is not None:
                new_pct = round(float(epss_pct), 4)
                if epss_obj.get("percentile") != new_pct:
                    epss_obj["percentile"] = new_pct
                    has_changed = True

        # KEV update
        kev_hit = cve_id in kev_map
        old_kev = bool(kev_obj.get("current", False))
        if old_kev != kev_hit:
            kev_obj["current"] = kev_hit
            has_changed = True

        # date_added si KEV
        if kev_hit:
            if kev_obj.get("date_added") in (None, ""):
                kev_obj["date_added"] = kev_map.get(cve_id) or now.strftime("%Y-%m-%d")
                has_changed = True
            # initial (si pas encore défini)
            if "initial" not in kev_obj:
                kev_obj["initial"] = False

        # === Calcul “Remote + KEV + EPSS” ===
        remote = is_remote_exploitable(vuln)
        epss_current = epss_obj.get("current")
        kev_current = bool(kev_obj.get("current", False))

        score, level = compute_priority(remote, kev_current, epss_current)

        watchtower = ensure_dict(vuln, "watchtower")
        priority = ensure_dict(watchtower, "priority")
        new_priority = {
            "score": score,
            "level": level,
            "signals": {
                "remote_exploitable": remote,
                "kev": kev_current,
                "epss_current": float(epss_current) if isinstance(epss_current, (int, float)) else None
            }
        }
        if priority != new_priority:
            watchtower["priority"] = new_priority
            has_changed = True

        # === Dates de revue ===
        review = ensure_dict(watchtower, "review")

        # last_review: on ne l’écrase pas si déjà existant (revue humaine)
        if not review.get("last_review"):
            review["last_review"] = now_iso_utc()
            has_changed = True

        freq_days, rationale = review_frequency_days(level, vuln.get("status", "active"))
        if review.get("frequency_days") != freq_days:
            review["frequency_days"] = freq_days
            has_changed = True

        # next_review: basé sur last_review si parseable, sinon maintenant
        base = now
        try:
            lr = review.get("last_review")
            if lr:
                base = datetime.fromisoformat(lr.replace("Z", "+00:00"))
        except Exception:
            base = now

        next_review = (base + timedelta(days=freq_days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        if review.get("next_review") != next_review:
            review["next_review"] = next_review
            has_changed = True

        if review.get("rationale") != rationale:
            review["rationale"] = rationale
            has_changed = True

    # Sauvegarde
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    if has_changed:
        print("✅ Changements enregistrés dans le JSON.")
    else:
        print("ℹ️ Aucun changement détecté.")

if __name__ == "__main__":
    update_json()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analyze CPE inventory with NVD CVE API 2.0 + CISA KEV.

Input:
  data/inventory/cpelist.json

Output:
  data/inventory/cve_inventory.json

GitHub Actions secret expected:
  NVD_API_KEY

Usage:
  python scripts/analyze_cpes.py
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_KEY = os.getenv("NVD_API_KEY", None)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEV_URL = (
    "https://raw.githubusercontent.com/"
    "cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

# Chemins repo GitHub Actions.
# Si tu tiens absolument à /data/inventory/cpelist.json, le script essaie aussi
# cette variante absolue si le chemin relatif n'existe pas.
INPUT_FILE = Path(os.getenv("CPE_INPUT_FILE", "data/inventory/cpelist.json"))
OUTPUT_FILE = Path(os.getenv("CVE_OUTPUT_FILE", "data/inventory/cve_inventory.json"))

RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "2000"))

# Délai entre appels NVD.
# Avec clé API NVD, 0.7 s est généralement prudent pour des inventaires moyens.
REQUEST_DELAY_SECONDS = float(os.getenv("NVD_REQUEST_DELAY_SECONDS", "0.7"))

# Nombre de tentatives en cas de 429 / 5xx / erreur réseau.
MAX_RETRIES = int(os.getenv("NVD_MAX_RETRIES", "5"))

# Timeout HTTP.
HTTP_TIMEOUT_SECONDS = int(os.getenv("HTTP_TIMEOUT_SECONDS", "90"))

# Exclure les CVE rejetées.
NO_REJECTED = os.getenv("NVD_NO_REJECTED", "true").lower() in ("1", "true", "yes", "y")


# ---------------------------------------------------------------------------
# RCE heuristic
# ---------------------------------------------------------------------------

RCE_KEYWORDS = [
    "remote code execution",
    "remote arbitrary code execution",
    "arbitrary code execution",
    "execute arbitrary code",
    "execution of arbitrary code",
    "code execution vulnerability",
    "unauthenticated code execution",
    "pre-authentication code execution",
    "pre-auth code execution",
    "remote command execution",
    "arbitrary command execution",
    "execute arbitrary commands",
    "command injection",
    "os command injection",
    "code injection",
    "server-side template injection",
    "template injection",
    "deserialization of untrusted data",
    "unsafe deserialization",
    "insecure deserialization",
    "java deserialization",
    "php object injection",
    "expression language injection",
]

# CWE très souvent associés à des RCE.
# Ce n'est pas une preuve absolue de RCE : on le sort en "heuristique".
RCE_CWES = {
    "CWE-77",    # Improper Neutralization of Special Elements used in a Command
    "CWE-78",    # OS Command Injection
    "CWE-94",    # Code Injection
    "CWE-95",    # Eval Injection
    "CWE-502",   # Deserialization of Untrusted Data
    "CWE-917",   # Expression Language Injection
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def resolve_input_file() -> Path:
    """
    Supporte :
      - data/inventory/cpelist.json
      - /data/inventory/cpelist.json
    """
    if INPUT_FILE.exists():
        return INPUT_FILE

    absolute_variant = Path("/data/inventory/cpelist.json")
    if absolute_variant.exists():
        return absolute_variant

    raise FileNotFoundError(
        f"Fichier CPE introuvable. Chemins testés: {INPUT_FILE} et {absolute_variant}"
    )


def normalize_cpe(value: str) -> Optional[str]:
    value = str(value).strip().strip('"').strip("'")
    if value.startswith("cpe:2.3:"):
        return value
    return None


def extract_cpes_from_text(text: str) -> List[str]:
    """
    Extrait tous les CPE 2.3 depuis un texte libre.
    """
    pattern = re.compile(r"cpe:2\.3:[aho]:[^\s,;\"']+", re.IGNORECASE)
    return sorted(set(m.group(0).strip() for m in pattern.finditer(text)))


def iter_values(obj: Any) -> Iterable[Any]:
    """
    Itère récursivement dans un JSON pour retrouver des champs CPE,
    au cas où cpelist.json soit plus structuré qu'une simple liste.
    """
    if isinstance(obj, dict):
        for value in obj.values():
            yield value
            yield from iter_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield item
            yield from iter_values(item)


def load_cpes(input_file: Path) -> List[str]:
    """
    Formats supportés :

    1) Liste simple :
       [
         "cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*"
       ]

    2) Objet :
       {
         "cpes": [
           "cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*"
         ]
       }

    3) Objets :
       {
         "items": [
           {"cpe": "cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*"},
           {"cpe23": "cpe:2.3:a:nginx:nginx:1.27.0:*:*:*:*:*:*:*"}
         ]
       }

    4) Texte JSON contenant des CPE dans des chaînes.
    """
    raw_text = input_file.read_text(encoding="utf-8")
    cpes: Set[str] = set()

    # Extraction regex globale, utile même si la structure varie.
    cpes.update(extract_cpes_from_text(raw_text))

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON invalide dans {input_file}: {exc}") from exc

    # Cas explicite {"cpes": [...]}
    if isinstance(data, dict) and isinstance(data.get("cpes"), list):
        for item in data["cpes"]:
            if isinstance(item, str):
                cpe = normalize_cpe(item)
                if cpe:
                    cpes.add(cpe)
            elif isinstance(item, dict):
                for key in ("cpe", "cpe23", "cpeName", "cpe_name", "criteria"):
                    if key in item:
                        cpe = normalize_cpe(str(item[key]))
                        if cpe:
                            cpes.add(cpe)

    # Cas récursif plus générique.
    for value in iter_values(data):
        if isinstance(value, str):
            cpe = normalize_cpe(value)
            if cpe:
                cpes.add(cpe)

    result = sorted(cpes)

    if not result:
        raise ValueError(f"Aucun CPE 2.3 détecté dans {input_file}")

    return result


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "github-actions-cpe-nvd-kev-analyzer/1.0",
            "Accept": "application/json",
        }
    )

    if API_KEY:
        session.headers.update({"apiKey": API_KEY})

    return session


def request_json_with_retries(
    session: requests.Session,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = HTTP_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    last_exc: Optional[Exception] = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(url, params=params, timeout=timeout)

            if response.status_code in (429, 500, 502, 503, 504):
                message = response.headers.get("message", "")
                wait = min(60, attempt * attempt * 2)
                eprint(
                    f"[WARN] HTTP {response.status_code} sur {url}. "
                    f"Tentative {attempt}/{MAX_RETRIES}. "
                    f"Message: {message}. Attente {wait}s."
                )
                time.sleep(wait)
                continue

            if not response.ok:
                message = response.headers.get("message", "")
                body_preview = response.text[:500] if response.text else ""
                raise RuntimeError(
                    f"HTTP {response.status_code} sur {url}. "
                    f"Message header: {message}. Body: {body_preview}"
                )

            return response.json()

        except (requests.RequestException, json.JSONDecodeError, RuntimeError) as exc:
            last_exc = exc
            wait = min(60, attempt * attempt * 2)
            eprint(
                f"[WARN] Erreur requête tentative {attempt}/{MAX_RETRIES}: {exc}. "
                f"Attente {wait}s."
            )
            time.sleep(wait)

    raise RuntimeError(f"Échec après {MAX_RETRIES} tentatives: {last_exc}")


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------

def load_kev_catalog(session: requests.Session) -> Tuple[Set[str], Dict[str, Dict[str, Any]]]:
    data = request_json_with_retries(session, KEV_URL)

    vulnerabilities = data.get("vulnerabilities", [])
    kev_set: Set[str] = set()
    kev_map: Dict[str, Dict[str, Any]] = {}

    for item in vulnerabilities:
        cve_id = item.get("cveID") or item.get("cve_id") or item.get("cve")
        if cve_id:
            kev_set.add(cve_id)
            kev_map[cve_id] = item

    return kev_set, kev_map


# ---------------------------------------------------------------------------
# NVD parsing
# ---------------------------------------------------------------------------

def get_english_description(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "") or ""

    if descriptions:
        return descriptions[0].get("value", "") or ""

    return ""


def get_weaknesses(cve: Dict[str, Any]) -> List[str]:
    weaknesses: List[str] = []

    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value:
                weaknesses.append(value)

    return sorted(set(weaknesses))


def get_references(cve: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = cve.get("references", [])

    # NVD 2.0 expose généralement references comme liste.
    if isinstance(refs, list):
        return refs

    # Compatibilité éventuelle avec d'anciens formats.
    if isinstance(refs, dict):
        return refs.get("referenceData", []) or []

    return []


def get_best_cvss_v3(cve: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sélectionne le meilleur CVSS v3 :
      1) Priorité aux métriques Primary
      2) Puis CVSS 3.1 avant 3.0
      3) Puis score le plus élevé si plusieurs candidats
    """
    metrics = cve.get("metrics", {}) or {}
    candidates: List[Dict[str, Any]] = []

    for metric_key, version_rank in (("cvssMetricV31", 31), ("cvssMetricV30", 30)):
        for metric in metrics.get(metric_key, []) or []:
            cvss_data = metric.get("cvssData", {}) or {}
            score = cvss_data.get("baseScore")

            candidates.append(
                {
                    "metric_key": metric_key,
                    "version": cvss_data.get("version"),
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                    "base_score": score,
                    "base_severity": (
                        cvss_data.get("baseSeverity")
                        or metric.get("baseSeverity")
                        or None
                    ),
                    "vector": cvss_data.get("vectorString"),
                    "exploitability_score": metric.get("exploitabilityScore"),
                    "impact_score": metric.get("impactScore"),
                    "_version_rank": version_rank,
                    "_type_rank": 1 if metric.get("type") == "Primary" else 0,
                }
            )

    if not candidates:
        return {
            "cvss_version": None,
            "cvss_base_score": None,
            "cvss_base_severity": "UNKNOWN",
            "cvss_vector": None,
            "cvss_source": None,
            "cvss_type": None,
            "cvss_exploitability_score": None,
            "cvss_impact_score": None,
        }

    candidates.sort(
        key=lambda x: (
            x["_type_rank"],
            x["_version_rank"],
            float(x["base_score"] or 0),
        ),
        reverse=True,
    )

    best = candidates[0]

    return {
        "cvss_version": best["version"],
        "cvss_base_score": best["base_score"],
        "cvss_base_severity": best["base_severity"] or "UNKNOWN",
        "cvss_vector": best["vector"],
        "cvss_source": best["source"],
        "cvss_type": best["type"],
        "cvss_exploitability_score": best["exploitability_score"],
        "cvss_impact_score": best["impact_score"],
    }


def detect_rce(cve: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Détection RCE heuristique.
    Retourne:
      - bool
      - liste de raisons
    """
    reasons: List[str] = []

    description = get_english_description(cve)
    description_low = description.lower()

    for keyword in RCE_KEYWORDS:
        if keyword in description_low:
            reasons.append(f"description_keyword:{keyword}")

    weaknesses = get_weaknesses(cve)
    weakness_upper = {w.upper() for w in weaknesses}

    matched_cwes = sorted(RCE_CWES.intersection(weakness_upper))
    for cwe in matched_cwes:
        reasons.append(f"weakness:{cwe}")

    # Références : utile mais moins fort, on ne déclenche que si un mot-clé
    # d'exécution existe aussi dans la description.
    refs = get_references(cve)
    ref_text = " ".join(
        [
            " ".join(ref.get("tags", []) or [])
            + " "
            + str(ref.get("url", ""))
            + " "
            + str(ref.get("source", ""))
            for ref in refs
        ]
    ).lower()

    if (
        "exploit" in ref_text
        and (
            "command" in description_low
            or "code execution" in description_low
            or "execute arbitrary" in description_low
        )
    ):
        reasons.append("reference:exploit_with_execution_context")

    # Déduplication en conservant l'ordre.
    deduped = list(dict.fromkeys(reasons))

    return bool(deduped), deduped


def compute_priority(kev: bool, rce: bool, cvss_score: Optional[float]) -> str:
    score = float(cvss_score or 0)

    if kev and (rce or score >= 9.0):
        return "CRITICAL"

    if kev:
        return "HIGH"

    if rce and score >= 9.0:
        return "CRITICAL"

    if rce:
        return "HIGH"

    if score >= 9.0:
        return "HIGH"

    if score >= 7.0:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "UNKNOWN"


def is_better_cvss(new_score: Optional[float], old_score: Optional[float]) -> bool:
    return float(new_score or 0) > float(old_score or 0)


# ---------------------------------------------------------------------------
# NVD querying
# ---------------------------------------------------------------------------

def query_nvd_for_cpe(session: requests.Session, cpe: str) -> List[Dict[str, Any]]:
    """
    Retourne la liste complète des objets vulnerabilities NVD pour un cpeName.
    """
    vulnerabilities: List[Dict[str, Any]] = []

    start_index = 0
    total_results = None

    while True:
        params: Dict[str, Any] = {
            "cpeName": cpe,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }

        if NO_REJECTED:
            # Paramètre booléen NVD API 2.0.
            # requests l'encodera comme noRejected=.
            params["noRejected"] = ""

        data = request_json_with_retries(session, NVD_URL, params=params)

        page_items = data.get("vulnerabilities", []) or []
        vulnerabilities.extend(page_items)

        total_results = int(data.get("totalResults", 0))
        results_per_page = int(data.get("resultsPerPage", RESULTS_PER_PAGE))

        eprint(
            f"[NVD] {cpe} | startIndex={start_index} | "
            f"page={len(page_items)} | total={total_results}"
        )

        start_index += results_per_page

        if start_index >= total_results:
            break

        time.sleep(REQUEST_DELAY_SECONDS)

    return vulnerabilities


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze() -> Dict[str, Any]:
    input_file = resolve_input_file()
    output_file = OUTPUT_FILE

    eprint(f"[INFO] Input CPE file: {input_file}")
    eprint(f"[INFO] Output CVE file: {output_file}")
    eprint(f"[INFO] NVD API key present: {'yes' if API_KEY else 'no'}")

    session = make_session()

    cpes = load_cpes(input_file)
    eprint(f"[INFO] CPE détectés: {len(cpes)}")

    kev_set, kev_map = load_kev_catalog(session)
    eprint(f"[INFO] KEV chargés: {len(kev_set)}")

    inventory: Dict[str, Dict[str, Any]] = {}
    by_cpe: Dict[str, Dict[str, Any]] = {}

    errors: List[Dict[str, str]] = []

    for index, cpe in enumerate(cpes, start=1):
pes)}: {cpe}")

        by_cpe.setdefault(
            cpe,
            {
                "cpe": cpe,
                "total_cves": 0,
                "kev_cves": 0,
                "rce_cves": 0,
                "max_cvss_base_score": None,
                "cves": [],
                "error": None,
            },
        )

        try:
            vulnerabilities = query_nvd_for_cpe(session, cpe)

        except Exception as exc:
            error_msg = str(exc)
            eprint(f"[ERROR] {cpe}: {error_msg}")
            by_cpe[cpe]["error"] = error_msg
            errors.append({"cpe": cpe, "error": error_msg})
            continue

        for item in vulnerabilities:
            cve = item.get("cve", {}) or {}
            cve_id = cve.get("id")

            if not cve_id:
                continue

            cvss = get_best_cvss_v3(cve)
            cvss_score = cvss["cvss_base_score"]
            kev = cve_id in kev_set
            rce, rce_reasons = detect_rce(cve)
            priority = compute_priority(kev, rce, cvss_score)

            description = get_english_description(cve)
            weaknesses = get_weaknesses(cve)

            kev_details = kev_map.get(cve_id, {}) if kev else {}

            if cve_id not in inventory:
                inventory[cve_id] = {
                    "cve_id": cve_id,
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "vuln_status": cve.get("vulnStatus"),
                    "description_en": description,

                    "cvss_version": cvss["cvss_version"],
                    "cvss_base_score": cvss_score,
                    "cvss_base_severity": cvss["cvss_base_severity"],
                    "cvss_vector": cvss["cvss_vector"],
                    "cvss_source": cvss["cvss_source"],
                    "cvss_type": cvss["cvss_type"],
                    "cvss_exploitability_score": cvss["cvss_exploitability_score"],
                    "cvss_impact_score": cvss["cvss_impact_score"],

                    "kev": kev,
                    "kev_date_added": kev_details.get("dateAdded"),
                    "kev_due_date": kev_details.get("dueDate"),
                    "kev_known_ransomware_campaign_use": kev_details.get(
                        "knownRansomwareCampaignUse"
                    ),
                    "kev_required_action": kev_details.get("requiredAction"),
                    "kev_notes": kev_details.get("notes"),

                    "rce": rce,
                    "rce_reasons": rce_reasons,

                    "priority": priority,
                    "weaknesses": weaknesses,

                    "cpes": [],
                    "source_cpe_count": 0,
                }

            else:
                existing = inventory[cve_id]

                # Si une autre entrée NVD donne un meilleur CVSS v3, on garde le plus élevé.
                if is_better_cvss(cvss_score, existing.get("cvss_base_score")):
                    existing.update(
                        {
                            "cvss_version": cvss["cvss_version"],
                            "cvss_base_score": cvss_score,
                            "cvss_base_severity": cvss["cvss_base_severity"],
                            "cvss_vector": cvss["cvss_vector"],
                            "cvss_source": cvss["cvss_source"],
                            "cvss_type": cvss["cvss_type"],
                            "cvss_exploitability_score": cvss[
                                "cvss_exploitability_score"
                            ],
                            "cvss_impact_score": cvss["cvss_impact_score"],
                        }
                    )

                # Fusion RCE.
                existing["rce"] = bool(existing.get("rce")) or rce
                existing["rce_reasons"] = sorted(
                    set(existing.get("rce_reasons", []) + rce_reasons)
                )

                # Fusion weaknesses.
                existing["weaknesses"] = sorted(
                    set(existing.get("weaknesses", []) + weaknesses)
                )

                # La priorité peut changer après fusion.
                existing["priority"] = compute_priority(
                    bool(existing.get("kev")),
                    bool(existing.get("rce")),
                    existing.get("cvss_base_score"),
                )

            if cpe not in inventory[cve_id]["cpes"]:
                inventory[cve_id]["cpes"].append(cpe)

            if cve_id not in by_cpe[cpe]["cves"]:
                by_cpe[cpe]["cves"].append(cve_id)

        # Stats par CPE après traitement de la page complète.
        cve_ids_for_cpe = by_cpe[cpe]["cves"]

        by_cpe[cpe]["total_cves"] = len(cve_ids_for_cpe)
        by_cpe[cpe]["kev_cves"] = sum(
            1 for cve_id in cve_ids_for_cpe if inventory[cve_id]["kev"]
        )
        by_cpe[cpe]["rce_cves"] = sum(
            1 for cve_id in cve_ids_for_cpe if inventory[cve_id]["rce"]
        )

        scores = [
            inventory[cve_id].get("cvss_base_score")
            for cve_id in cve_ids_for_cpe
            if inventory[cve_id].get("cvss_base_score") is not None
        ]

        by_cpe[cpe]["max_cvss_base_score"] = max(scores) if scores else None

        time.sleep(REQUEST_DELAY_SECONDS)

    # Finalisation source_cpe_count.
    for cve_item in inventory.values():
        cve_item["cpes"] = sorted(set(cve_item["cpes"]))
        cve_item["source_cpe_count"] = len(cve_item["cpes"])

    cves_sorted = sorted(
        inventory.values(),
        key=lambda x: (
            # KEV d'abord
            not bool(x.get("kev")),
            # RCE ensuite
            not bool(x.get("rce")),
            # Score descendant
            -float(x.get("cvss_base_score") or 0),
            # Date publication descendante
            str(x.get("published") or ""),
            # CVE ID
            str(x.get("cve_id") or ""),
        ),
    )

    total_kev = sum(1 for x in cves_sorted if x.get("kev"))
    total_rce = sum(1 for x in cves_sorted if x.get("rce"))
    total_cvss_critical = sum(
        1 for x in cves_sorted if float(x.get("cvss_base_score") or 0) >= 9.0
    )

    result = {
        "generated_at": utc_now_iso(),
        "source_file": str(input_file),
        "nvd_api": {
            "endpoint": NVD_URL,
            "results_per_page": RESULTS_PER_PAGE,
            "no_rejected": NO_REJECTED,
            "api_key_present": bool(API_KEY),
        },
        "kev_source": KEV_URL,
        "summary": {
            "total_cpes": len(cpes),
            "total_cves": len(cves_sorted),
            "total_kev_cves": total_kev,
            "total_rce_cves": total_rce,
            "total_cvss_base_score_gte_9": total_cvss_critical,
            "total_errors": len(errors),
        },
        "errors": errors,
        "by_cpe": [by_cpe[cpe] for cpe in sorted(by_cpe.keys())],
        "cves": cves_sorted,
    }

    return result


def main() -> None:
    try:
        result = analyze()

        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

        with OUTPUT_FILE.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        eprint(f"[OK] JSON généré: {OUTPUT_FILE}")
        eprint(
            "[OK] Résumé: "
            f"{result['summary']['total_cpes']} CPE, "
            f"{result['summary']['total_cves']} CVE, "
            f"{result['summary']['total_kev_cves']} KEV, "
            f"{result['summary']['total_rce_cves']} RCE heuristiques."
        )

    except Exception as exc:
        eprint(f"[FATAL] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

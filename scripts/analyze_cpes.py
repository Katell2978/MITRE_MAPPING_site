#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_cpes.py

Lit data/inventory/cpelist.json, interroge NVD CVE API 2.0 par cpeName,
enrichit avec CISA KEV, détecte RCE par heuristique, puis écrit :
  data/inventory/cve_inventory.json

Variables GitHub Actions supportées :
  NVD_API_KEY               secret NVD, utilisé dans le header apiKey
  CPE_INPUT_FILE              défaut: data/inventory/cpelist.json
  CVE_OUTPUT_FILE              défaut: data/inventory/cve_inventory.json
  NVD_MAX_WORKERS             défaut: 3
  NVD_RESULTS_PER_PAGE        défaut: 2000
  NVD_REQUEST_DELAY_SECONDS   défaut: 0.7
  NVD_MAX_RETRIES              défaut: 5
  HTTP_TIMEOUT_SECONDS        défaut: 90
  NVD_NO_REJECTED              défaut: true
"""

import json
import os
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests


# =============================================================================
# Configuration
# =============================================================================

API_KEY = os.getenv("NVD_API_KEY", None)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEV_URL = (
    "https://raw.githubusercontent.com/"
    "cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

INPUT_FILE = Path(os.getenv("CPE_INPUT_FILE", "data/inventory/cpelist.json"))
OUTPUT_FILE = Path(os.getenv("CVE_OUTPUT_FILE", "data/inventory/cve_inventory.json"))

MAX_WORKERS = int(os.getenv("NVD_MAX_WORKERS", "3"))
RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "2000"))
REQUEST_DELAY_SECONDS = float(os.getenv("NVD_REQUEST_DELAY_SECONDS", "0.7"))
MAX_RETRIES = int(os.getenv("NVD_MAX_RETRIES", "5"))
HTTP_TIMEOUT_SECONDS = int(os.getenv("HTTP_TIMEOUT_SECONDS", "90"))
NO_REJECTED = os.getenv("NVD_NO_REJECTED", "true").lower() in {"1", "true", "yes", "y"}


# =============================================================================
# RCE heuristic
# =============================================================================

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

RCE_CWES = {
    "CWE-77",
    "CWE-78",
    "CWE-94",
    "CWE-95",
    "CWE-502",
    "CWE-917",
}


# =============================================================================
# Thread-local HTTP session and global rate limiter
# =============================================================================

_thread_local = threading.local()
_rate_lock = threading.Lock()
_last_request_ts = 0.0


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr, flush=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rate_limit_wait() -> None:
    """
    Limiteur global simple pour éviter de déclencher toutes les requêtes NVD
    exactement en même temps, même avec plusieurs workers.
    """
    global _last_request_ts

    with _rate_lock:
        now = time.monotonic()
        delta = now - _last_request_ts

        if delta < REQUEST_DELAY_SECONDS:
            time.sleep(REQUEST_DELAY_SECONDS - delta)

        _last_request_ts = time.monotonic()


def get_session() -> requests.Session:
    """
    Une session requests par thread.
    """
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "github-actions-cpe-nvd-kev-analyzer/1.0",
                "Accept": "application/json",
            }
        )

        if API_KEY:
            session.headers.update({"apiKey": API_KEY})

        _thread_local.session = session

    return _thread_local.session


# =============================================================================
# Input loading
# =============================================================================

def resolve_input_file() -> Path:
    if INPUT_FILE.exists():
        return INPUT_FILE

    absolute_variant = Path("/data/inventory/cpelist.json")

    if absolute_variant.exists():
        return absolute_variant

    raise FileNotFoundError(
        f"Fichier CPE introuvable. Chemins testés: {INPUT_FILE} et {absolute_variant}"
    )


def extract_cpes_from_text(text: str) -> List[str]:
    pattern = re.compile(r"cpe:2\.3:[^\s,;\"']+", re.IGNORECASE)
    return sorted({match.group(0).strip() for match in pattern.finditer(text)})


def normalize_cpe(value: Any) -> Optional[str]:
    if value is None:
        return None

    text = str(value).strip().strip('"').strip("'")

    if text.startswith("cpe:2.3:"):
        return text

    return None


def iter_json_values(obj: Any) -> Iterable[Any]:
    if isinstance(obj, dict):
        for value in obj.values():
            yield value
            yield from iter_json_values(value)

    elif isinstance(obj, list):
        for item in obj:
            yield item
            yield from iter_json_values(item)


def load_cpes(input_file: Path) -> List[str]:
    """
    Formats supportés :
    1. Liste simple : ["cpe:2.3:a:..."]
    2. Objet avec cpes : {"cpes": ["cpe:2.3:a:..."]}
    3. Objets imbriqués : {"items": [{"cpe": "cpe:2.3:a:..."}]}
    4. Tout JSON contenant des chaînes CPE.
    """
    raw_text = input_file.read_text(encoding="utf-8")

    cpes: Set[str] = set(extract_cpes_from_text(raw_text))

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON invalide dans {input_file}: {exc}") from exc

    if isinstance(data, dict) and isinstance(data.get("cpes"), list):
        for item in data["cpes"]:
            if isinstance(item, str):
                cpe = normalize_cpe(item)
                if cpe:
                    cpes.add(cpe)
            elif isinstance(item, dict):
                for key in ("cpe", "cpe23", "cpeName", "cpe_name", "criteria"):
                    cpe = normalize_cpe(item.get(key))
                    if cpe:
                        cpes.add(cpe)

    for value in iter_json_values(data):
        if isinstance(value, str):
            cpe = normalize_cpe(value)
            if cpe:
                cpes.add(cpe)

    result = sorted(cpes)

    if not result:
        raise ValueError(f"Aucun CPE 2.3 détecté dans {input_file}")

    return result


# =============================================================================
# HTTP helpers
# =============================================================================

def request_json_with_retries(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = HTTP_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    session = get_session()
    last_error: Optional[Exception] = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            rate_limit_wait()

            response = session.get(
                url,
                params=params,
                timeout=timeout,
            )

            if response.status_code in {429, 500, 502, 503, 504}:
                message = response.headers.get("message", "")
                wait_seconds = min(90, 2 * attempt * attempt)

                eprint(
                    f"[WARN] HTTP {response.status_code} | "
                    f"attempt={attempt}/{MAX_RETRIES} | "
                    f"wait={wait_seconds}s | "
                    f"message={message}"
                )

                time.sleep(wait_seconds)
                continue

            if not response.ok:
                message = response.headers.get("message", "")
                body_preview = response.text[:500] if response.text else ""

                raise RuntimeError(
                    f"HTTP {response.status_code} on {url}. "
                    f"Header message: {message}. "
                    f"Body preview: {body_preview}"
                )

            return response.json()

        except (requests.RequestException, json.JSONDecodeError, RuntimeError) as exc:
            last_error = exc
            wait_seconds = min(90, 2 * attempt * attempt)

            eprint(
                f"[WARN] Request error | "
                f"attempt={attempt}/{MAX_RETRIES} | "
                f"wait={wait_seconds}s | "
                f"error={exc}"
            )

            time.sleep(wait_seconds)

    raise RuntimeError(f"Échec après {MAX_RETRIES} tentatives: {last_error}")


# =============================================================================
# KEV loading
# =============================================================================

def load_kev_catalog() -> Tuple[Set[str], Dict[str, Dict[str, Any]]]:
    data = request_json_with_retries(KEV_URL)

    vulnerabilities = data.get("vulnerabilities", []) or []

    kev_set: Set[str] = set()
    kev_map: Dict[str, Dict[str, Any]] = {}

    for item in vulnerabilities:
        cve_id = item.get("cveID") or item.get("cve_id") or item.get("cve")
        if cve_id:
            kev_set.add(cve_id)
            kev_map[cve_id] = item

    return kev_set, kev_map


# =============================================================================
# NVD parsing
# =============================================================================

def get_english_description(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", []) or []

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "") or ""

    if descriptions:
        return descriptions[0].get("value", "") or ""

    return ""


def get_weaknesses(cve: Dict[str, Any]) -> List[str]:
    weaknesses: Set[str] = set()

    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value")
            if value:
                weaknesses.add(value)

    return sorted(weaknesses)


def get_references(cve: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = cve.get("references", []) or []

    if isinstance(refs, list):
        return refs

    if isinstance(refs, dict):
        return refs.get("referenceData", []) or []

    return []


def get_best_cvss_v3(cve: Dict[str, Any]) -> Dict[str, Any]:
    metrics = cve.get("metrics", {}) or {}
    candidates: List[Dict[str, Any]] = []

    for metric_key, version_rank in (("cvssMetricV31", 31), ("cvssMetricV30", 30)):
        for metric in metrics.get(metric_key, []) or []:
            cvss_data = metric.get("cvssData", {}) or {}

            candidates.append(
                {
                    "version": cvss_data.get("version"),
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                    "base_score": cvss_data.get("baseScore"),
                    "base_severity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                    "exploitability_score": metric.get("exploitabilityScore"),
                    "impact_score": metric.get("impactScore"),
                    "_type_rank": 1 if metric.get("type") == "Primary" else 0,
                    "_version_rank": version_rank,
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
        key=lambda item: (
            item["_type_rank"],
            item["_version_rank"],
            float(item["base_score"] or 0),
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
    reasons: List[str] = []

    description = get_english_description(cve)
    description_lower = description.lower()

    for keyword in RCE_KEYWORDS:
        if keyword in description_lower:
            reasons.append(f"description_keyword:{keyword}")

    weaknesses = {w.upper() for w in get_weaknesses(cve)}

    for cwe in sorted(RCE_CWES.intersection(weaknesses)):
        reasons.append(f"weakness:{cwe}")

    references = get_references(cve)

    reference_text = " ".join(
        [
            " ".join(ref.get("tags", []) or [])
            + " "
            + str(ref.get("url", ""))
            + " "
            + str(ref.get("source", ""))
            for ref in references
        ]
    ).lower()

    if (
        "exploit" in reference_text
        and (
            "command" in description_lower
            or "code execution" in description_lower
            or "execute arbitrary" in description_lower
        )
    ):
        reasons.append("reference:exploit_with_execution_context")

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


# =============================================================================
# NVD querying
# =============================================================================

def query_nvd_for_cpe(cpe: str) -> List[Dict[str, Any]]:
    vulnerabilities: List[Dict[str, Any]] = []
    start_index = 0

    while True:
        params: Dict[str, Any] = {
            "cpeName": cpe,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }

        if NO_REJECTED:
            params["noRejected"] = ""

        data = request_json_with_retries(
            NVD_URL,
            params=params,
        )

        page_items = data.get("vulnerabilities", []) or []
        vulnerabilities.extend(page_items)

        total_results = int(data.get("totalResults", 0))
        results_per_page = int(data.get("resultsPerPage", RESULTS_PER_PAGE))

        eprint(
            f"[NVD] cpe={cpe} | "
            f"startIndex={start_index} | "
            f"page={len(page_items)} | "
            f"total={total_results}"
        )

        start_index += results_per_page

        if start_index >= total_results:
            break

    return vulnerabilities


# =============================================================================
# Worker and merge
# =============================================================================

def analyze_one_cpe(
    cpe: str,
    kev_set: Set[str],
    kev_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    try:
        vulnerabilities = query_nvd_for_cpe(cpe)
        cve_records: List[Dict[str, Any]] = []

        for item in vulnerabilities:
            cve = item.get("cve", {}) or {}
            cve_id = cve.get("id")

            if not cve_id:
                continue

            cvss = get_best_cvss_v3(cve)
            cvss_score = cvss["cvss_base_score"]

            kev = cve_id in kev_set
            kev_details = kev_map.get(cve_id, {}) if kev else {}

            rce, rce_reasons = detect_rce(cve)

            priority = compute_priority(
                kev=kev,
                rce=rce,
                cvss_score=cvss_score,
            )

            record = {
                "cve_id": cve_id,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "vuln_status": cve.get("vulnStatus"),
                "description_en": get_english_description(cve),
                "cvss_version": cvss["cvss_version"],
                "cvss_base_score": cvss["cvss_base_score"],
                "cvss_base_severity": cvss["cvss_base_severity"],
                "cvss_vector": cvss["cvss_vector"],
                "cvss_source": cvss["cvss_source"],
                "cvss_type": cvss["cvss_type"],
                "cvss_exploitability_score": cvss["cvss_exploitability_score"],
                "cvss_impact_score": cvss["cvss_impact_score"],
                "kev": kev,
                "kev_date_added": kev_details.get("dateAdded"),
                "kev_due_date": kev_details.get("dueDate"),
                "kev_known_ransomware_campaign_use": kev_details.get("knownRansomwareCampaignUse"),
                "kev_required_action": kev_details.get("requiredAction"),
                "kev_notes": kev_details.get("notes"),
                "rce": rce,
                "rce_reasons": rce_reasons,
                "priority": priority,
                "weaknesses": get_weaknesses(cve),
                "cpes": [cpe],
                "source_cpe_count": 1,
            }
            cve_records.append(record)

        scores = [
            float(item["cvss_base_score"])
            for item in cve_records
            if item.get("cvss_base_score") is not None
        ]
        max_cvss = max(scores) if scores else None

        return {
            "cpe": cpe,
            "ok": True,
            "error": None,
            "cves": cve_records,
            "by_cpe": {
                "cpe": cpe,
                "total_cves": len(cve_records),
                "kev_cves": sum(1 for item in cve_records if item["kev"]),
                "rce_cves": sum(1 for item in cve_records if item["rce"]),
                "max_cvss_base_score": max_cvss,
                "cves": sorted({item["cve_id"] for item in cve_records}),
                "error": None,
            },
        }

    except Exception as exc:
        error = str(exc)
        eprint(f"[ERROR] cpe={cpe} | {error}")
        return {
            "cpe": cpe,
            "ok": False,
            "error": error,
            "cves": [],
            "by_cpe": {
                "cpe": cpe,
                "total_cves": 0,
                "kev_cves": 0,
                "rce_cves": 0,
                "max_cvss_base_score": None,
                "cves": [],
                "error": error,
            },
        }


def should_replace_cvss(new_item: Dict[str, Any], old_item: Dict[str, Any]) -> bool:
    new_score = float(new_item.get("cvss_base_score") or 0)
    old_score = float(old_item.get("cvss_base_score") or 0)

    if new_score > old_score:
        return True
    if new_score < old_score:
        return False

    new_is_primary = new_item.get("cvss_type") == "Primary"
    old_is_primary = old_item.get("cvss_type") == "Primary"

    return new_is_primary and not old_is_primary


def merge_cve(inventory: Dict[str, Dict[str, Any]], item: Dict[str, Any]) -> None:
    cve_id = item["cve_id"]

    if cve_id not in inventory:
        inventory[cve_id] = dict(item)
        inventory[cve_id]["cpes"] = sorted(set(item.get("cpes", [])))
        inventory[cve_id]["source_cpe_count"] = len(inventory[cve_id]["cpes"])
        return

    existing = inventory[cve_id]

    if should_replace_cvss(item, existing):
        for key in (
            "cvss_version", "cvss_base_score", "cvss_base_severity",
            "cvss_vector", "cvss_source", "cvss_type",
            "cvss_exploitability_score", "cvss_impact_score"
        ):
            existing[key] = item.get(key)

    existing["kev"] = bool(existing.get("kev")) or bool(item.get("kev"))
    existing["rce"] = bool(existing.get("rce")) or bool(item.get("rce"))
    existing["rce_reasons"] = sorted(set(existing.get("rce_reasons", []) + item.get("rce_reasons", [])))
    existing["weaknesses"] = sorted(set(existing.get("weaknesses", []) + item.get("weaknesses", [])))
    existing["cpes"] = sorted(set(existing.get("cpes", []) + item.get("cpes", [])))
    existing["source_cpe_count"] = len(existing["cpes"])

    existing["priority"] = compute_priority(
        kev=bool(existing.get("kev")),
        rce=bool(existing.get("rce")),
        cvss_score=existing.get("cvss_base_score"),
    )


# =============================================================================
# Main analysis
# =============================================================================

def analyze() -> Dict[str, Any]:
    input_file = resolve_input_file()

    eprint(f"[INFO] Input file: {input_file}")
    eprint(f"[INFO] Output file: {OUTPUT_FILE}")
    eprint(f"[INFO] NVD API key present: {'yes' if API_KEY else 'no'}")
    eprint(f"[INFO] MAX_WORKERS={MAX_WORKERS}")
    eprint(f"[INFO] RESULTS_PER_PAGE={RESULTS_PER_PAGE}")
    eprint(f"[INFO] NO_REJECTED={NO_REJECTED}")

    cpes = load_cpes(input_file)
    eprint(f"[INFO] CPE loaded: {len(cpes)}")

    kev_set, kev_map = load_kev_catalog()
    eprint(f"[INFO] KEV loaded: {len(kev_set)}")

    inventory: Dict[str, Dict[str, Any]] = {}
    by_cpe: Dict[str, Dict[str, Any]] = {}
    errors: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(analyze_one_cpe, cpe, kev_set, kev_map): cpe
            for cpe in cpes
        }

        done_count = 0
        for future in as_completed(future_map):
            cpe = future_map[future]
            done_count += 1

            eprint(f"[INFO] Completed {done_count}/{len(cpes)}: {cpe}")

            try:
                result = future.result()
            except Exception as exc:
                error = str(exc)
                eprint(f"[ERROR] Worker failed for {cpe}: {error}")
                errors.append({"cpe": cpe, "error": error})
                by_cpe[cpe] = {
                    "cpe": cpe, "total_cves": 0, "kev_cves": 0, "rce_cves": 0,
                    "max_cvss_base_score": None, "cves": [], "error": error
                }
                continue

            by_cpe[cpe] = result["by_cpe"]

            if not result["ok"]:
                errors.append({"cpe": cpe, "error": result["error"]})
                continue

            for cve_item in result["cves"]:
                merge_cve(inventory, cve_item)

    cves_sorted = sorted(
        inventory.values(),
        key=lambda item: (
            not bool(item.get("kev")),
            not bool(item.get("rce")),
            -float(item.get("cvss_base_score") or 0),
            str(item.get("published") or ""),
            str(item.get("cve_id") or ""),
        ),
    )

    total_kev = sum(1 for item in cves_sorted if item.get("kev"))
    total_rce = sum(1 for item in cves_sorted if item.get("rce"))
    total_cvss_gte_9 = sum(1 for item in cves_sorted if float(item.get("cvss_base_score") or 0) >= 9.0)

    result = {
        "generated_at": utc_now_iso(),
        "source_file": str(input_file),
        "nvd_api": {
            "endpoint": NVD_URL,
            "results_per_page": RESULTS_PER_PAGE,
            "no_rejected": NO_REJECTED,
            "api_key_present": bool(API_KEY),
            "max_workers": MAX_WORKERS,
            "request_delay_seconds": REQUEST_DELAY_SECONDS,
        },
        "kev_source": KEV_URL,
        "summary": {
            "total_cpes": len(cpes),
            "total_cves": len(cves_sorted),
            "total_kev_cves": total_kev,
            "total_rce_cves": total_rce,
            "total_cvss_base_score_gte_9": total_cvss_gte_9,
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

        with OUTPUT_FILE.open("w", encoding="utf-8") as file:
            json.dump(result, file, indent=2, ensure_ascii=False)

        eprint(f"[OK] JSON generated: {OUTPUT_FILE}")
        eprint(
            "[OK] Summary: "
            f"{result['summary']['total_cpes']} CPE, "
            f"{result['summary']['total_cves']} CVE, "
            f"{result['summary']['total_kev_cves']} KEV, "
            f"{result['summary']['total_rce_cves']} RCE, "
            f"{result['summary']['total_errors']} errors."
        )

    except Exception as exc:
        eprint(f"[FATAL] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

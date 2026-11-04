import os
import subprocess
import shutil
import json
from pathlib import Path

# Configuration des chemins et du dépôt source
VULNRICHMENT_REPO_URL = "https://github.com/cisagov/vulnrichment.git"
CLONE_DIR = "temp_vulnrichment"
OUTPUT_DIR = "data/vulnrichment_summary"

def clone_or_update_repo():
    """Clone ou met à jour le dépôt CISA avec un historique minimal (--depth 1)."""
    if os.path.exists(CLONE_DIR):
        print("Mise à jour du dépôt vulnrichment existant...")
        subprocess.run(["git", "-C", CLONE_DIR, "pull"], check=True)
    else:
        print("Clonage superficiel du dépôt cisagov/vulnrichment...")
        subprocess.run(["git", "clone", "--depth", "1", VULNRICHMENT_REPO_URL, CLONE_DIR], check=True)

def process_vuln_data():
    """Parcourt les fichiers JSON et les regroupe par année pour éviter les fichiers trop lourds."""
    path = Path(CLONE_DIR)
    output_path = Path(OUTPUT_DIR)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Dictionnaire pour stocker les données classées par année
    by_year = {}
    count = 0
    
    print("Analyse et extraction des données de vulnérabilités...")
    for json_file in path.glob("**/*.json"):
        if ".git" in json_file.parts:
            continue
            
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            cve_id = data.get("cveMetadata", {}).get("cveId", json_file.stem)
            
            # Extraire l'année du CVE (ex: CVE-2024-1234 -> 2024)
            parts = cve_id.split("-")
            year = parts[1] if len(parts) > 1 and parts[1].isdigit() else "other"
            
            # Recherche du conteneur d'enrichissement CISA (ADP)
            adps = data.get("containers", {}).get("adp", [])
            cisa_enrichment = None
            for adp in adps:
                provider = adp.get("providerMetadata", {}).get("shortName", "").lower()
                org_id = adp.get("providerMetadata", {}).get("orgId", "")
                if "cisa" in provider or "13467591-2774-489e-91fe-df3e57e4e58d" in org_id:
                    cisa_enrichment = adp
                    break
            
            if cisa_enrichment:
                if year not in by_year:
                    by_year[year] = {}
                    
                by_year[year][cve_id] = {
                    "cveId": cve_id,
                    "metrics": cisa_enrichment.get("metrics", []),
                    "problemTypes": cisa_enrichment.get("problemTypes", []),
                    "other": cisa_enrichment.get("other", {})
                }
                count += 1
        except Exception:
            continue

    # Nettoyer l'ancien fichier unique s'il existe pour éviter qu'il ne reste dans Git
    old_single_file = output_path / "vulnrichment_summary.json"
    if old_single_file.exists():
        old_single_file.unlink()

    # Sauvegarder un fichier JSON distinct par année
    for year, items in by_year.items():
        year_file = output_path / f"cve_{year}.json"
        with open(year_file, 'w', encoding='utf-8') as f:
            json.dump(items, f, indent=2, ensure_ascii=False)
        print(f"Fichier généré : {year_file.name} ({len(items)} CVEs)")
        
    print(f"Succès ! Total de {count} CVEs enrichies réparties par année.")

def clean_up():
    """Supprime le dossier temporaire cloné."""
    if os.path.exists(CLONE_DIR):
        print("Nettoyage des fichiers temporaires...")
        shutil.rmtree(CLONE_DIR)

if __name__ == "__main__":
    try:
        clone_or_update_repo()
        process_vuln_data()
    finally:
        clean_up()

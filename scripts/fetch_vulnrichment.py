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
    """Clone ou met à jour le dépôt CISA avec un historique minimal (--depth 1) pour gagner du temps et de l'espace."""
    if os.path.exists(CLONE_DIR):
        print("Mise à jour du dépôt vulnrichment existant...")
        subprocess.run(["git", "-C", CLONE_DIR, "pull"], check=True)
    else:
        print("Clonage superficiel du dépôt cisagov/vulnrichment...")
        subprocess.run(["git", "clone", "--depth", "1", VULNRICHMENT_REPO_URL, CLONE_DIR], check=True)

def process_vuln_data():
    """Parcourt les fichiers JSON du dépôt pour extraire l'enrichissement CISA (ADP)."""
    path = Path(CLONE_DIR)
    output_path = Path(OUTPUT_DIR)
    output_path.mkdir(parents=True, exist_ok=True)
    
    summary = {}
    count = 0
    
    print("Analyse et extraction des données de vulnérabilités...")
    for json_file in path.glob("**/*.json"):
        # Ignorer le dossier .git interne
        if ".git" in json_file.parts:
            continue
            
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            cve_id = data.get("cveMetadata", {}).get("cveId", json_file.stem)
            
            # Recherche du conteneur d'enrichissement CISA (ADP)
            adps = data.get("containers", {}).get("adp", [])
            cisa_enrichment = None
            for adp in adps:
                provider = adp.get("providerMetadata", {}).get("shortName", "").lower()
                org_id = adp.get("providerMetadata", {}).get("orgId", "")
                if "cisa" in provider or "13467591-2774-489e-91fe-df3e57e4e58d" in org_id:
                    cisa_enrichment = adp
                    break
            
            # Si un enrichissement CISA est présent, on l'ajoute au résumé
            if cisa_enrichment:
                summary[cve_id] = {
                    "cveId": cve_id,
                    "metrics": cisa_enrichment.get("metrics", []),
                    "problemTypes": cisa_enrichment.get("problemTypes", []),
                    "references": cisa_enrichment.get("references", []),
                    "other": cisa_enrichment.get("other", {})
                }
                count += 1
        except Exception:
            # Ignorer les fichiers mal formés ou illisibles
            continue

    # Sauvegarde du fichier résumé exploitable par votre site web
    output_file = output_path / "vulnrichment_summary.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
        
    print(f"Succès ! {count} CVEs enrichies exportées vers {output_file}")

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

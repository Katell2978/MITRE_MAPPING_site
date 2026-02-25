import requests
import json
import os
from datetime import datetime

# Chemins des fichiers
JSON_PATH = 'data/vulnerability.json'

def fetch_cve_data(cve_id):
    """Interroge l'API NVD pour le CVSS et l'API FIRST pour l'EPSS."""
    # 1. Récupération EPSS
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    epss_val = 0.0
    try:
        r = requests.get(epss_url, timeout=10)
        data = r.json()
        if data['data']:
            epss_val = float(data['data'][0]['epss'])
    except Exception as e:
        print(f"Erreur EPSS: {e}")

    # 2. Récupération KEV (CISA)
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    is_kev = False
    try:
        r = requests.get(kev_url, timeout=10)
        kev_catalog = r.json()
        is_kev = any(v['cveID'] == cve_id for v in kev_catalog['vulnerabilities'])
    except Exception as e:
        print(f"Erreur KEV: {e}")

    return {"epss": epss_val, "kev": is_kev}

def update_json():
    if not os.path.exists(JSON_PATH):
        print("Fichier JSON introuvable.")
        return

    with open(JSON_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)

    cve_id = data['vulnerability_watch']['cve_id']
    updates = fetch_cve_data(cve_id)

    # Détection de changements majeurs pour notification
    has_changed = False
    
    # Update EPSS
    if updates['epss'] != data['vulnerability_watch']['metrics']['epss']['current']:
        print(f"Mise à jour EPSS détectée pour {cve_id}")
        data['vulnerability_watch']['metrics']['epss']['current'] = updates['epss']
        has_changed = True

    # Update KEV Status
    if updates['kev'] != data['vulnerability_watch']['metrics']['kev_status']['current']:
        print(f"ALERTE : Statut KEV modifié pour {cve_id} !")
        data['vulnerability_watch']['metrics']['kev_status']['current'] = updates['kev']
        if updates['kev']:
            data['vulnerability_watch']['metrics']['kev_status']['date_added'] = datetime.now().strftime("%Y-%m-%d")
        has_changed = True

    # Mise à jour de la date de dernier contrôle
    data['vulnerability_watch']['dates']['last_check'] = datetime.now().isoformat()

    # Sauvegarde
    with open(JSON_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    if has_changed:
        print("Changements enregistrés dans le JSON.")

if __name__ == "__main__":
    update_json()

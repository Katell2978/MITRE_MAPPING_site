import json
import requests
import time
import os
from datetime import datetime

# --- CE SCRIPT lIT mon inventaire de CPE et chercher les CVE sur le NVD ---
# --- CONFIGURATION ---
INVENTORY_PATH = 'data/inventory/inventory_cpe.json'
RESULTS_PATH = 'data/results/detected_vulns.json'
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Ajoute ta clé API ici ou via une variable d'environnement GitHub Secret
API_KEY = os.getenv('NVD_API_KEY', None) 

def load_inventory():
    with open(INVENTORY_PATH, 'r') as f:
        return json.load(f)

def scan_cpe(cpe_string):
    """Interroge la NVD pour un CPE spécifique."""
    print(f"[*] Analyse du CPE : {cpe_string}")
    params = {'virtualMatchString': cpe_string}
    headers = {'apiKey': API_KEY} if API_KEY else {}
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json().get('vulnerabilities', [])
        elif response.status_code == 403:
            print("[!] Rate limit atteint. Attente nécessaire.")
            return []
    except Exception as e:
        print(f"[!] Erreur API : {e}")
        return []

def main():
    inventory = load_inventory()
    all_findings = []
    
    # On limite pour la démo pour ne pas se faire bannir par la NVD immédiatement
    for ecu in inventory:
        ecu_id = ecu['component_id']
        # On ne scanne que les 3 premiers CPE de chaque ECU pour tester
        for cpe in ecu['cpe_list'][:3]: 
            vulns = scan_cpe(cpe)
            
            for v in vulns:
                cve_data = v['cve']
                finding = {
                    "ecu": ecu_id,
                    "cpe": cpe,
                    "cve_id": cve_data['id'],
                    "description": cve_data['descriptions'][0]['value'],
                    "published": cve_data['published'],
                    "last_modified": cve_data['lastModified'],
                    "metrics": cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}),
                    "scan_date": datetime.now().isoformat()
                }
                all_findings.append(finding)
            
            # Délai de courtoisie (5-10 sec sans clé, < 1 sec avec clé)
            time.sleep(6 if not API_KEY else 0.6)

    # Sauvegarde des résultats
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, 'w') as f:
        json.dump(all_findings, f, indent=2)
    
    print(f"\n[+] Scan terminé. {len(all_findings)} vulnérabilités trouvées.")
    print(f"[+] Résultats stockés dans : {RESULTS_PATH}")

if __name__ == "__main__":
    main()

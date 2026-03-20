import json
import requests
import time
import os
from datetime import datetime

# --- CONFIGURATION DES CHEMINS ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY_PATH = os.path.join(BASE_DIR, 'data', 'inventory', 'inventory_cpe.json')
RESULTS_DIR = os.path.join(BASE_DIR, 'data', 'results')
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Clé API NVD (Optionnelle mais recommandée)
API_KEY = os.getenv('NVD_API_KEY', None) 

def load_inventory():
    if not os.path.exists(INVENTORY_PATH):
        print(f"[!] Erreur : Inventaire introuvable à {INVENTORY_PATH}")
        return []
    with open(INVENTORY_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def scan_cpe(cpe_string):
    print(f"[*] Analyse NVD pour : {cpe_string}")
    params = {'virtualMatchString': cpe_string}
    headers = {'apiKey': API_KEY} if API_KEY else {}
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
        if response.status_code == 200:
            return response.json().get('vulnerabilities', [])
        return []
    except Exception as e:
        print(f"[!] Erreur : {e}")
        return []

def main():
    os.makedirs(os.path.join(BASE_DIR, 'data', 'inventory'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'data', 'results'), exist_ok=True)
    inventory = load_inventory()
    if not inventory: return

    all_findings = []
    
    for ecu in inventory:
        ecu_id = ecu['component_id']
        for cpe in ecu['cpe_list'][:5]: 
            vulns = scan_cpe(cpe)
            
            for v in vulns:
                cve_obj = v['cve']
                
                # Extraction CWE
                cwe_list = [d.get('value') for w in cve_obj.get('weaknesses', []) 
                            for d in w.get('description', []) if d.get('value', '').startswith('CWE-')]
                
                description = cve_obj['descriptions'][0]['value']
                
                # Métriques CVSS
                m_data = cve_obj.get('metrics', {})
                metrics = m_data.get('cvssMetricV31', [{}])[0].get('cvssData', {}) or \
                          m_data.get('cvssMetricV30', [{}])[0].get('cvssData', {})

                all_findings.append({
                    "ecu": ecu_id,
                    "cve_id": cve_obj['id'],
                    "cwe_ids": list(set(cwe_list)),
                    "description": description,
                    "is_rce": "remote code execution" in description.lower(),
                    "metrics": metrics,
                    "scan_date": datetime.now().isoformat()
                })
            time.sleep(6 if not API_KEY else 0.6)

    # --- GESTION DE L'HORODATAGE ---
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # 1. Nom de fichier unique avec Date et Heure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"detected_vulns_{timestamp}.json"
    full_path = os.path.join(RESULTS_DIR, filename)

    # 2. Sauvegarde du fichier horodaté
    with open(full_path, 'w', encoding='utf-8') as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)
    
    # 3. MISE À JOUR DU FICHIER "LATEST" (Pour le Dashboard)
    # On écrase toujours 'detected_vulns.json' pour que le HTML n'ait pas à changer de nom
    latest_path = os.path.join(RESULTS_DIR, 'detected_vulns.json')
    with open(latest_path, 'w', encoding='utf-8') as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Archive créée : {filename}")
    print(f"[+] Dashboard mis à jour : detected_vulns.json")

if __name__ == "__main__":
    main()

import json
import requests
import time
import os
from datetime import datetime

# --- CONFIGURATION DES CHEMINS ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY_PATH = os.path.join(BASE_DIR, 'data', 'inventory', 'inventory_cpe.json')
RESULTS_PATH = os.path.join(BASE_DIR, 'data', 'results', 'detected_vulns.json')
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Remplace par ta clé si tu en as une pour lever les limites de débit
API_KEY = os.getenv('NVD_API_KEY', None) 

def load_inventory():
    if not os.path.exists(INVENTORY_PATH):
        print(f"[!] Erreur : Inventaire introuvable à {INVENTORY_PATH}")
        return []
    with open(INVENTORY_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def scan_cpe(cpe_string):
    """Interroge la NVD pour un CPE spécifique."""
    print(f"[*] Analyse NVD pour : {cpe_string}")
    params = {'virtualMatchString': cpe_string}
    headers = {'apiKey': API_KEY} if API_KEY else {}
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
        if response.status_code == 200:
            return response.json().get('vulnerabilities', [])
        elif response.status_code == 403:
            print("[!] Rate limit atteint (403). Attente requise.")
            return []
        else:
            print(f"[!] Erreur API {response.status_code}")
            return []
    except Exception as e:
        print(f"[!] Erreur de connexion : {e}")
        return []

def main():
    inventory = load_inventory()
    if not inventory: return

    all_findings = []
    
    for ecu in inventory:
        ecu_id = ecu['component_id']
        # On scanne les 5 premiers CPE de chaque ECU pour rester efficace
        for cpe in ecu['cpe_list'][:5]: 
            vulns = scan_cpe(cpe)
            
            for v in vulns:
                cve_obj = v['cve']
                
                # --- EXTRACTION DES CWE (CRUCIAL POUR LE MAPPING) ---
                cwe_list = []
                for weakness in cve_obj.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        val = desc.get('value')
                        if val and val.startswith('CWE-'):
                            cwe_list.append(val)
                
                # --- DÉTECTION DES DRAPEAUX (FLAGS) ---
                description = cve_obj['descriptions'][0]['value']
                is_rce = "remote code execution" in description.lower() or " rce " in description.lower()
                
                # Extraction des métriques CVSS v3.1 ou v3.0
                metrics = {}
                m_data = cve_obj.get('metrics', {})
                cvss_v31 = m_data.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                cvss_v30 = m_data.get('cvssMetricV30', [{}])[0].get('cvssData', {})
                metrics = cvss_v31 if cvss_v31 else cvss_v30

                finding = {
                    "ecu": ecu_id,
                    "cpe": cpe,
                    "cve_id": cve_obj['id'],
                    "cwe_ids": list(set(cwe_list)), # Unicité des CWE
                    "description": description,
                    "is_rce": is_rce,
                    "is_kev": False, # Placeholder : à croiser avec la liste CISA si besoin
                    "published": cve_obj['published'],
                    "last_modified": cve_obj['lastModified'],
                    "metrics": metrics,
                    "scan_date": datetime.now().isoformat()
                }
                all_findings.append(finding)
            
            # Délai de courtoisie pour l'API NVD
            time.sleep(6 if not API_KEY else 0.6)

    # Sauvegarde finale
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, 'w', encoding='utf-8') as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)
    
    print(f"\n[+] SCAN TERMINÉ : {len(all_findings)} vulnérabilités enregistrées.")
    print(f"[+] Fichier mis à jour : {RESULTS_PATH}")

if __name__ == "__main__":
    main()

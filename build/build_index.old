import json
import os
import urllib.request

def download_if_needed(url, dest):
    print(f"Téléchargement de {dest} depuis MITRE...")
    try:
        urllib.request.urlretrieve(url, dest)
        print(f"✅ {dest} téléchargé ({os.path.getsize(dest) // 1024} KB)")
    except Exception as e:
        print(f"❌ Erreur de téléchargement pour {dest}: {e}")

def generate_mitre_index():
    # 1. Préparation des dossiers
    if not os.path.exists("matrices"): os.makedirs("matrices")
    if not os.path.exists("build"): os.makedirs("build")

    # 2. Liens officiels du MITRE
    sources = {
        "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
    }
    
    # 3. Téléchargement automatique
    for key, url in sources.items():
        download_if_needed(url, f"matrices/{key}.json")

    # 4. Traitement des fichiers
    master_index = {}
    for key in sources.keys():
        path = f"matrices/{key}.json"
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for obj in data.get('objects', []):
                    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                        tid = next((ref.get('external_id') for ref in obj.get('external_references', []) 
                                  if ref.get('source_name').startswith('mitre')), None)
                        if tid:
                            if tid in master_index:
                                if key not in master_index[tid]['m']: master_index[tid]['m'].append(key)
                            else:
                                master_index[tid] = {
                                    "n": obj.get('name'),
                                    "m": [key],
                                    "t": [p.get('phase_name') for p in obj.get('kill_chain_phases', [])]
                                }

    # 5. Sauvegarde
    with open("build/mitre_map_index.json", "w", encoding="utf-8") as f:
        json.dump(master_index, f, separators=(',', ':'))
    
    print(f"\n--- FINI ---")
    print(f"L'index contient maintenant {len(master_index)} techniques.")

if __name__ == "__main__":
    generate_mitre_index()

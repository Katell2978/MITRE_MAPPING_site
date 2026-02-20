import json
import os
import urllib.request

def generate_mitre_index():
    # Création des dossiers au cas où
    for folder in ["matrices", "build"]:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"Dossier {folder} créé.")

    # 1. TÉLÉCHARGEMENT DU KEV (CRITIQUE)
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_dest = "build/kev.json"
    print(f"Tentative de téléchargement du KEV...")
    try:
        # On utilise un User-Agent pour éviter d'être bloqué par le site de la CISA
        req = urllib.request.Request(kev_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(kev_dest, 'wb') as out_file:
            out_file.write(response.read())
        print(f"✅ SUCCÈS : {kev_dest} a été créé ! ({os.path.getsize(kev_dest) // 1024} KB)")
    except Exception as e:
        print(f"❌ ERREUR KEV : Impossible de télécharger le fichier. Détails : {e}")

    # 2. TÉLÉCHARGEMENT DES MATRICES MITRE
    sources = {
        "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
    }
    
    master_index = {}
    for key, url in sources.items():
        dest = f"matrices/{key}.json"
        print(f"Téléchargement de {key}...")
        try:
            urllib.request.urlretrieve(url, dest)
            # Traitement MITRE (ton code habituel d'indexation)
            with open(dest, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for obj in data.get('objects', []):
                    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                        tid = next((ref.get('external_id') for ref in obj.get('external_references', []) 
                                  if ref.get('source_name').startswith('mitre')), None)
                        if tid:
                            if tid in master_index:
                                if key not in master_index[tid]['m']: master_index[tid]['m'].append(key)
                            else:
                                master_index[tid] = {"n": obj.get('name'), "m": [key], "t": [p.get('phase_name') for p in obj.get('kill_chain_phases', [])]}
        except Exception as e:
            print(f"Erreur sur {key}: {e}")

    # Sauvegarde de l'index MITRE
    with open("build/mitre_map_index.json", "w", encoding="utf-8") as f:
        json.dump(master_index, f, separators=(',', ':'))
    print(f"✅ Index MITRE généré avec {len(master_index)} techniques.")

if __name__ == "__main__":
    generate_mitre_index()

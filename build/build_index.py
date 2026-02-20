import json
import os
import urllib.request

def generate_mitre_index():
    if not os.path.exists("matrices"): os.makedirs("matrices")
    if not os.path.exists("build"): os.makedirs("build")

    # On ajoute le flux KEV de la CISA ici
    sources = {
        "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    }
    
    for key, url in sources.items():
        dest = f"matrices/{key}.json" if key != "kev" else f"build/kev.json"
        print(f"Téléchargement de {key}...")
        try:
            urllib.request.urlretrieve(url, dest)
        except Exception as e:
            print(f"Erreur sur {key}: {e}")

    # ... (gardez le reste de votre logique de traitement MITRE habituelle) ...
    # Le reste du script génère toujours build/mitre_map_index.json

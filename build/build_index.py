import json
import os
import sys

def generate_mitre_index():
    # Définition des chemins relatifs à la RACINE du dépôt
    # (Le script sera exécuté depuis la racine par le workflow)
    matrices = {
        "enterprise": "matrices/entreprise.json",
        "mobile": "matrices/mobile.json",
        "ics": "matrices/ics.json"
    }
    
    output_file = "build/mitre_map_index.json"
    master_index = {}

    print("--- Démarrage de l'indexation ---")
    
    # Vérification du dossier build
    if not os.path.exists("build"):
        os.makedirs("build")

    for matrix_key, file_path in matrices.items():
        if not os.path.exists(file_path):
            print(f"⚠️ Fichier introuvable : {file_path}")
            continue
            
        print(f"Analyse de {file_path}...")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                count = 0
                for obj in data.get('objects', []):
                    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                        # On cherche l'ID MITRE (Txxxx)
                        tid = next((ref.get('external_id') for ref in obj.get('external_references', []) 
                                  if ref.get('source_name') == 'mitre-attack'), None)
                        
                        if tid:
                            if tid in master_index:
                                if matrix_key not in master_index[tid]['m']:
                                    master_index[tid]['m'].append(matrix_key)
                            else:
                                master_index[tid] = {
                                    "n": obj.get('name'),
                                    "m": [matrix_key],
                                    "t": [p.get('phase_name') for p in obj.get('kill_chain_phases', [])]
                                }
                            count += 1
                print(f"✅ {matrix_key} : {count} techniques indexées.")
        except Exception as e:
            print(f"❌ Erreur sur {file_path} : {e}")

    # Sauvegarde finale
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(master_index, f, separators=(',', ':'))
    
    print(f"--- Fin ---")
    print(f"Fichier généré : {output_file} ({os.path.getsize(output_file) // 1024} KB)")

if __name__ == "__main__":
    generate_mitre_index()

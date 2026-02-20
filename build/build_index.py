import json
import os

def generate_mitre_index():
    # Configuration des sources
    matrices = {
        "enterprise": "matrices/enterprise-attack.json",
        "mobile": "matrices/mobile-attack.json",
        "ics": "matrices/ics-attack.json"
    }
    
    master_index = {}

    print("Début de la génération de mitre_map_index.json...")

    for matrix_name, file_path in matrices.items():
        if not os.path.exists(file_path):
            print(f"⚠️  Fichier {file_path} introuvable. Passage...")
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        count = 0
        for obj in data.get('objects', []):
            # On ne garde que les techniques (attack-pattern) non obsolètes
            if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
                
                # Extraction du matricule Txxxx
                tid = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        tid = ref.get('external_id')
                        break
                
                if tid:
                    # Si la technique existe déjà (partagée entre matrices), on ajoute la nouvelle matrice
                    if tid in master_index:
                        if matrix_name not in master_index[tid]['matrices']:
                            master_index[tid]['matrices'].append(matrix_name)
                    else:
                        # Création de l'entrée
                        master_index[tid] = {
                            "n": obj.get('name'),
                            "m": [matrix_name], # Matrices
                            "t": [p.get('phase_name') for p in obj.get('kill_chain_phases', [])] # Tactiques
                        }
                    count += 1
        
        print(f"✅ {matrix_name.capitalize()} : {count} techniques indexées.")

    # Sauvegarde du fichier final
    with open('mitre_map_index.json', 'w', encoding='utf-8') as f:
        json.dump(master_index, f, separators=(',', ':')) # Compression maximale

    print(f"\nTerminé ! Fichier généré : mitre_map_index.json ({os.path.getsize('mitre_map_index.json') // 1024} KB)")

if __name__ == "__main__":
    generate_mitre_index()

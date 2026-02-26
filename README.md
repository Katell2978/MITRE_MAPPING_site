MITRE MAPPING MITRE - Work in progress

Obj : permettre de trouver les liens entre les matrices pour simplifier la vie des équipes cyber

Restea faire 
Matrices à inclure : Mitre Attack Entreprise, Moobile et ICS, Mitre Emb3d, Auto-Isac ATM
Referentiel à inclure : CWE et CAPEC et KEV
Pour les vuln Mapping mesure de protection (Mitre Attack / Mobile / ICS / Emb3d)
referentiel TTP --> DET --> DATA

Le reve serait j'ai une CVE, j'ai un asset avec une proprieté exemple de l'emb3d et j'ai oui ou non la mesure de protection alors est-ce que la vuln est exploitable - mais bon la je reve un peu.

A etudier : si Technique dans les ADR - elemtary steps on peut aussi faire un fichier TechID --> ElementarySteps --> AdRID
pour retouver l'ADR a regarder (pour commencer)

Sur la Detection, il faudrait faire le lien avec les DET et savoir les lier au TUC dans une base confidentielle



En cible à long terme : identifier chaine complete d'un ID avec l'ensemble des element y c Data components et DET du Mitre Att&ck

Ce petit outil devrait pouvoir aussi faire le lien pour un CVE (mais ça on a déja par ailleurs)

Kat


Index.html fonctionnalitées :
✅ Recherche par CVE (NVD API v2.0)
✅ Recherche par CPE (NVD API v2.0 cpeName=...)
✅ Drilldown CWE → CAPEC → vraies Techniques MITRE ATT&CK (via tes fichiers data/cwe_db.json, data/capec_db.json, data/techniques_db.json)
TODO : Jointure ATT&CK → ATM (via data/ATM-matrix-TTP.csv) Pas 
TODO : Affiche ATM / DET / DC /  A voir si pertinant rmq
Ongoing mise en veille CVE
TODO: Mise en veille CPE
✅ Ajoute un visuel SVG “pivots & liens” (CWE→CAPEC→ATT&CK→ATM→DET/DC)
✅ Inclut un moniteur d’activité en bas de page (log détaillé)



Note pour regenerer listes des Tactiques et technqiues du Mitre avec recuperation des datas sur le site :
--> lancer le script  build/build_index.py depuis Codespaces via le bouton play.
--> si ok validate dans le source controle, puit commit(lebleu)

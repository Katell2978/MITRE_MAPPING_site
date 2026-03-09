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
TOFO : Ajouter condition d'exploitation critere
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




<-------------- CPEList2 ------------------------>
# 📦 CPEList — Analyse de vulnérabilités OFFLINE sur base du fichier de cpe dans data (NVD / EUVD / OSV)
 Objectif fournir une **chaîne complète OFFLINE** permettant :
 
- d’analyser des **produits formalisés en CPE 2.3**
- de **corréler les vulnérabilités** issues de plusieurs sources (NVD, EUVD, OSV)
- de **prioriser le risque** (CVSS, EPSS, KEV, RCE)
- sans **aucun appel réseau** côté navigateur
- compatible **GitHub Pages**

👉 Le résultat final est une **page HTML autonome** qui lit une base JSON locale enrichie.
---

## 🧱 Architecture globale

```text
┌──────────────────────┐
│ list_cpe.csv         │  ← Liste produits (CPE) dans data
└─────────┬────────────┘
          │
          ▼
┌──────────────────────┐
│ Scripts OFFLINE      │
│ - download_dumps     │  ← Téléchargement des dumps dans data et scripts dans scripts
│ - generate_db        │  ← Corrélation & enrichissement
└─────────┬────────────┘
          │
          ▼
┌──────────────────────┐
│ offline_cpe_db.json  │  ← Base locale enrichie
└─────────┬────────────┘
          │
          ▼
┌──────────────────────┐
│ CPEList_offline.html │  ← Analyse & priorisation
└──────────────────────┘


2️⃣ Télécharger les dumps OFFLINE
🛠 Script : scripts/download_dumps.sh
Rôle : télécharge les dumps officiels sans API, sans clé, sans proxy reproductible sur poste ou CI
Sources couvertes :
NVD : JSON feeds officiels (par année + modified)
OSV : dump global officiel (all.zip)
EUVD : export agrégé open (en attendant un dump officiel)

▶️ Exécution
Shellchmod +x tools/download_dumps.sh./tools/download_dumps.shAfficher plus de lignes
Résultat :
 data/nvd/*.json.gz
 data/osv/osv_all.zip
 data/euvd/euvd_dump.json

3️⃣ Générer la base OFFLINE enrichie
🛠 Script : scripts/generate_offline_db.py
Rôle :

lit list_cpe.csv
parcourt les dumps NVD / EUVD / OSV
corrèle par CPE
calcule un résumé par produit

Enrichissements produits :

nombre de CVE
CVSS max
EPSS max
KEV (CISA exploité)
CWE
base prête pour le calcul de score risque

▶️ Exécution
Shellpython3 tools/generate_offline_db.py
Résultats générés :

✅ data/offline_cpe_db.json
✅ data/offline_cpe_db.csv


4️⃣ Analyser avec la page HTML OFFLINE
🌐 CPEList2.html
Fonctionnement :

charge uniquement data/offline_cpe_db.json
aucun appel réseau
compatible GitHub Pages

Fonctionnalités :

affichage CVE / CVSS / EPSS / KEV / CWE
score de risque composite
🔥 filtre KEV
🧨 filtre RCE (heuristique CWE)
🧠 filtre par score minimal
tri par score / CVSS / #CVE
affichage des dates de mise à jour des dumps

🧠 Score de risque (logique)
Score simple, explicable et ajustable :
Plain TextScore = CVSS × (1.5 si KEV) × EPSS``Afficher plus de lignes
Objectif : priorisation exploitation réelle > sévérité théorique


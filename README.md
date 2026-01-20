# JDBC Oracle Analysis & Report Framework (AnalyseV2 / ReportV2)

Framework Python (compatible Python 2.6) pour **analyser**, **valider** et **reporter** des chaînes JDBC Oracle
(Current / New / DR) avec résolution DNS, CNAME, SCAN et persistance JSON (cache).

L’objectif est de :
- Extraire et normaliser les informations JDBC depuis un CSV
- Résoudre **Host → CNAME → SCAN**
- Comparer **Current vs New** et **Current vs NewDR**
- Mettre en cache les résultats (éviter nslookup/ssh srvctl si déjà calculé)
- Générer un reporting console (summary + détail par ID + debug)

---

## 📁 Contenu du projet

- `AnalyseV2.py` : moteur d’analyse (CSV → JSON cache)
- `ReportV2.py` : moteur de report (JSON → affichage summary / détail)
- `connexions_store_v2.json` : fichier de persistance (cache) généré par AnalyseV2
- (optionnel) `lib/` : future modularisation (voir section “Découpage recommandé”)

---

## ✅ Pré-requis

- Python 2.6+
- `nslookup` disponible sur la machine qui exécute AnalyseV2
- Accès SSH vers les hosts (si besoin de `srvctl config scan`) :
  - utilisateur attendu : `oracle@<host>`
  - `. /home/oracle/.bash_profile ; srvctl config scan`

---

## ⚙️ AnalyseV2

### Usage

```bash
python AnalyseV2.py file.csv ligne=N
python AnalyseV2.py file.csv ligne=ALL
python AnalyseV2.py file.csv id=N
python AnalyseV2.py file.csv columns
Options
Option	Description
-debug	Active les messages debug
-update	Force le recalcul (ignore le cache JSON, relance nslookup/ssh srvctl)
-h / -help / --help	Affiche l’aide

Fonctionnement résumé
Lecture CSV (DictReader avec ;)

Normalisation des clés/valeurs (gestion BOM + encodage mixte)

Construction d’un objet par ligne :

RawSource : colonnes du CSV conservées telles quelles

Interpreted : parsing JDBC (Current/New/DR)

Identity : Host/CNAME/SCAN pour Current/New/DR (si calcul)

Status : ValidSyntax + ScanCompare + Dirty + erreurs + mode

Persistance JSON : connexions_store_v2.json

Cache : si l’objet existe et RawSource inchangé et pas -update, on ne recalcul pas DNS/SCAN

📊 ReportV2
Usage
bash
Copier le code
python ReportV2.py connexions_store_v2.json
python ReportV2.py connexions_store_v2.json -summary
python ReportV2.py connexions_store_v2.json -summary ?
python ReportV2.py connexions_store_v2.json -summary Application=?
python ReportV2.py connexions_store_v2.json -summary Application=VALUE
python ReportV2.py connexions_store_v2.json id=N
python ReportV2.py connexions_store_v2.json id=N -debug
python ReportV2.py connexions_store_v2.json -help
Fonctionnalités
-summary : tableau compact (id, Database, Application, Lot, DR, Statut, Valid, Scan, ScanDR, Dirty)

filtres sur -summary (liste + valeurs possibles)

id=N : détail complet (métadata + JDBC parsed + status)

-debug : ajoute RAWSOURCE + détails d’erreur (ErrorType/ErrorDetail)

🧾 Structure JSON (contrat AnalyseV2 → ReportV2)
Chaque entrée objects[] contient :

id

RawSource : informations CSV (Application, Lot, Databases, Statut Global, etc.)

Interpreted :

CurrentJdbc, NewJdbc, NewJdbcDR

ParsedCurrentJdbc, ParsedNewJdbc, ParsedNewJdbcDR

DRHosts (liste)

Identités réseau (stockées pour cache) :

Identity.Current.Host, Identity.Current.CNAME, Identity.Current.SCAN

Identity.New.Host, Identity.New.CNAME, Identity.New.SCAN

Identity.NewDR.Host, Identity.NewDR.CNAME, Identity.NewDR.SCAN

Status :

ValidSyntax

ScanCompare, ScanCompareDR

Dirty, DirtyReason

ErrorType, ErrorDetail

Mode, LastUpdateTime

Remarque : les champs exacts peuvent évoluer, mais le principe est stable : RawSource + Interpreted + Identity + Status.

🔄 Logique cache (éviter nslookup/ssh srvctl)
Règle
Si l’objet existe dans le JSON

ET RawSource identique

ET pas de -update

➡️ alors :

on refait uniquement le parsing JDBC (Interpreted)

on réutilise Identity (Host/CNAME/SCAN) persisté

on ne relance pas nslookup/srvctl

Sinon
➡️ full compute (parsing + DNS + SCAN)

✅ Comparaison logique (Current/New et Current/DR)
Comparaison Current vs New
Si parsing invalide → ScanCompare=ERROR, ErrorType=SYNTAX_ERROR

Si type_adresse != SCAN → ScanCompare=NOT_APPLICABLE

Sinon :

text
Copier le code
Si Host(Current) == Host(New)  -> OK
Sinon
  Si CNAME(Current) == CNAME(New) -> OK
  Sinon
     Si SCAN(Current) == SCAN(New) -> VALIDE
     Sinon -> DIFFERENT
Comparaison Current vs NewDR
Même logique sur ScanCompareDR, uniquement si NewJdbcDR est renseigné.

📈 Progression (AnalyseV2)
AnalyseV2 affiche une jauge :

text
Copier le code
Progress: [Id: 120/200 | NEW_SCAN     ] .......................... 60%
largeur fixe du bloc entre [] pour éviter les “sauts”

la progression est basée sur id / total (id réel)

🔷 Diagramme logique de flux (CSV → AnalyseV2 → JSON → ReportV2)
1) Flux global
text
Copier le code
CSV Source
   │
   ▼
AnalyseV2.py
   │
   ▼
connexions_store_v2.json
   │
   ▼
ReportV2.py
Le JSON est le contrat entre AnalyseV2 et ReportV2.

2) Flux interne AnalyseV2
text
Copier le code
[Start]
   │
   ▼
Parse arguments
   │
   ├─ columns
   │
   ├─ id=N / ligne=N|ALL
   │
   ▼
Load CSV → rows
   │
   ▼
Load JSON store
   │
   ▼
Build index by id
   │
   ▼
FOR each selected id
   │
   ├─ exists in JSON ?
   │      │
   │      ├─ yes → RAW changed ?
   │      │        │
   │      │        ├─ no + no force → reuse cache (skip DNS/SCAN)
   │      │        │
   │      │        └─ yes / force → recompute full
   │      │
   │      └─ no → full compute
   │
   ▼
PARSE JDBC strings (Current/New/DR)
   │
   ▼
Syntax validation
   │
   ▼
Identity resolution (if needed)
   │
   ├─ Host (from parsed JDBC)
   ├─ CNAME (nslookup)
   ├─ SCAN (nslookup if scan, else ssh srvctl)
   │
   ▼
Compare Current/New + Current/DR
   │
   ▼
Build Status object
   │
   ▼
Store JSON object
   │
   ▼
Progress display
   │
   ▼
[End loop]
   │
   ▼
Save JSON
   │
   ▼
[End]
3) Flux interne ReportV2
text
Copier le code
Load JSON
   │
   ▼
- help ?
   │
   ├─ yes → print help, exit
   │
   ▼
- summary ?
   │
   ├─ yes → apply optional filter → print summary table → exit
   │
   ▼
id=N ?
   │
   ├─ yes → show_object
   │        ├─ Metadata
   │        ├─ Current JDBC (parsed + identities)
   │        ├─ New JDBC (parsed + identities)
   │        ├─ New JDBC DR (parsed + identities)
   │        ├─ Names
   │        ├─ Status
   │        ├─ Debug: RawSource + Error details
   │
   ▼
No option → default summary
🧩 Découpage recommandé (pour maintenance)
Les scripts devenant longs, l’objectif est de pouvoir modifier une seule méthode + ses appels sans toucher au reste.

Proposition de modularisation
text
Copier le code
.
├── AnalyseV2.py           # main (arguments + boucle + appels)
├── ReportV2.py            # main (arguments + affichage + filtres)
└── lib/
    ├── jdbc_parser.py     # parse JDBC + clean + extract DR hosts
    ├── dns_tools.py       # nslookup : cname / fqdn
    ├── scan_tools.py      # srvctl + normalize scan
    ├── logic_compare.py   # logique métier compare current/new/dr
    ├── progress.py        # show_progress stable
    ├── json_store.py      # load/save/index JSON
    └── common.py          # unicode helpers + debug_print
Bénéfices
Corrections ciblées (ex: progress.py uniquement)

Réduction des régressions

Réutilisation Analyse ↔ Report (formatting commun)

Lecture et test plus faciles

🚀 Création d’un repo GitHub dédié
1) Créer le repo sur GitHub
GitHub → New repository

Nom (ex) : jdbc-oracle-analysis

Private/Public selon ton besoin

Ne pas générer README automatiquement (tu ajoutes celui-ci)

2) Initialiser en local et pousser
Exemple PowerShell :

powershell
Copier le code
mkdir jdbc-oracle-analysis
cd jdbc-oracle-analysis
git init

# copier tes fichiers
copy ..\AnalyseV2.py .
copy ..\ReportV2.py .
copy ..\README.md .

git add .
git commit -m "Initial commit - JDBC analysis/report"
git branch -M main
git remote add origin https://github.com/<TON_USER>/jdbc-oracle-analysis.git
git push -u origin main
GitHub n’accepte plus les mots de passe : utiliser un token (PAT) comme mot de passe.

👤 Auteur
Abderrahim LAROUSSI

📝 Licence
Usage interne / professionnel / pédagogique.

Copier le code

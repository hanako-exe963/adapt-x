# ADAPT-X — Autonomous Attacker Digital Profiling & Threat Prediction Engine

**ADAPT-X** est un moteur d'analyse défensive (blue team / threat intelligence) qui transforme des logs bruts d'attaquants (honeypot, IDS) en :

1. **Profils comportementaux** (archétypes d'attaquants)
2. **Position sur la Cyber Kill Chain / MITRE ATT&CK**
3. **Prédiction de la prochaine étape probable** de l'attaque
4. **Score de risque composite** (0–100) pour la priorisation SOC

> ⚠️ **Portée du projet** : ADAPT-X est un outil d'**analyse défensive**. Il ingère et classe des logs déjà collectés par un honeypot/IDS — il ne scanne, n'exploite, ni n'attaque aucune cible. Les données de démonstration sont **entièrement synthétiques**.

---

## Architecture

```
┌─────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
│   Ingestion      │──▶│ Feature           │──▶│ Profiling (KMeans)    │
│ (synthetic /     │   │ Engineering       │   │ → archétype           │
│  Cowrie JSONL)   │   │ (tempo, entropie, │   │  (Bot / Script Kiddie │
│                  │   │  succès, stages)  │   │   / Skilled Operator) │
└─────────────────┘   └──────────────────┘   └──────────┬────────────┘
                                                          │
                       ┌──────────────────┐               ▼
                       │ Kill-Chain Tagging│   ┌──────────────────────┐
                       │ (règles + MITRE   │──▶│  Risk Scoring         │
                       │  ATT&CK mapping)  │   │  (score composite)    │
                       └────────┬─────────┘   └──────────┬────────────┘
                                │                          │
                                ▼                          ▼
                       ┌──────────────────┐      ┌──────────────────┐
                       │ Markov Predictor  │      │ Dashboard Flask   │
                       │ (prochaine étape) │─────▶│ (table + charts)  │
                       └──────────────────┘      └──────────────────┘
```

### Modules

| Fichier | Rôle |
|---|---|
| `adaptx/data_generator.py` | Génère des sessions d'attaquants synthétiques réalistes (3 archétypes) |
| `adaptx/ingestion.py` | Charge les données synthétiques ou des logs Cowrie honeypot réels (JSONL) |
| `adaptx/killchain.py` | Classifie chaque commande observée en étape Kill Chain / tactique MITRE ATT&CK ; chaîne de Markov pour prédire la prochaine étape |
| `adaptx/features.py` | Extrait l'empreinte comportementale par IP (tempo, entropie, diversité, succès) |
| `adaptx/profiling.py` | Clustering KMeans → archétype d'attaquant explicable |
| `adaptx/risk.py` | Score de risque composite pondéré et transparent |
| `adaptx/pipeline.py` | Orchestration complète + CLI |
| `dashboard/app.py` | Dashboard Flask interactif |
| `tests/test_pipeline.py` | Suite de tests unitaires (pytest) |

---

## Installation

```bash
cd ADAPT-X
python3 -m venv venv && source venv/bin/activate   # optionnel
pip install -r requirements.txt
```

## Utilisation — CLI

```bash
# Pipeline complet sur données synthétiques (150 sessions par défaut)
python3 -m adaptx.pipeline --n-sessions 200 --clusters 3 --out outputs

# Sur un vrai log Cowrie (honeypot SSH/Telnet)
python3 -m adaptx.pipeline --source /chemin/vers/cowrie.jsonl
```

Cela produit :
- `outputs/adaptx_report.csv`
- `outputs/adaptx_report.json`
- Un résumé des attaquants les plus critiques imprimé dans le terminal

## Utilisation — Dashboard

```bash
python3 dashboard/app.py
# puis ouvrir http://127.0.0.1:5000
```

Le dashboard affiche :
- Répartition des archétypes (camembert)
- Répartition des niveaux de risque
- Répartition par étape actuelle de la kill chain
- Tableau triable de tous les attaquants profilés avec leur score, niveau de risque et prochaine étape prédite

## Tests

```bash
pytest tests/ -v
```

---

## Détails méthodologiques

### 1. Archétypes comportementaux
Trois profils simulés (et retrouvés par le clustering, sans supervision) :
- **Automated Bot** : tempo très rapide, commandes répétitives, faible diversité
- **Script Kiddie** : reconnaissance bruyante + tentatives d'exploit "canned"
- **Skilled Operator** : tempo lent et délibéré, diversité de commandes élevée, tente la persistance et l'exfiltration (profil type APT)

### 2. Cyber Kill Chain / MITRE ATT&CK
Chaque commande est taguée par un classifieur à base de règles vers une étape :
`recon → delivery → exploitation → installation → c2 → actions_on_objective`,
avec une correspondance MITRE ATT&CK (TA0043, TA0001, TA0002, TA0003, TA0011, TA0010/TA0040).

### 3. Prédiction de la prochaine étape
Une **chaîne de Markov d'ordre 1** est entraînée sur l'ensemble des séquences d'étapes observées, produisant une matrice de transition `P(étape suivante | étape actuelle)`. C'est un choix volontairement **explicable** (vs. un LSTM boîte noire), adapté à un contexte SOC où l'analyste doit pouvoir justifier une alerte.

### 4. Score de risque
Somme pondérée transparente :
```
risk = 0.40 × progression_kill_chain
     + 0.25 × sévérité_archétype
     + 0.15 × diversité_tactiques
     + 0.10 × persistance (sessions répétées)
     + 0.10 × taux_de_succès_des_commandes
```

---

## Extensions possibles (roadmap)

- Remplacer le classifieur de commandes par un modèle NLP fine-tuné (BERT léger) pour capturer les variantes obfusquées
- Ajouter un modèle séquentiel (LSTM/Transformer) en complément de la chaîne de Markov pour capturer les dépendances d'ordre supérieur
- Enrichissement GeoIP / ASN / réputation d'IP (threat intel feeds)
- Ingestion temps réel via Kafka/Redis pour un déploiement SOC en production
- Export STIX/TAXII pour l'interopérabilité avec d'autres plateformes de threat intel

---

## Avertissement éthique

Ce projet est destiné à des fins **défensives, éducatives et de portfolio en cybersécurité**. Il ne doit être utilisé que sur des logs collectés légalement (honeypots que vous opérez, environnements de test, données synthétiques). ADAPT-X ne contient aucun code d'exploitation, de scan actif ou d'attaque.

# 📧 Agent d'Analyse d'Emails AI

Agent AI complet pour l'analyse approfondie d'emails utilisant Google ADK (Agent Development Kit). Cet agent utilise la méthode ReAct pour orchestrer une investigation complète incluant l'analyse des headers, liens, pièces jointes, images (y compris QR codes), et contenu textuel.

## 🚀 Fonctionnalités

### 🔍 Analyse Complète
- **Headers d'emails** : Extraction et analyse des en-têtes techniques (SPF, DKIM, DMARC)
- **Liens** : Détection et analyse des liens suspects, redirections, domaines malveillants
- **Pièces jointes** : Analyse des types de fichiers, tailles, extensions suspectes
- **Images et QR codes** : Détection et décodage des QR codes avec analyse du contenu
- **Contenu textuel** : Analyse sémantique, détection de phishing, ingénierie sociale

### 🤖 Architecture Multi-Agents
- **Agent Orchestrateur** : Coordonne l'investigation avec méthode ReAct
- **Agent d'Analyse de Contenu** : Spécialisé dans l'analyse textuelle et sémantique
- **Agent de Génération de Rapports** : Création de rapports structurés
- **Workflow Séquentiel** : Orchestration automatique des analyses

### 📊 Génération de Rapports
- **Formats multiples** : JSON, HTML, PDF
- **Évaluation de risque** : Score de sécurité avec recommandations
- **Rapports détaillés** : Analyse technique complète
- **Interface française** : Tous les rapports en français

## 🛠️ Installation

### Prérequis
- Python 3.9+
- Google Cloud CLI
- Compte Google Cloud avec facturation activée

### 1. Cloner le projet
```bash
git clone <repository-url>
cd email-analyzer-agent
```

### 2. Créer un environnement virtuel
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

### 3. Installer les dépendances
```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Configuration Google Cloud
```bash
# Authentification
gcloud auth application-default login

# Configurer le projet
export GOOGLE_GENAI_USE_VERTEXAI=true
export GOOGLE_CLOUD_PROJECT=your-project-id
export GOOGLE_CLOUD_LOCATION=us-central1
```

### 5. Configuration des variables d'environnement
Copiez le fichier `env_template.txt` vers `.env` et configurez vos variables :

```bash
cp env_template.txt .env
```

Éditez le fichier `.env` avec vos valeurs :
```env
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_API_KEY=your_api_key_here
GOOGLE_CLOUD_PROJECT=your_project_id
GOOGLE_CLOUD_LOCATION=us-central1
```

## 🎯 Utilisation

### Interface Web (Recommandée)
```bash
adk web
```

Ouvrez l'URL affichée dans votre navigateur, sélectionnez "email_analyzer" et commencez l'analyse.

### Interface Terminal
```bash
adk run .
```

### Exemple d'utilisation

1. **Démarrer l'agent** :
```
📧 Bonjour ! Je suis votre Agent d'Analyse d'Emails.
Veuillez coller le contenu complet de l'email à analyser (headers inclus).
```

2. **Fournir l'email** :
```
Return-Path: <sender@example.com>
Received: from mail.example.com...
From: sender@example.com
To: recipient@company.com
Subject: Action urgente requise
...
[Contenu complet de l'email]
```

3. **Recevoir l'analyse** :
```
🔍 ANALYSE COMPLÈTE TERMINÉE

📊 RÉSUMÉ EXÉCUTIF
Niveau de risque : ÉLEVÉ ⚠️
Principales menaces : Phishing, Liens suspects, QR code malveillant

📋 DÉTAILS DE L'ANALYSE
...
```

## 🔧 Architecture Technique

### Structure du Projet
```
email-analyzer-agent/
├── email_analyzer/
│   ├── __init__.py
│   ├── agent.py          # Agent principal et orchestrateur
│   ├── tools.py          # Outils d'analyse (headers, liens, QR codes)
│   └── prompts.py        # Instructions pour les agents
├── requirements.txt      # Dépendances Python
├── pyproject.toml       # Configuration du package
├── env_template.txt     # Template des variables d'environnement
└── README.md           # Documentation
```

### Agents Spécialisés

#### 1. Agent d'Investigation (ReAct)
- **Rôle** : Orchestrateur principal utilisant la méthode ReAct
- **Outils** : Tous les outils d'analyse + Google Search
- **Processus** : 6 étapes d'investigation séquentielles

#### 2. Agent d'Analyse de Contenu
- **Rôle** : Analyse textuelle et sémantique approfondie
- **Spécialités** : Détection de phishing, ingénierie sociale
- **Outils** : Extracteur de contenu, analyseur de sécurité

#### 3. Agent de Génération de Rapports
- **Rôle** : Création de rapports structurés
- **Formats** : JSON, HTML, PDF
- **Langue** : Français professionnel

### Outils d'Analyse

#### 🔍 Analyse des Headers
```python
parse_email_headers(email_content)
```
- Extraction des en-têtes techniques
- Vérification SPF, DKIM, DMARC
- Analyse du routage

#### 🔗 Analyse des Liens
```python
extract_links_from_email(email_content)
```
- Détection des liens HTML et texte
- Analyse des domaines suspects
- Vérification des redirections

#### 📎 Analyse des Pièces Jointes
```python
extract_attachments_info(email_content)
```
- Types de fichiers et tailles
- Détection d'extensions suspectes
- Analyse des signatures

#### 📱 Détection des QR Codes
```python
detect_qr_codes_in_images(email_content)
```
- Scan des images embarquées
- Décodage des QR codes
- Analyse du contenu décodé

#### 🛡️ Analyse de Sécurité
```python
analyze_email_security(email_content)
```
- Score de risque global
- Recommandations de sécurité
- Détection de patterns malveillants

## 📊 Exemples de Rapports

### Rapport JSON
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "analysis_version": "1.0",
  "email_analysis": {
    "headers": {...},
    "links": [...],
    "attachments": [...],
    "qr_codes": [...],
    "security_analysis": {
      "risk_score": 8,
      "risk_level": "high",
      "indicators": [...]
    }
  }
}
```

### Rapport HTML
Interface web complète avec :
- Résumé exécutif coloré
- Sections détaillées
- Recommandations actionables
- Visualisations des risques

## 🚀 Déploiement

### Cloud Run
```bash
adk deploy cloud_run \
  --project=$GOOGLE_CLOUD_PROJECT \
  --region=$GOOGLE_CLOUD_LOCATION \
  --service_name=email-analyzer \
  --with_ui \
  ./email_analyzer
```

### Configuration de Production
1. **Sécurité** : Configurez les IAM roles appropriés
2. **Monitoring** : Activez Cloud Monitoring
3. **Logs** : Configurez Cloud Logging
4. **Scaling** : Ajustez les paramètres de scaling

## 🔒 Sécurité et Confidentialité

### Mesures de Sécurité
- **Isolation** : Analyse en environnement isolé
- **Chiffrement** : Tous les échanges chiffrés
- **Audit** : Logging complet des analyses
- **Quarantaine** : Isolation des contenus suspects

### Confidentialité
- **Données temporaires** : Aucune persistance par défaut
- **Anonymisation** : Possibilité d'anonymiser les données
- **Conformité** : Respect des réglementations RGPD

## 🔧 Personnalisation

### Ajouter des Outils Personnalisés
```python
from google.adk.tools import FunctionTool

def custom_analysis_tool(email_content: str) -> dict:
    # Votre logique d'analyse
    return {"result": "analysis"}

custom_tool = FunctionTool(
    name="custom_analysis",
    description="Outil d'analyse personnalisé",
    function=custom_analysis_tool
)
```

### Modifier les Prompts
Éditez `email_analyzer/prompts.py` pour personnaliser :
- Instructions des agents
- Formats de rapport
- Critères d'analyse

## 🐛 Débogage

### Interface de Débogage
```bash
adk web
```
Utilisez l'onglet "Events" pour voir :
- Étapes d'exécution
- Appels d'outils
- Raisonnement de l'agent

### Logs Détaillés
```bash
export GOOGLE_CLOUD_LOGGING_ENABLED=true
adk run .
```

## 📈 Métriques et Monitoring

### Métriques Clés
- **Temps d'analyse** : Durée moyenne par email
- **Taux de détection** : Précision des alertes
- **Utilisation des ressources** : CPU, mémoire
- **Satisfaction utilisateur** : Feedback sur les rapports

### Monitoring
- **Cloud Monitoring** : Métriques système
- **Custom Metrics** : Métriques métier
- **Alertes** : Notifications en cas d'anomalie

## 🤝 Contribution

### Développement
1. Fork le projet
2. Créez une branche feature
3. Implémentez vos modifications
4. Ajoutez des tests
5. Soumettez une Pull Request

### Standards de Code
- **PEP 8** : Style de code Python
- **Type Hints** : Annotations de type
- **Documentation** : Docstrings complètes
- **Tests** : Couverture de code

## 📚 Documentation Avancée

### Guides Spécialisés
- [Guide de Déploiement](docs/deployment.md)
- [API Reference](docs/api.md)
- [Exemples d'Usage](docs/examples.md)
- [Troubleshooting](docs/troubleshooting.md)

### Ressources Externes
- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [Vertex AI Documentation](https://cloud.google.com/vertex-ai/docs)
- [Gemini API Reference](https://ai.google.dev/docs)

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🆘 Support

### Communauté
- **Issues GitHub** : Rapports de bugs et demandes de fonctionnalités
- **Discussions** : Questions et partage d'expériences
- **Wiki** : Documentation communautaire

### Support Commercial
Pour un support commercial ou des fonctionnalités entreprise, contactez l'équipe de développement.

---

**Développé avec ❤️ en utilisant Google ADK**

*Agent d'Analyse d'Emails AI - Votre partenaire de confiance pour la sécurité email* 
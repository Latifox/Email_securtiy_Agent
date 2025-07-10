#!/bin/bash

# 🚀 Script de Déploiement - Agent d'Analyse d'Emails
# Automatise l'installation, la configuration et le déploiement

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration par défaut
DEFAULT_PROJECT_ID=""
DEFAULT_REGION="us-central1"
DEFAULT_SERVICE_NAME="email-analyzer"

echo -e "${BLUE}🚀 Déploiement Agent d'Analyse d'Emails${NC}"
echo -e "${BLUE}======================================${NC}"

# Fonction d'affichage
print_step() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Vérification des prérequis
check_prerequisites() {
    print_step "Vérification des prérequis..."
    
    # Vérifier Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 n'est pas installé"
        exit 1
    fi
    
    # Vérifier gcloud
    if ! command -v gcloud &> /dev/null; then
        print_error "Google Cloud CLI n'est pas installé"
        echo "Installez gcloud: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
    
    # Vérifier l'authentification
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        print_error "Vous n'êtes pas authentifié avec gcloud"
        echo "Exécutez: gcloud auth login"
        exit 1
    fi
    
    print_step "Prérequis vérifiés"
}

# Configuration du projet
configure_project() {
    print_step "Configuration du projet Google Cloud..."
    
    # Demander le project ID si non défini
    if [ -z "$GOOGLE_CLOUD_PROJECT" ]; then
        echo -n "Entrez votre Project ID Google Cloud: "
        read -r GOOGLE_CLOUD_PROJECT
        export GOOGLE_CLOUD_PROJECT
    fi
    
    # Demander la région si non définie
    if [ -z "$GOOGLE_CLOUD_LOCATION" ]; then
        echo -n "Entrez la région (défaut: $DEFAULT_REGION): "
        read -r GOOGLE_CLOUD_LOCATION
        GOOGLE_CLOUD_LOCATION=${GOOGLE_CLOUD_LOCATION:-$DEFAULT_REGION}
        export GOOGLE_CLOUD_LOCATION
    fi
    
    # Configurer gcloud
    gcloud config set project "$GOOGLE_CLOUD_PROJECT"
    gcloud config set compute/region "$GOOGLE_CLOUD_LOCATION"
    
    print_step "Projet configuré: $GOOGLE_CLOUD_PROJECT"
}

# Activation des APIs
enable_apis() {
    print_step "Activation des APIs Google Cloud..."
    
    apis=(
        "aiplatform.googleapis.com"
        "run.googleapis.com"
        "cloudbuild.googleapis.com"
        "artifactregistry.googleapis.com"
    )
    
    for api in "${apis[@]}"; do
        echo "Activation de $api..."
        gcloud services enable "$api" --quiet
    done
    
    print_step "APIs activées"
}

# Installation des dépendances
install_dependencies() {
    print_step "Installation des dépendances..."
    
    # Créer l'environnement virtuel s'il n'existe pas
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    # Activer l'environnement virtuel
    source venv/bin/activate
    
    # Installer les dépendances
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install -e .
    
    print_step "Dépendances installées"
}

# Configuration des variables d'environnement
setup_environment() {
    print_step "Configuration des variables d'environnement..."
    
    # Créer le fichier .env s'il n'existe pas
    if [ ! -f ".env" ]; then
        cp env_template.txt .env
        print_warning "Fichier .env créé à partir du template"
        print_warning "Veuillez éditer .env avec vos valeurs avant de continuer"
        
        # Remplacer les valeurs par défaut
        sed -i.bak "s/your_project_id/$GOOGLE_CLOUD_PROJECT/g" .env
        sed -i.bak "s/us-central1/$GOOGLE_CLOUD_LOCATION/g" .env
        rm .env.bak
    fi
    
    # Exporter les variables
    export GOOGLE_GENAI_USE_VERTEXAI=true
    export GOOGLE_CLOUD_REGION="$GOOGLE_CLOUD_LOCATION"
    
    print_step "Variables d'environnement configurées"
}

# Test local
test_local() {
    print_step "Test local de l'agent..."
    
    source venv/bin/activate
    
    # Test rapide
    echo "Test de l'installation..."
    python -c "
import email_analyzer
from email_analyzer import tools, prompts, agent
print('✅ Import réussi')
print('✅ Outils disponibles:', len(tools.ALL_TOOLS))
print('✅ Agent configuré')
"
    
    print_step "Test local réussi"
}

# Déploiement sur Cloud Run
deploy_cloud_run() {
    print_step "Déploiement sur Cloud Run..."
    
    source venv/bin/activate
    
    # Nom du service
    SERVICE_NAME=${SERVICE_NAME:-$DEFAULT_SERVICE_NAME}
    
    # Déploiement avec ADK
    adk deploy cloud_run \
        --project="$GOOGLE_CLOUD_PROJECT" \
        --region="$GOOGLE_CLOUD_LOCATION" \
        --service_name="$SERVICE_NAME" \
        --app_name="email-analyzer-app" \
        --with_ui \
        ./email_analyzer
    
    # Obtenir l'URL du service
    SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
        --region="$GOOGLE_CLOUD_LOCATION" \
        --format="value(status.url)")
    
    print_step "Déploiement réussi!"
    echo -e "${GREEN}🌐 URL du service: $SERVICE_URL${NC}"
}

# Configuration des permissions
setup_permissions() {
    print_step "Configuration des permissions..."
    
    # Permettre l'accès public (pour démo)
    gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
        --region="$GOOGLE_CLOUD_LOCATION" \
        --member="allUsers" \
        --role="roles/run.invoker" \
        --quiet
    
    print_step "Permissions configurées"
}

# Nettoyage
cleanup() {
    print_step "Nettoyage..."
    
    # Supprimer les fichiers temporaires
    find . -name "*.pyc" -delete
    find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    
    print_step "Nettoyage terminé"
}

# Affichage des informations finales
show_final_info() {
    echo -e "${GREEN}🎉 Déploiement terminé avec succès!${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo -e "${YELLOW}Informations du déploiement:${NC}"
    echo -e "  📦 Projet: $GOOGLE_CLOUD_PROJECT"
    echo -e "  🌍 Région: $GOOGLE_CLOUD_LOCATION"
    echo -e "  🚀 Service: $SERVICE_NAME"
    echo -e "  🌐 URL: $SERVICE_URL"
    echo ""
    echo -e "${YELLOW}Commandes utiles:${NC}"
    echo -e "  📊 Logs: gcloud run services logs tail $SERVICE_NAME --region=$GOOGLE_CLOUD_LOCATION"
    echo -e "  🔧 Redéployer: $0 --deploy-only"
    echo -e "  🧪 Test local: adk web"
    echo ""
    echo -e "${GREEN}✅ Votre agent d'analyse d'emails est maintenant opérationnel!${NC}"
}

# Fonction principale
main() {
    case "${1:-}" in
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --help, -h          Afficher cette aide"
            echo "  --check-only        Vérifier les prérequis uniquement"
            echo "  --install-only      Installer les dépendances uniquement"
            echo "  --deploy-only       Déployer uniquement (sans installation)"
            echo "  --test-only         Tester localement uniquement"
            exit 0
            ;;
        --check-only)
            check_prerequisites
            exit 0
            ;;
        --install-only)
            check_prerequisites
            install_dependencies
            setup_environment
            exit 0
            ;;
        --deploy-only)
            configure_project
            enable_apis
            deploy_cloud_run
            setup_permissions
            show_final_info
            exit 0
            ;;
        --test-only)
            test_local
            exit 0
            ;;
        *)
            # Déploiement complet
            check_prerequisites
            configure_project
            enable_apis
            install_dependencies
            setup_environment
            test_local
            deploy_cloud_run
            setup_permissions
            cleanup
            show_final_info
            ;;
    esac
}

# Gestion des erreurs
trap 'print_error "Erreur lors du déploiement à la ligne $LINENO"' ERR

# Exécution
main "$@" 
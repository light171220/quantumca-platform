#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

generate_secret() {
    openssl rand -base64 48 | tr -d '\n'
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    if [ ! -f "$PROJECT_ROOT/deployment/docker/docker-compose.yml" ]; then
        log_error "Docker compose file not found at deployment/docker/docker-compose.yml"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

create_env_file() {
    local env_file="$PROJECT_ROOT/.env"
    
    if [ -f "$env_file" ]; then
        log_info "Environment file exists. Reading existing configuration..."
        source "$env_file"
    else
        log_info "Creating new environment file..."
    fi
    
    if [ -z "$JWT_SECRET" ]; then
        JWT_SECRET=$(generate_secret)
        log_info "Generated new JWT secret"
    fi
    
    if [ -z "$ROOT_CA_PASSPHRASE" ]; then
        ROOT_CA_PASSPHRASE=$(generate_secret)
        log_info "Generated new Root CA passphrase"
    fi
    
    if [ -z "$INTERMEDIATE_CA_PASSPHRASE" ]; then
        INTERMEDIATE_CA_PASSPHRASE=$(generate_secret)
        log_info "Generated new Intermediate CA passphrase"
    fi
    
    if [ -z "$BACKUP_ENCRYPTION_PASSWORD" ]; then
        BACKUP_ENCRYPTION_PASSWORD=$(generate_secret)
        log_info "Generated new backup encryption password"
    fi
    
    cat > "$env_file" << EOF
JWT_SECRET=$JWT_SECRET
ROOT_CA_PASSPHRASE=$ROOT_CA_PASSPHRASE
INTERMEDIATE_CA_PASSPHRASE=$INTERMEDIATE_CA_PASSPHRASE
BACKUP_ENCRYPTION_PASSWORD=$BACKUP_ENCRYPTION_PASSWORD

ENVIRONMENT=development
LOG_LEVEL=info

DATABASE_PATH=/app/data/quantumca.db

KEY_ENCRYPTION_ENABLED=true
DOMAIN_VALIDATION_REQUIRED=true
CERTIFICATE_CHAIN_VALIDATION=true
TLS_ENABLED=false
FIPS_MODE=false
COMPLIANCE_MODE=false

ENABLE_MULTI_PQC=true
MIN_SECURITY_LEVEL=128

CERTIFICATE_VALIDITY_DAYS=365
INTERMEDIATE_CA_VALIDITY_DAYS=1825
ROOT_CA_VALIDITY_DAYS=7300

API_RATE_LIMIT=100
API_RATE_BURST=50

BACKUP_ENABLED=true
BACKUP_INTERVAL=24h
BACKUP_RETENTION_DAYS=30

METRICS_ENABLED=true
HEALTH_CHECK_INTERVAL=30s
EOF
    
    chmod 600 "$env_file"
    log_success "Environment file created/updated: $env_file"
}

create_directories() {
    log_info "Creating necessary directories..."
    
    local dirs=("ssl" "shared-data")
    
    for dir in "${dirs[@]}"; do
        local dir_path="$PROJECT_ROOT/$dir"
        if [ ! -d "$dir_path" ]; then
            mkdir -p "$dir_path"
            log_info "Created directory: $dir_path"
        fi
    done
    
    if [ ! -d "$PROJECT_ROOT/backend/data/keys" ]; then
        mkdir -p "$PROJECT_ROOT/backend/data/keys"
        chmod 700 "$PROJECT_ROOT/backend/data/keys"
        log_info "Created backend keys directory"
    fi
    
    log_success "Directories created successfully"
}

generate_dev_ssl() {
    local ssl_dir="$PROJECT_ROOT/ssl"
    local cert_file="$ssl_dir/quantumca.crt"
    local key_file="$ssl_dir/quantumca.key"
    
    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
        log_info "Generating self-signed SSL certificates for development..."
        
        openssl req -x509 -newkey rsa:4096 -keyout "$key_file" -out "$cert_file" \
            -days 365 -nodes -subj "/C=US/ST=CA/L=San Francisco/O=QuantumCA/CN=localhost" \
            2>/dev/null
        
        log_success "SSL certificates generated"
    else
        log_info "SSL certificates already exist"
    fi
}

start_services() {
    log_info "Building and starting QuantumCA Platform services..."
    
    # Copy .env file to deployment directory for docker-compose
    if [ -f "$PROJECT_ROOT/.env" ]; then
        cp "$PROJECT_ROOT/.env" "$PROJECT_ROOT/deployment/docker/.env"
        log_info "Environment file copied to deployment directory"
    fi
    
    cd "$PROJECT_ROOT/deployment/docker"
    
    if command -v docker-compose &> /dev/null; then
        docker-compose build --no-cache
    else
        docker compose build --no-cache
    fi
    
    log_info "Starting services..."
    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi
    
    log_success "Services started successfully"
}

wait_for_services() {
    log_info "Waiting for services to become healthy..."
    
    local max_attempts=60
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:8080/health >/dev/null 2>&1; then
            log_success "Backend service is healthy"
            break
        fi
        
        log_info "Attempt $attempt/$max_attempts - waiting for backend service..."
        sleep 5
        ((attempt++))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        log_error "Backend service failed to become healthy"
        return 1
    fi
    
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:3000 >/dev/null 2>&1; then
            log_success "Frontend service is healthy"
            break
        fi
        
        log_info "Attempt $attempt/$max_attempts - waiting for frontend service..."
        sleep 5
        ((attempt++))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        log_error "Frontend service failed to become healthy"
        return 1
    fi
}

display_status() {
    log_success "🎉 QuantumCA Platform is now running!"
    echo
    echo "📊 Service Status:"
    echo "  • API Server:      http://localhost:8080"
    echo "  • OCSP Responder:  http://localhost:8081"
    echo "  • Metrics:         http://localhost:9090/metrics"
    echo "  • Web Interface:   http://localhost:3000"
    echo "  • Health Check:    http://localhost:8080/health"
    echo
    echo "🔐 Security Information:"
    echo "  • All keys are encrypted at rest"
    echo "  • Domain validation is enabled"
    echo "  • Certificate chain validation is enabled"
    echo "  • Multi-PQC (Post-Quantum Cryptography) is enabled"
    echo
    echo "📋 Management Commands:"
    echo "  • View logs:       cd deployment/docker && docker-compose logs -f"
    echo "  • Stop services:   cd deployment/docker && docker-compose down"
    echo "  • Restart:         cd deployment/docker && docker-compose restart"
    echo "  • Update:          cd deployment/docker && docker-compose pull && docker-compose up -d"
    echo
    echo "🔧 Configuration:"
    echo "  • Environment file: $PROJECT_ROOT/.env"
    echo "  • Backend data:     $PROJECT_ROOT/backend/data"
    echo "  • SSL certificates: $PROJECT_ROOT/ssl"
    echo
    echo "⚠️  Important Security Notes:"
    echo "  • Keep your .env file secure and backed up"
    echo "  • Regular backup your keys directory"
    echo "  • Monitor certificate expiration dates"
    echo "  • Review audit logs regularly"
    echo
    log_warning "For production deployment, ensure you:"
    log_warning "1. Enable TLS with proper certificates"
    log_warning "2. Use a reverse proxy (nginx/traefik)"
    log_warning "3. Set up proper firewall rules"
    log_warning "4. Configure log rotation"
    log_warning "5. Set up monitoring and alerting"
}

cleanup() {
    if [ $? -ne 0 ]; then
        log_error "Setup failed. Check the logs for more information."
        echo "Logs can be viewed with: cd deployment/docker && docker-compose logs"
    fi
}

main() {
    trap cleanup EXIT
    
    echo "🚀 QuantumCA Platform Production Setup"
    echo "======================================="
    echo
    
    check_prerequisites
    create_env_file
    create_directories
    generate_dev_ssl
    start_services
    wait_for_services
    display_status
    
    echo
    log_success "Setup completed successfully! 🎉"
}

main "$@"
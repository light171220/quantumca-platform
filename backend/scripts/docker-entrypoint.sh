#!/bin/sh

# Docker entrypoint script for QuantumCA Platform
set -e

echo "🚀 Starting QuantumCA Platform Docker Container..."

# Set default environment variables if not provided
export DATABASE_PATH=${DATABASE_PATH:-"/app/data/quantumca.db"}
export KEYS_PATH=${KEYS_PATH:-"/app/keys"}
export CERTIFICATES_PATH=${CERTIFICATES_PATH:-"/app/data/certificates"}
export BACKUP_PATH=${BACKUP_PATH:-"/app/backups"}
export LOGS_PATH=${LOGS_PATH:-"/app/logs"}
export LOG_LEVEL=${LOG_LEVEL:-"info"}
export API_PORT=${API_PORT:-"8080"}
export OCSP_PORT=${OCSP_PORT:-"8081"}
export METRICS_PORT=${METRICS_PORT:-"9090"}
export ENVIRONMENT=${ENVIRONMENT:-"production"}

# Generate secure secrets if not provided
if [ -z "$JWT_SECRET" ]; then
    echo "⚠️  Generating JWT secret (consider setting JWT_SECRET environment variable)"
    export JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
fi

if [ -z "$ROOT_CA_PASSPHRASE" ]; then
    echo "⚠️  Generating Root CA passphrase (consider setting ROOT_CA_PASSPHRASE environment variable)"
    export ROOT_CA_PASSPHRASE=$(openssl rand -base64 48 | tr -d '\n')
fi

if [ -z "$INTERMEDIATE_CA_PASSPHRASE" ]; then
    echo "⚠️  Generating Intermediate CA passphrase (consider setting INTERMEDIATE_CA_PASSPHRASE environment variable)"
    export INTERMEDIATE_CA_PASSPHRASE=$(openssl rand -base64 48 | tr -d '\n')
fi

if [ -z "$BACKUP_ENCRYPTION_PASSWORD" ]; then
    echo "⚠️  Generating backup encryption password (consider setting BACKUP_ENCRYPTION_PASSWORD environment variable)"
    export BACKUP_ENCRYPTION_PASSWORD=$(openssl rand -base64 48 | tr -d '\n')
fi

# Function to check if setup is needed
needs_setup() {
    # Check if database exists and has tables
    if [ ! -f "$DATABASE_PATH" ]; then
        return 0  # needs setup
    fi
    
    # Check if key store has any keys
    if [ ! -d "$KEYS_PATH" ] || [ -z "$(ls -A "$KEYS_PATH" 2>/dev/null)" ]; then
        return 0  # needs setup
    fi
    
    # Check if at least one key file exists
    if ! ls "$KEYS_PATH"/*.encrypted >/dev/null 2>&1; then
        return 0  # needs setup
    fi
    
    return 1  # no setup needed
}

# Function to run setup
run_setup() {
    echo "🔧 Running initial setup..."
    
    # Set environment variables for setup
    export KEY_ENCRYPTION_ENABLED=true
    export DOMAIN_VALIDATION_REQUIRED=true
    export CERTIFICATE_CHAIN_VALIDATION=true
    export ENABLE_MULTI_PQC=true
    
    # Run setup binary
    if ! ./quantumca-setup; then
        echo "❌ Setup failed!"
        exit 1
    fi
    
    echo "✅ Setup completed successfully"
}

# Function to validate setup
validate_setup() {
    echo "🔍 Validating setup..."
    
    # Check if database exists
    if [ ! -f "$DATABASE_PATH" ]; then
        echo "❌ Database file not found: $DATABASE_PATH"
        return 1
    fi
    
    # Check if key directory exists and has files
    if [ ! -d "$KEYS_PATH" ] || [ -z "$(ls -A "$KEYS_PATH" 2>/dev/null)" ]; then
        echo "❌ Key directory not found or empty: $KEYS_PATH"
        return 1
    fi
    
    # Check for required key files
    if ! ls "$KEYS_PATH"/*.encrypted >/dev/null 2>&1; then
        echo "❌ No encrypted key files found in: $KEYS_PATH"
        return 1
    fi
    
    echo "✅ Setup validation passed"
    return 0
}

# Function to start the application
start_app() {
    echo "🌐 Starting QuantumCA Platform API Server..."
    
    # Export all necessary environment variables
    export TLS_ENABLED=${TLS_ENABLED:-"false"}
    export BACKUP_ENABLED=${BACKUP_ENABLED:-"true"}
    export METRICS_ENABLED=${METRICS_ENABLED:-"true"}
    export FIPS_MODE=${FIPS_MODE:-"false"}
    export COMPLIANCE_MODE=${COMPLIANCE_MODE:-"false"}
    
    # Start the API server
    exec ./quantumca-api
}

# Function to wait for dependencies
wait_for_dependencies() {
    echo "⏳ Waiting for dependencies..."
    # Add any dependency checks here if needed
    sleep 2
}

# Main execution flow
main() {
    echo "🔧 Initializing QuantumCA Platform..."
    echo "📂 Database Path: $DATABASE_PATH"
    echo "🔐 Keys Path: $KEYS_PATH"
    echo "📊 Environment: $ENVIRONMENT"
    
    # Wait for any dependencies
    wait_for_dependencies
    
    # Check if setup is needed
    if needs_setup; then
        echo "🆕 First-time setup detected"
        run_setup
    else
        echo "✅ Existing installation detected"
    fi
    
    # Validate setup
    if ! validate_setup; then
        echo "❌ Setup validation failed"
        exit 1
    fi
    
    # Start the application
    start_app
}

# Handle signals gracefully
trap 'echo "🛑 Received termination signal, shutting down..."; exit 0' TERM INT

# Run main function
main "$@"
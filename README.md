# Quantum-Safe Certificate Authority Platform

A complete quantum-resistant Certificate Authority platform built with Go, featuring post-quantum cryptography algorithms including Dilithium, Falcon, SPHINCS+, and Kyber.

## Features

- Post-quantum cryptography support (Dilithium, Falcon, SPHINCS+, Kyber)
- Three-tier service model (Direct certificates, Intermediate CA, Private Root CA)
- Domain validation via DNS TXT records and HTTP file validation
- OCSP responder for real-time certificate status
- Web interface for certificate management
- RESTful API for programmatic access
- SQLite database for simplicity
- Certificate lifecycle management (issue, renew, revoke)

## Quick Start

1. Clone the repository
2. Copy `.env.example` to `.env` and configure
3. Initialize the platform:
   ```bash
   go run cmd/setup/main.go
   ```
4. Start the API server:
   ```bash
   go run cmd/api/main.go
   ```
5. Access the web interface at `http://localhost:8080`

## API Endpoints

### Customers
- `POST /api/v1/customers` - Create customer
- `GET /api/v1/customers/{id}` - Get customer details

### Domains
- `POST /api/v1/domains` - Add domain for validation
- `POST /api/v1/domains/{id}/verify` - Verify domain ownership

### Certificates
- `POST /api/v1/certificates` - Request new certificate
- `GET /api/v1/certificates` - List customer certificates
- `GET /api/v1/certificates/{id}` - Get specific certificate
- `POST /api/v1/certificates/{id}/revoke` - Revoke certificate

### Intermediate CA
- `POST /api/v1/intermediate-ca` - Request intermediate CA
- `GET /api/v1/intermediate-ca/{id}` - Get intermediate CA details

### System
- `GET /ocsp` - OCSP responder endpoint
- `GET /health` - Health check

## Service Tiers

1. **Tier 1**: Direct certificate issuance for small businesses
2. **Tier 2**: Intermediate CA service for enterprises
3. **Tier 3**: Private root CA setup for government/critical infrastructure

## Security

This platform implements quantum-safe cryptography to protect against future quantum computer attacks. All certificates are signed using multiple post-quantum algorithms for maximum security.

## Configuration

Edit `configs/config.yaml` to customize the platform settings including certificate validity periods, supported algorithms, and validation methods.
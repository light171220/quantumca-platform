package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func NewSQLiteDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	pragmas := "?_foreign_keys=1&_journal_mode=WAL&_synchronous=NORMAL&_timeout=10000&_busy_timeout=10000&_cache_size=10000"
	db, err := sql.Open("sqlite3", path+pragmas)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`PRAGMA foreign_keys = ON`,
		
		`CREATE TABLE IF NOT EXISTS customers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			company_name TEXT NOT NULL CHECK(length(company_name) > 0),
			email TEXT NOT NULL UNIQUE CHECK(length(email) > 0 AND email LIKE '%@%'),
			api_key TEXT NOT NULL UNIQUE CHECK(length(api_key) >= 32),
			tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
		)`,
		
		`CREATE TABLE IF NOT EXISTS domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			domain_name TEXT NOT NULL CHECK(length(domain_name) > 0),
			validation_token TEXT NOT NULL CHECK(length(validation_token) > 0),
			is_verified BOOLEAN DEFAULT FALSE NOT NULL,
			verified_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
			UNIQUE(customer_id, domain_name)
		)`,
		
		`CREATE TABLE IF NOT EXISTS certificates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			serial_number TEXT NOT NULL UNIQUE CHECK(length(serial_number) > 0),
			common_name TEXT NOT NULL CHECK(length(common_name) > 0),
			subject_alt_names TEXT NOT NULL DEFAULT '[]',
			certificate_pem TEXT NOT NULL CHECK(length(certificate_pem) > 0),
			private_key_pem TEXT NOT NULL CHECK(length(private_key_pem) > 0),
			algorithms TEXT NOT NULL DEFAULT '[]',
			is_multi_pqc BOOLEAN DEFAULT FALSE NOT NULL,
			has_kem BOOLEAN DEFAULT FALSE NOT NULL,
			multi_pqc_certificates TEXT DEFAULT '[]',
			multi_pqc_private_keys TEXT DEFAULT '[]',
			kem_public_key_pem TEXT DEFAULT '',
			kem_private_key_pem TEXT DEFAULT '',
			fingerprint TEXT DEFAULT '',
			key_id TEXT DEFAULT '',
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			last_alert_sent DATETIME DEFAULT '1970-01-01 00:00:00' NOT NULL,
			revoked_at DATETIME,
			revocation_reason TEXT,
			FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
			CHECK(not_after > not_before),
			CHECK(revoked_at IS NULL OR status = 'revoked')
		)`,
		
		`CREATE TABLE IF NOT EXISTS intermediate_cas (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			common_name TEXT NOT NULL CHECK(length(common_name) > 0),
			serial_number TEXT NOT NULL UNIQUE CHECK(length(serial_number) > 0),
			certificate_pem TEXT NOT NULL CHECK(length(certificate_pem) > 0),
			private_key_pem TEXT NOT NULL CHECK(length(private_key_pem) > 0),
			algorithms TEXT NOT NULL DEFAULT '[]',
			is_multi_pqc BOOLEAN DEFAULT FALSE NOT NULL,
			has_kem BOOLEAN DEFAULT FALSE NOT NULL,
			multi_pqc_certificates TEXT DEFAULT '[]',
			multi_pqc_private_keys TEXT DEFAULT '[]',
			kem_public_key_pem TEXT DEFAULT '',
			kem_private_key_pem TEXT DEFAULT '',
			fingerprint TEXT DEFAULT '',
			key_id TEXT DEFAULT '',
			max_path_len INTEGER DEFAULT 0,
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
			CHECK(not_after > not_before)
		)`,
		
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT NOT NULL CHECK(length(user_id) > 0),
			customer_id INTEGER,
			action TEXT NOT NULL CHECK(length(action) > 0),
			resource TEXT NOT NULL CHECK(length(resource) > 0),
			resource_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			details TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL
		)`,
		
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			key_hash TEXT NOT NULL UNIQUE CHECK(length(key_hash) > 0),
			name TEXT NOT NULL CHECK(length(name) > 0),
			permissions TEXT NOT NULL DEFAULT '[]',
			last_used DATETIME,
			expires_at DATETIME,
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
			CHECK(expires_at IS NULL OR expires_at > created_at)
		)`,
		
		`CREATE TABLE IF NOT EXISTS certificate_templates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE CHECK(length(name) > 0),
			description TEXT,
			key_usages TEXT NOT NULL DEFAULT '[]',
			ext_key_usages TEXT DEFAULT '[]',
			validity_days INTEGER NOT NULL CHECK(validity_days > 0),
			max_validity_days INTEGER NOT NULL CHECK(max_validity_days >= validity_days),
			is_ca BOOLEAN DEFAULT FALSE NOT NULL,
			path_length INTEGER,
			policies TEXT DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS revocation_list (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			certificate_id INTEGER NOT NULL,
			serial_number TEXT NOT NULL,
			revocation_time DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			reason_code INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
			UNIQUE(serial_number)
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_customers_api_key ON customers(api_key)`,
		`CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email)`,
		`CREATE INDEX IF NOT EXISTS idx_customers_status ON customers(status)`,
		`CREATE INDEX IF NOT EXISTS idx_customers_tier ON customers(tier)`,
		
		`CREATE INDEX IF NOT EXISTS idx_domains_customer_id ON domains(customer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_domains_domain_name ON domains(domain_name)`,
		`CREATE INDEX IF NOT EXISTS idx_domains_verified ON domains(is_verified)`,
		`CREATE INDEX IF NOT EXISTS idx_domains_validation_token ON domains(validation_token)`,
		
		`CREATE INDEX IF NOT EXISTS idx_certificates_customer_id ON certificates(customer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_serial_number ON certificates(serial_number)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_common_name ON certificates(common_name)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_created_at ON certificates(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_expiry_status ON certificates(not_after, status)`,
		
		`CREATE INDEX IF NOT EXISTS idx_intermediate_cas_customer_id ON intermediate_cas(customer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_intermediate_cas_status ON intermediate_cas(status)`,
		`CREATE INDEX IF NOT EXISTS idx_intermediate_cas_not_after ON intermediate_cas(not_after)`,
		`CREATE INDEX IF NOT EXISTS idx_intermediate_cas_serial ON intermediate_cas(serial_number)`,
		
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_customer_id ON audit_logs(customer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource, resource_id)`,
		
		`CREATE INDEX IF NOT EXISTS idx_api_keys_customer_id ON api_keys(customer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at)`,

		`CREATE INDEX IF NOT EXISTS idx_revocation_list_serial ON revocation_list(serial_number)`,
		`CREATE INDEX IF NOT EXISTS idx_revocation_list_cert_id ON revocation_list(certificate_id)`,
		
		`CREATE TRIGGER IF NOT EXISTS update_customers_updated_at 
		 AFTER UPDATE ON customers FOR EACH ROW
		 BEGIN
			UPDATE customers SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
		 END`,
		 
		`CREATE TRIGGER IF NOT EXISTS update_domains_updated_at 
		 AFTER UPDATE ON domains FOR EACH ROW
		 BEGIN
			UPDATE domains SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
		 END`,
		 
		`CREATE TRIGGER IF NOT EXISTS update_certificates_updated_at 
		 AFTER UPDATE ON certificates FOR EACH ROW
		 BEGIN
			UPDATE certificates SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
		 END`,
		 
		`CREATE TRIGGER IF NOT EXISTS update_intermediate_cas_updated_at 
		 AFTER UPDATE ON intermediate_cas FOR EACH ROW
		 BEGIN
			UPDATE intermediate_cas SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
		 END`,

		`CREATE TRIGGER IF NOT EXISTS update_api_keys_updated_at 
		 AFTER UPDATE ON api_keys FOR EACH ROW
		 BEGIN
			UPDATE api_keys SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
		 END`,

		`CREATE TRIGGER IF NOT EXISTS update_certificate_templates_updated_at 
		 AFTER UPDATE ON certificate_templates FOR EACH ROW
		 BEGIN
			UPDATE certificate_templates SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
		 END`,

		`CREATE TRIGGER IF NOT EXISTS insert_revocation_entry
		 AFTER UPDATE OF status ON certificates FOR EACH ROW
		 WHEN NEW.status = 'revoked' AND OLD.status != 'revoked'
		 BEGIN
			INSERT INTO revocation_list (certificate_id, serial_number, reason_code)
			VALUES (NEW.id, NEW.serial_number, 0);
		 END`,
	}

	for i, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}

	if err := insertDefaultTemplates(db); err != nil {
		return fmt.Errorf("failed to insert default templates: %w", err)
	}

	if err := validateSchema(db); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	return nil
}

func insertDefaultTemplates(db *sql.DB) error {
	templates := []struct {
		name            string
		description     string
		keyUsages       string
		extKeyUsages    string
		validityDays    int
		maxValidityDays int
		isCA            bool
		pathLength      *int
	}{
		{
			name:            "TLS Server",
			description:     "Standard TLS server certificate for web servers and APIs",
			keyUsages:       `["digital_signature", "key_encipherment"]`,
			extKeyUsages:    `["server_auth"]`,
			validityDays:    365,
			maxValidityDays: 825,
			isCA:            false,
		},
		{
			name:            "TLS Client",
			description:     "TLS client certificate for mutual authentication",
			keyUsages:       `["digital_signature", "key_agreement"]`,
			extKeyUsages:    `["client_auth"]`,
			validityDays:    365,
			maxValidityDays: 1095,
			isCA:            false,
		},
		{
			name:            "Code Signing",
			description:     "Certificate for signing software applications and code",
			keyUsages:       `["digital_signature"]`,
			extKeyUsages:    `["code_signing"]`,
			validityDays:    1095,
			maxValidityDays: 1095,
			isCA:            false,
		},
		{
			name:            "Email Protection",
			description:     "S/MIME certificate for email encryption and digital signatures",
			keyUsages:       `["digital_signature", "key_encipherment"]`,
			extKeyUsages:    `["email_protection"]`,
			validityDays:    365,
			maxValidityDays: 1095,
			isCA:            false,
		},
		{
			name:            "Intermediate CA",
			description:     "Intermediate Certificate Authority for issuing end-entity certificates",
			keyUsages:       `["cert_sign", "crl_sign", "digital_signature"]`,
			extKeyUsages:    `[]`,
			validityDays:    1825,
			maxValidityDays: 3650,
			isCA:            true,
			pathLength:      func() *int { i := 0; return &i }(),
		},
	}

	for _, template := range templates {
		query := `INSERT OR IGNORE INTO certificate_templates 
				  (name, description, key_usages, ext_key_usages, validity_days, max_validity_days, is_ca, path_length)
				  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		
		_, err := db.Exec(query, template.name, template.description, template.keyUsages, 
			template.extKeyUsages, template.validityDays, template.maxValidityDays, 
			template.isCA, template.pathLength)
		if err != nil {
			return fmt.Errorf("failed to insert template %s: %w", template.name, err)
		}
	}

	return nil
}

func validateSchema(db *sql.DB) error {
	requiredTables := []string{
		"customers", "domains", "certificates", "intermediate_cas", 
		"audit_logs", "api_keys", "certificate_templates", "revocation_list",
	}

	for _, table := range requiredTables {
		var count int
		query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`
		err := db.QueryRow(query, table).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}
		if count == 0 {
			return fmt.Errorf("required table %s not found", table)
		}
	}

	var foreignKeysEnabled int
	err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeysEnabled)
	if err != nil {
		return fmt.Errorf("failed to check foreign keys: %w", err)
	}
	if foreignKeysEnabled == 0 {
		return fmt.Errorf("foreign keys not enabled")
	}

	return nil
}
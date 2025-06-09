package storage

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func NewSQLiteDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	return db, nil
}

func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS customers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			company_name TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			api_key TEXT NOT NULL UNIQUE,
			tier INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			domain_name TEXT NOT NULL,
			validation_token TEXT NOT NULL,
			is_verified BOOLEAN DEFAULT FALSE,
			verified_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (customer_id) REFERENCES customers(id),
			UNIQUE(customer_id, domain_name)
		)`,
		`CREATE TABLE IF NOT EXISTS certificates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			serial_number TEXT NOT NULL UNIQUE,
			common_name TEXT NOT NULL,
			subject_alt_names TEXT,
			certificate_pem TEXT NOT NULL,
			private_key_pem TEXT NOT NULL,
			algorithms TEXT NOT NULL,
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (customer_id) REFERENCES customers(id)
		)`,
		`CREATE TABLE IF NOT EXISTS intermediate_cas (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			customer_id INTEGER NOT NULL,
			common_name TEXT NOT NULL,
			certificate_pem TEXT NOT NULL,
			private_key_pem TEXT NOT NULL,
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (customer_id) REFERENCES customers(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_customers_api_key ON customers(api_key)`,
		`CREATE INDEX IF NOT EXISTS idx_domains_customer_id ON domains(customer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_customer_id ON certificates(customer_id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_serial_number ON certificates(serial_number)`,
		`CREATE INDEX IF NOT EXISTS idx_intermediate_cas_customer_id ON intermediate_cas(customer_id)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration failed: %v", err)
		}
	}

	return nil
}
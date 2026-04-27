package database

import (
	"database/sql"
	"fmt"
	"log"

	"auth-api/config"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func Connect() {
	cfg := config.AppConfig

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode,
	)

	var err error
	DB, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Veritabanı açılamadı: %v", err)
	}

	if err := DB.Ping(); err != nil {
		log.Fatalf("Veritabanına bağlanılamadı: %v", err)
	}

	log.Println("✅ PostgreSQL'e bağlanıldı")
	migrate()
}

func migrate() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		reset_token TEXT,
		reset_token_expires_at TIMESTAMP,
		email_verified BOOLEAN DEFAULT FALSE,
		email_verification_token TEXT,
		email_verification_expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
	ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token TEXT;
	ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMP;
	`
	if _, err := DB.Exec(query); err != nil {
		log.Fatalf("Tablo oluşturulamadı: %v", err)
	}
	log.Println("✅ users tablosu hazır")
}

package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	JWTSecret      string
	JWTExpiryHours int

	ResetTokenExpiryMinutes int

	ServerPort string
}

var AppConfig *Config

func Load() {
	// .env dosyası varsa yükle, yoksa sistem env'lerini kullan
	if err := godotenv.Load(); err != nil {
		log.Println(".env dosyası bulunamadı, sistem env değişkenleri kullanılacak")
	}

	AppConfig = &Config{
		DBHost:                  getEnv("DB_HOST", "localhost"),
		DBPort:                  getEnv("DB_PORT", "5432"),
		DBUser:                  getEnv("DB_USER", "postgres"),
		DBPassword:              getEnv("DB_PASSWORD", "postgres"),
		DBName:                  getEnv("DB_NAME", "authdb"),
		DBSSLMode:               getEnv("DB_SSLMODE", "disable"),
		JWTSecret:               getEnv("JWT_SECRET", "default-secret-change-me"),
		JWTExpiryHours:          getEnvInt("JWT_EXPIRY_HOURS", 24),
		ResetTokenExpiryMinutes: getEnvInt("RESET_TOKEN_EXPIRY_MINUTES", 15),
		ServerPort:              getEnv("SERVER_PORT", "8080"),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}

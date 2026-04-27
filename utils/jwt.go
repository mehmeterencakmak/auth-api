package utils

import (
	"errors"
	"time"

	"auth-api/config"
	"auth-api/models"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateToken kayıtlı kullanıcı için JWT üretir
func GenerateToken(userID int, username string) (string, error) {
	cfg := config.AppConfig
	expiry := time.Now().Add(time.Duration(cfg.JWTExpiryHours) * time.Hour)

	claims := &models.Claims{
		UserID:   userID,
		Username: username,
		IsGuest:  false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecret))
}

// GenerateGuestToken misafir kullanıcı için kısa ömürlü token üretir
func GenerateGuestToken() (string, error) {
	cfg := config.AppConfig
	expiry := time.Now().Add(1 * time.Hour) // misafirler 1 saat

	claims := &models.Claims{
		UserID:   0,
		Username: "guest",
		IsGuest:  true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "guest",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecret))
}

// ValidateToken token'ı doğrular ve claims döner
func ValidateToken(tokenString string) (*models.Claims, error) {
	cfg := config.AppConfig

	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("beklenmeyen imzalama yöntemi")
		}
		return []byte(cfg.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("geçersiz token")
	}
	return claims, nil
}

package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"auth-api/config"
	"auth-api/database"
	"auth-api/models"
	"auth-api/utils"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

func Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Eksik veya hatalı alan: "+err.Error())
		return
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Şifre hashlenirken hata oluştu")
		return
	}

	verificationToken, err := utils.GenerateRandomToken()
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Doğrulama tokenı üretilemedi")
		return
	}
	tokenExpiry := time.Now().Add(24 * time.Hour)

	var userID int
	query := `
		INSERT INTO users (username, email, password_hash, email_verification_token, email_verification_expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	err = database.DB.QueryRow(query,
		req.Username, strings.ToLower(req.Email), hash, verificationToken, tokenExpiry,
	).Scan(&userID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			if strings.Contains(pqErr.Constraint, "username") {
				utils.JSONError(c, http.StatusConflict, "Bu kullanıcı adı zaten alınmış")
				return
			}
			if strings.Contains(pqErr.Constraint, "email") {
				utils.JSONError(c, http.StatusConflict, "Bu email zaten kayıtlı")
				return
			}
		}
		utils.JSONError(c, http.StatusInternalServerError, "Kayıt sırasında hata oluştu")
		return
	}

	body := fmt.Sprintf(
		"Merhaba %s,\n\nHesabını doğrulamak için aşağıdaki token'ı kullan:\n\n%s\n\nPOST /api/v1/auth/verify-email\n{ \"token\": \"%s\" }\n\nToken 24 saat geçerlidir.",
		req.Username, verificationToken, verificationToken,
	)
	_ = utils.SendEmail(req.Email, "Email Doğrulama", body)

	token, err := utils.GenerateToken(userID, req.Username)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Token üretilemedi")
		return
	}

	utils.JSONSuccess(c, http.StatusCreated, "Kayıt başarılı. Lütfen emailini doğrula.", gin.H{
		"token":          token,
		"username":       req.Username,
		"email":          req.Email,
		"email_verified": false,
	})
}

func Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Eksik veya hatalı alan: "+err.Error())
		return
	}

	var user models.User
	query := `SELECT id, username, email, password_hash, email_verified FROM users WHERE email = $1`
	err := database.DB.QueryRow(query, strings.ToLower(req.Email)).
		Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.EmailVerified)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.JSONError(c, http.StatusUnauthorized, "Email veya şifre hatalı")
			return
		}
		utils.JSONError(c, http.StatusInternalServerError, "Veritabanı hatası")
		return
	}

	if !utils.CheckPassword(user.PasswordHash, req.Password) {
		utils.JSONError(c, http.StatusUnauthorized, "Email veya şifre hatalı")
		return
	}

	if !user.EmailVerified {
		utils.JSONError(c, http.StatusForbidden, "Email adresin doğrulanmamış. Lütfen emailini kontrol et.")
		return
	}

	token, err := utils.GenerateToken(user.ID, user.Username)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Token üretilemedi")
		return
	}

	utils.JSONSuccess(c, http.StatusOK, "Giriş başarılı", gin.H{
		"token":    token,
		"username": user.Username,
		"email":    user.Email,
	})
}

func VerifyEmail(c *gin.Context) {
	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Token gerekli")
		return
	}

	var userID int
	var expiresAt time.Time
	err := database.DB.QueryRow(
		`SELECT id, email_verification_expires_at FROM users WHERE email_verification_token = $1 AND email_verified = FALSE`,
		req.Token,
	).Scan(&userID, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.JSONError(c, http.StatusBadRequest, "Geçersiz veya zaten kullanılmış token")
			return
		}
		utils.JSONError(c, http.StatusInternalServerError, "Veritabanı hatası")
		return
	}

	if time.Now().After(expiresAt) {
		utils.JSONError(c, http.StatusBadRequest, "Token süresi dolmuş, yeniden kayıt ol veya destek iste")
		return
	}

	_, err = database.DB.Exec(
		`UPDATE users SET email_verified = TRUE, email_verification_token = NULL, email_verification_expires_at = NULL, updated_at = NOW() WHERE id = $1`,
		userID,
	)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Doğrulama kaydedilemedi")
		return
	}

	utils.JSONSuccess(c, http.StatusOK, "Email başarıyla doğrulandı, artık giriş yapabilirsin", nil)
}

func Guest(c *gin.Context) {
	token, err := utils.GenerateGuestToken()
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Misafir token üretilemedi")
		return
	}

	utils.JSONSuccess(c, http.StatusOK, "Misafir girişi başarılı", gin.H{
		"token":    token,
		"username": "guest",
		"is_guest": true,
		"note":     "Misafir tokenı 1 saat geçerlidir, private endpoint'lere erişemez",
	})
}

// ResendVerification email doğrulama tokenını yeniden gönderir
func ResendVerification(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Geçerli bir email gerekli")
		return
	}

	var userID int
	var username string
	var verified bool
	err := database.DB.QueryRow(
		`SELECT id, username, email_verified FROM users WHERE email = $1`,
		strings.ToLower(req.Email),
	).Scan(&userID, &username, &verified)

	if err != nil {
		utils.JSONSuccess(c, http.StatusOK, "Eğer bu email kayıtlıysa doğrulama maili gönderildi", nil)
		return
	}

	if verified {
		utils.JSONError(c, http.StatusBadRequest, "Bu email zaten doğrulanmış")
		return
	}

	token, err := utils.GenerateRandomToken()
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Token üretilemedi")
		return
	}
	expiry := time.Now().Add(time.Duration(config.AppConfig.ResetTokenExpiryMinutes) * time.Minute)

	_, err = database.DB.Exec(
		`UPDATE users SET email_verification_token = $1, email_verification_expires_at = $2, updated_at = NOW() WHERE id = $3`,
		token, expiry, userID,
	)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Token kaydedilemedi")
		return
	}

	body := fmt.Sprintf(
		"Merhaba %s,\n\nYeni doğrulama token'ın:\n\n%s\n\nPOST /api/v1/auth/verify-email\n{ \"token\": \"%s\" }\n\nToken %d dakika geçerlidir.",
		username, token, token, config.AppConfig.ResetTokenExpiryMinutes,
	)
	_ = utils.SendEmail(req.Email, "Email Doğrulama (Yeniden)", body)

	utils.JSONSuccess(c, http.StatusOK, "Eğer bu email kayıtlıysa doğrulama maili gönderildi", nil)
}

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
)

// ForgotPassword email alır, reset token üretir ve döner
// (Gerçek bir uygulamada bu token email ile gönderilirdi.
// Bu mini projede direkt response'da dönüyoruz ki Postman'den test edebilesin.)
func ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Geçerli bir email gerekli")
		return
	}

	var userID int
	var username string
	err := database.DB.QueryRow(
		`SELECT id, username FROM users WHERE email = $1`,
		strings.ToLower(req.Email),
	).Scan(&userID, &username)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.JSONError(c, http.StatusNotFound, "Bu email ile kayıtlı kullanıcı bulunamadı")
			return
		}
		utils.JSONError(c, http.StatusInternalServerError, "Veritabanı hatası")
		return
	}

	resetToken, err := utils.GenerateRandomToken()
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Reset token üretilemedi")
		return
	}

	expiry := time.Now().Add(time.Duration(config.AppConfig.ResetTokenExpiryMinutes) * time.Minute)

	_, err = database.DB.Exec(
		`UPDATE users SET reset_token = $1, reset_token_expires_at = $2, updated_at = NOW() WHERE id = $3`,
		resetToken, expiry, userID,
	)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Reset token kaydedilemedi")
		return
	}

	body := fmt.Sprintf(
		"Merhaba %s,\n\nŞifre sıfırlama talebinde bulundun. Aşağıdaki token'ı kullanarak şifreni sıfırlayabilirsin:\n\n%s\n\nPOST /api/v1/auth/reset-password\n{ \"token\": \"%s\", \"new_password\": \"yeni_sifren\" }\n\nToken %d dakika geçerlidir. Bu talebi sen yapmadıysan bu emaili dikkate alma.",
		username, resetToken, resetToken, config.AppConfig.ResetTokenExpiryMinutes,
	)
	_ = utils.SendEmail(req.Email, "Şifre Sıfırlama", body)

	utils.JSONSuccess(c, http.StatusOK, "Şifre sıfırlama bağlantısı emailine gönderildi", nil)
}

// ChangePasswordViaEmail email + mevcut şifreyi doğrular, yeni rastgele şifre üretip emaile gönderir
func ChangePasswordViaEmail(c *gin.Context) {
	var req models.ChangePasswordViaEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Eksik veya hatalı alan: "+err.Error())
		return
	}

	var userID int
	var username, passwordHash string
	var emailVerified bool
	err := database.DB.QueryRow(
		`SELECT id, username, password_hash, email_verified FROM users WHERE email = $1`,
		strings.ToLower(req.Email),
	).Scan(&userID, &username, &passwordHash, &emailVerified)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.JSONError(c, http.StatusUnauthorized, "Email veya şifre hatalı")
			return
		}
		utils.JSONError(c, http.StatusInternalServerError, "Veritabanı hatası")
		return
	}

	if !emailVerified {
		utils.JSONError(c, http.StatusForbidden, "Email adresin doğrulanmamış")
		return
	}

	if !utils.CheckPassword(passwordHash, req.OldPassword) {
		utils.JSONError(c, http.StatusUnauthorized, "Email veya şifre hatalı")
		return
	}

	newPassword, err := utils.GenerateRandomPassword()
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Yeni şifre üretilemedi")
		return
	}

	newHash, err := utils.HashPassword(newPassword)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Şifre hashlenirken hata oluştu")
		return
	}

	_, err = database.DB.Exec(
		`UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
		newHash, userID,
	)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Şifre güncellenemedi")
		return
	}

	body := fmt.Sprintf(
		"Merhaba %s,\n\nYeni şifren:\n\n%s\n\nBu şifreyi giriş yaptıktan sonra değiştirmenizi öneririz.",
		username, newPassword,
	)
	if err := utils.SendEmail(req.Email, "Yeni Şifren", body); err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Şifre güncellendi fakat email gönderilemedi")
		return
	}

	utils.JSONSuccess(c, http.StatusOK, "Yeni şifren emailine gönderildi", nil)
}

// ResetPassword reset token ve yeni şifre alır, şifreyi günceller
func ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Eksik veya hatalı alan: "+err.Error())
		return
	}

	var userID int
	var username, email string
	var expiresAt time.Time
	err := database.DB.QueryRow(
		`SELECT id, username, email, reset_token_expires_at FROM users WHERE reset_token = $1`,
		req.Token,
	).Scan(&userID, &username, &email, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.JSONError(c, http.StatusBadRequest, "Geçersiz reset token")
			return
		}
		utils.JSONError(c, http.StatusInternalServerError, "Veritabanı hatası")
		return
	}

	if time.Now().After(expiresAt) {
		utils.JSONError(c, http.StatusBadRequest, "Reset tokenının süresi dolmuş, yeniden talep edin")
		return
	}

	newHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Şifre hashlenirken hata oluştu")
		return
	}

	_, err = database.DB.Exec(
		`UPDATE users
		 SET password_hash = $1, reset_token = NULL, reset_token_expires_at = NULL, updated_at = NOW()
		 WHERE id = $2`,
		newHash, userID,
	)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Şifre güncellenemedi")
		return
	}

	body := fmt.Sprintf(
		"Merhaba %s,\n\nŞifren başarıyla sıfırlandı. Artık yeni şifrenle giriş yapabilirsin.\n\nEğer bu işlemi sen yapmadıysan lütfen hemen bizimle iletişime geç.",
		username,
	)
	_ = utils.SendEmail(email, "Şifren Sıfırlandı", body)

	utils.JSONSuccess(c, http.StatusOK, "Şifre başarıyla sıfırlandı, artık yeni şifrenle giriş yapabilirsin", nil)
}

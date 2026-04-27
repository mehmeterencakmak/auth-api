package handlers

import (
	"database/sql"
	"net/http"
	"strings"

	"auth-api/database"
	"auth-api/models"
	"auth-api/utils"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

// Me bilgi amaçlı: token'a sahip kullanıcının bilgilerini döner
func Me(c *gin.Context) {
	userID := c.GetInt("user_id")

	var user models.User
	query := `SELECT id, username, email, email_verified, created_at, updated_at FROM users WHERE id = $1`
	err := database.DB.QueryRow(query, userID).
		Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		utils.JSONError(c, http.StatusNotFound, "Kullanıcı bulunamadı")
		return
	}

	utils.JSONSuccess(c, http.StatusOK, "Kullanıcı bilgileri", user)
}

// ChangePassword eski şifreyi doğrular, yeniyi hashler ve günceller
func ChangePassword(c *gin.Context) {
	userID := c.GetInt("user_id")

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Eksik veya hatalı alan: "+err.Error())
		return
	}

	if req.OldPassword == req.NewPassword {
		utils.JSONError(c, http.StatusBadRequest, "Yeni şifre eskisiyle aynı olamaz")
		return
	}

	var currentHash, email, username string
	err := database.DB.QueryRow(`SELECT password_hash, email, username FROM users WHERE id = $1`, userID).
		Scan(&currentHash, &email, &username)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.JSONError(c, http.StatusNotFound, "Kullanıcı bulunamadı")
			return
		}
		utils.JSONError(c, http.StatusInternalServerError, "Veritabanı hatası")
		return
	}

	if !utils.CheckPassword(currentHash, req.OldPassword) {
		utils.JSONError(c, http.StatusUnauthorized, "Eski şifre yanlış, yeni şifreyle eşleşmiyor")
		return
	}

	newHash, err := utils.HashPassword(req.NewPassword)
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

	body := "Merhaba " + username + ",\n\nHesabının şifresi başarıyla değiştirildi.\n\nEğer bu işlemi sen yapmadıysan lütfen hemen bizimle iletişime geç."
	_ = utils.SendEmail(email, "Şifre Değiştirildi", body)

	utils.JSONSuccess(c, http.StatusOK, "Şifre başarıyla güncellendi", nil)
}

// ChangeUsername kullanıcı adını günceller
func ChangeUsername(c *gin.Context) {
	userID := c.GetInt("user_id")

	var req models.ChangeUsernameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Eksik veya hatalı alan: "+err.Error())
		return
	}

	currentUsername := c.GetString("username")
	if req.NewUsername == currentUsername {
		utils.JSONError(c, http.StatusBadRequest, "Yeni kullanıcı adı mevcut olanla aynı")
		return
	}

	_, err := database.DB.Exec(
		`UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2`,
		req.NewUsername, userID,
	)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" &&
			strings.Contains(pqErr.Constraint, "username") {
			utils.JSONError(c, http.StatusConflict, "Bu kullanıcı adı zaten alınmış")
			return
		}
		utils.JSONError(c, http.StatusInternalServerError, "Kullanıcı adı güncellenemedi")
		return
	}

	utils.JSONSuccess(c, http.StatusOK, "Kullanıcı adı başarıyla güncellendi", gin.H{
		"new_username": req.NewUsername,
		"note":         "Yeni token almak için tekrar login olmanız önerilir",
	})
}

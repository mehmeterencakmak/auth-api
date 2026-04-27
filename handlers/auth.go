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

// Register yeni kullanıcı kaydeder
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

	var userID int
	query := `
		INSERT INTO users (username, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id
	`
	err = database.DB.QueryRow(query, req.Username, strings.ToLower(req.Email), hash).Scan(&userID)
	if err != nil {
		// unique constraint hata kontrolü
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

	token, err := utils.GenerateToken(userID, req.Username)
	if err != nil {
		utils.JSONError(c, http.StatusInternalServerError, "Token üretilemedi")
		return
	}

	utils.JSONSuccess(c, http.StatusCreated, "Kayıt başarılı", gin.H{
		"token":    token,
		"username": req.Username,
		"email":    req.Email,
	})
}

// Login email + şifre ile giriş yapar, JWT döner
func Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.JSONError(c, http.StatusBadRequest, "Eksik veya hatalı alan: "+err.Error())
		return
	}

	var user models.User
	query := `SELECT id, username, email, password_hash FROM users WHERE email = $1`
	err := database.DB.QueryRow(query, strings.ToLower(req.Email)).
		Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash)

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

// Guest kayıt gerektirmeden misafir token döner
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

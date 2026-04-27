package middleware

import (
	"net/http"
	"strings"

	"auth-api/utils"

	"github.com/gin-gonic/gin"
)

// AuthRequired Authorization header'daki Bearer token'ı doğrular
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.JSONError(c, http.StatusUnauthorized, "Authorization header eksik")
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.JSONError(c, http.StatusUnauthorized, "Authorization header formatı hatalı (Bearer <token> olmalı)")
			c.Abort()
			return
		}

		claims, err := utils.ValidateToken(parts[1])
		if err != nil {
			utils.JSONError(c, http.StatusUnauthorized, "Geçersiz veya süresi dolmuş token")
			c.Abort()
			return
		}

		// Misafir kullanıcılar private endpoint'leri kullanamaz
		if claims.IsGuest {
			utils.JSONError(c, http.StatusForbidden, "Misafir kullanıcılar bu işlemi yapamaz, lütfen kayıt olun")
			c.Abort()
			return
		}

		// Sonraki handler'lar için context'e koy
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}

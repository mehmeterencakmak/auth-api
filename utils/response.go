package utils

import "github.com/gin-gonic/gin"

// JSONError tutarlı hata yanıtı üretir
func JSONError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{
		"success": false,
		"error":   message,
	})
}

// JSONSuccess tutarlı başarı yanıtı üretir
func JSONSuccess(c *gin.Context, status int, message string, data interface{}) {
	resp := gin.H{
		"success": true,
		"message": message,
	}
	if data != nil {
		resp["data"] = data
	}
	c.JSON(status, resp)
}

// GenerateRandomToken şifre sıfırlama için rastgele token üretir
func GenerateRandomToken() (string, error) {
	return generateSecureToken(32)
}

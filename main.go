package main

import (
	"log"

	"auth-api/config"
	"auth-api/database"
	"auth-api/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1. Config'i yükle
	config.Load()

	// 2. Veritabanına bağlan + tabloyu oluştur
	database.Connect()
	defer database.DB.Close()

	// 3. Gin router'ı başlat
	r := gin.Default()
	routes.Setup(r)

	// 4. Sunucuyu çalıştır
	port := config.AppConfig.ServerPort
	log.Printf("🚀 Sunucu :%s portunda başlatılıyor...", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Sunucu başlatılamadı: %v", err)
	}
}

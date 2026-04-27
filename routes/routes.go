package routes

import (
	"auth-api/handlers"
	"auth-api/middleware"

	"github.com/gin-gonic/gin"
)

func Setup(r *gin.Engine) {
	// Sağlık kontrolü
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	api := r.Group("/api/v1")
	{
		// --- Public endpoint'ler (token gerektirmez) ---
		public := api.Group("/auth")
		{
			public.POST("/register", handlers.Register)
			public.POST("/login", handlers.Login)
			public.POST("/guest", handlers.Guest)
			public.POST("/forgot-password", handlers.ForgotPassword)
			public.POST("/reset-password", handlers.ResetPassword)
		}

		// --- Private endpoint'ler (Bearer token gerekir) ---
		private := api.Group("/user")
		private.Use(middleware.AuthRequired())
		{
			private.GET("/me", handlers.Me)
			private.PUT("/change-password", handlers.ChangePassword)
			private.PUT("/change-username", handlers.ChangeUsername)
		}
	}
}

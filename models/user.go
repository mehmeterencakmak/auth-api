package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	IsGuest  bool   `json:"is_guest"`
	jwt.RegisteredClaims
}

type User struct {
	ID                          int        `json:"id"`
	Username                    string     `json:"username"`
	Email                       string     `json:"email"`
	PasswordHash                string     `json:"-"`
	EmailVerified               bool       `json:"email_verified"`
	EmailVerificationToken      *string    `json:"-"`
	EmailVerificationExpiresAt  *time.Time `json:"-"`
	ResetToken                  *string    `json:"-"`
	ResetTokenExpiresAt         *time.Time `json:"-"`
	CreatedAt                   time.Time  `json:"created_at"`
	UpdatedAt                   time.Time  `json:"updated_at"`
}

// --- Request Body modelleri ---

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

type ChangeUsernameRequest struct {
	NewUsername string `json:"new_username" binding:"required,min=3,max=50"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type ChangePasswordViaEmailRequest struct {
	Email       string `json:"email" binding:"required,email"`
	OldPassword string `json:"old_password" binding:"required"`
}

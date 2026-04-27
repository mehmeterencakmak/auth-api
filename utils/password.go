package utils

import "golang.org/x/crypto/bcrypt"

// HashPassword şifreyi bcrypt ile hashler
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword hash ile düz şifreyi karşılaştırır
func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

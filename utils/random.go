package utils

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

func generateSecureToken(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateRandomPassword kullanıcıya emaille gönderilecek okunabilir rastgele şifre üretir.
// Büyük harf + küçük harf + rakam karışımı, 12 karakter.
func GenerateRandomPassword() (string, error) {
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	result := make([]byte, 12)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

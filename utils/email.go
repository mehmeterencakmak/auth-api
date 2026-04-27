package utils

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"

	"auth-api/config"
)

// SendEmail SMTP üzerinden email gönderir.
// SMTP yapılandırılmamışsa token/içeriği konsola yazar (geliştirme modu).
func SendEmail(to, subject, body string) error {
	cfg := config.AppConfig

	if cfg.SMTPHost == "" || cfg.SMTPUser == "" {
		log.Printf("[DEV-MODE] Email gönderilemiyor (SMTP yapılandırılmamış).\nKime: %s\nKonu: %s\nİçerik:\n%s\n", to, subject, body)
		return nil
	}

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPHost)

	msg := buildMessage(cfg.SMTPFrom, to, subject, body)

	addr := cfg.SMTPHost + ":" + cfg.SMTPPort
	if err := smtp.SendMail(addr, auth, cfg.SMTPFrom, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("email gönderilemedi: %w", err)
	}
	return nil
}

func buildMessage(from, to, subject, body string) string {
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + to + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

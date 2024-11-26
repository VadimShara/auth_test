package email

import (
	"fmt"
	"net/smtp"
)

func SendWarning(email string, appEmail, appPassword, smtpHost string) error {
	smtpPort := "587"

	auth := smtp.PlainAuth("", appEmail, appPassword, smtpHost)

	from := appEmail
	to := []string{email}
	subject := "Email Verification Code"
	body := fmt.Sprintf("")
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", email, subject, body))

	err := smtp.SendMail(fmt.Sprintf("%s:%s", smtpHost, smtpPort), auth, from, to, msg)
	if err != nil {
		return err
	}

	return nil
}

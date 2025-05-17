package models

type User struct {
	UserID       string
	Username     string
	PasswordHash string
	Email        string
	CertID       string
	PINHash      string
}

package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashPassword 对密码进行SHA256哈希
func HashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// CheckPassword 检查密码是否匹配
func CheckPassword(password, hash string) bool {
	return HashPassword(password) == hash
}

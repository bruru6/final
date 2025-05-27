package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// 采用SHA256算法对密码进行加密存储和校验。

// HashPassword 对密码进行SHA256哈希
// 输入明文密码，返回哈希字符串
func HashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// CheckPassword 检查密码是否匹配
// 输入明文密码和哈希，返回是否一致
func CheckPassword(password, hash string) bool {
	return HashPassword(password) == hash
}

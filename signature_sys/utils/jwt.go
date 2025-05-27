package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// utils/jwt.go
// 本文件实现了JWT令牌的生成与校验工具函数。
// 用于用户登录态管理，基于HS256算法。

var jwtKey = generateRandomKey()

func generateRandomKey() []byte {
	return []byte(time.Now().Format("20060102150405.000000000"))
}

// Claims 结构体，包含用户ID、用户名及标准JWT字段
// 用于JWT载荷
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateJWT 生成JWT
// 输入用户ID和用户名，返回签名后的token字符串
func GenerateJWT(userID, username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// ParseJWT 校验JWT
// 输入token字符串，返回Claims结构体和错误信息
func ParseJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return claims, nil
}

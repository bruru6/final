package models

// models/user.go
// 本文件定义了User用户数据结构，对应数据库User表。
// 主要用于用户信息的存储和传递。

type User struct {
	UserID       string // 用户唯一ID
	Username     string // 用户名
	PasswordHash string // 密码哈希
	Email        string // 邮箱
	CertID       string // 证书ID（可选）
	PINHash      string // PIN码哈希
}

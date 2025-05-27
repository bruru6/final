package middleware

import (
	"net/http"
	"signature_sys/utils"
)

// middleware/middleware.go
// 本文件实现了JWT认证相关的中间件和工具函数。
// 包括登录校验、用户信息获取等，供各业务Handler调用。

// JWT认证中间件，未登录则跳转到登录页
// 用法：在需要登录的路由上包裹此中间件
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 从请求中获取名为"token"的Cookie
		cookie, err := r.Cookie("token")
		if err != nil || cookie.Value == "" {
			// 如果Cookie不存在或值为空，跳转到登录页
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// 解析JWT，验证其合法性
		_, err = utils.ParseJWT(cookie.Value)
		if err != nil {
			// 如果JWT解析失败，跳转到登录页
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// 如果验证通过，执行下一个Handler
		next(w, r)
	}
}

// 获取当前登录用户信息（未登录返回空字符串）
// 返回值：userID, username
func GetCurrentUser(r *http.Request) (userID, username string) {
	// 从请求中获取名为"token"的Cookie
	cookie, err := r.Cookie("token")
	if err != nil || cookie.Value == "" {
		// 如果Cookie不存在或值为空，返回空字符串
		return "", ""
	}
	// 解析JWT，提取其中的用户信息
	claims, err := utils.ParseJWT(cookie.Value)
	if err != nil {
		// 如果JWT解析失败，返回空字符串
		return "", ""
	}
	// 返回用户ID和用户名
	return claims.UserID, claims.Username
}

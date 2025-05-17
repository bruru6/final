package middleware

import (
	"net/http"
	"signature_sys/utils"
)

// JWT认证中间件，未登录则跳转到登录页
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		_, err = utils.ParseJWT(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// 获取当前登录用户信息（未登录返回空字符串）
func GetCurrentUser(r *http.Request) (userID, username string) {
	cookie, err := r.Cookie("token")
	if err != nil || cookie.Value == "" {
		return "", ""
	}
	claims, err := utils.ParseJWT(cookie.Value)
	if err != nil {
		return "", ""
	}
	return claims.UserID, claims.Username
}

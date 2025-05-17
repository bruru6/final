package handlers

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"signature_sys/config"
	"signature_sys/models"
	"signature_sys/utils"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("signsys-secret-key"))

// 注册页面和处理
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		t, _ := template.ParseFiles("templates/register.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")
		pin := r.FormValue("pin")
		if username == "" || password == "" || pin == "" {
			http.Error(w, "用户名、密码和PIN码不能为空", 400)
			return
		}
		userID := uuid.New().String()
		passwordHash := utils.HashPassword(password)
		pinHash := utils.HashPassword(pin)
		_, err := config.DB.Exec("INSERT INTO [User] (UserID, Username, PasswordHash, Email, PINHash) VALUES (@p1, @p2, @p3, @p4, @p5)", userID, username, passwordHash, email, pinHash)
		if err != nil {
			log.Println("注册失败:", err)
			http.Error(w, "注册失败", 500)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// 登录页面和处理
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		t, _ := template.ParseFiles("templates/login.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		var user models.User
		row := config.DB.QueryRow("SELECT UserID, PasswordHash FROM [User] WHERE Username=@p1", username)
		err := row.Scan(&user.UserID, &user.PasswordHash)
		if err == sql.ErrNoRows || !utils.CheckPassword(password, user.PasswordHash) {
			http.Error(w, "用户名或密码错误", 401)
			return
		}
		if err != nil {
			http.Error(w, "登录失败", 500)
			return
		}
		token, err := utils.GenerateJWT(user.UserID, username)
		if err != nil {
			http.Error(w, "生成Token失败", 500)
			return
		}
		// 设置JWT到cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(24 * time.Hour),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// 退出登录
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// 首页处理
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	// 恢复正常首页逻辑：根据token判断是否登录
	isLogin := false
	username := ""
	if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
		if claims, err := utils.ParseJWT(cookie.Value); err == nil {
			isLogin = true
			username = claims.Username
		}
	}
	t, _ := template.ParseFiles("templates/index.html")
	t.Execute(w, map[string]interface{}{
		"IsLogin":  isLogin,
		"Username": username,
	})
}

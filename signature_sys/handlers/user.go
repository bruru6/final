// handlers/user.go
// 本文件实现了用户相关的所有HTTP处理逻辑，包括注册、登录、登出、首页展示、PIN码设置等。
// 涉及数据库操作、证书自动生成、JWT认证、会话管理等功能。

package handlers

import (
	"crypto/ecdsa"         // ECC加密算法
	"crypto/elliptic"      // 椭圆曲线
	"crypto/rand"          // 随机数生成器
	"crypto/rsa"           // RSA加密算法
	"crypto/x509"          // X.509证书标准
	"crypto/x509/pkix"     // X.509证书主题
	"database/sql"         // 数据库操作
	"encoding/pem"         // PEM格式编码
	"fmt"                  // 格式化输出
	"html/template"        // HTML模板渲染
	"math/big"             // 大整数运算
	"net/http"             // HTTP协议
	"os"                   // 文件操作
	"path/filepath"        // 文件路径操作
	"signature_sys/config" // 配置模块
	"signature_sys/models" // 数据模型模块
	"signature_sys/utils"  // 工具模块
	"time"                 // 时间操作

	"github.com/google/uuid"      // UUID生成器
	"github.com/gorilla/sessions" // 会话管理
)

// 全局会话存储，基于Cookie实现，密钥为signsys-secret-key
var store = sessions.NewCookieStore([]byte("signsys-secret-key"))

// RegisterHandler 处理用户注册页面的GET和POST请求
// GET: 渲染注册页面
// POST: 校验参数，写入用户表，自动生成ECC和RSA证书并写入证书表
// 注册流程：
// 1. 校验用户名、密码、PIN码等参数
// 2. 生成用户ID，对密码和PIN码进行哈希加密
// 3. 写入用户表
// 4. 自动生成ECC证书（P256曲线），生成私钥、证书、公钥，写入文件和数据库
// 5. 自动生成RSA证书（2048位），生成私钥、证书、公钥，写入文件和数据库
// 6. 注册成功后跳转到登录页
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 渲染注册页面
		t, _ := template.ParseFiles("templates/register.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		// 获取表单参数
		username := r.FormValue("username") // 用户名
		password := r.FormValue("password") // 密码
		email := r.FormValue("email")       // 邮箱
		pin := r.FormValue("pin")           // PIN码
		// 校验必填项
		if username == "" || password == "" || pin == "" {
			http.Error(w, "用户名、密码和PIN码不能为空", 400)
			return
		}
		// 生成用户ID，密码/PIN加密存储
		userID := uuid.New().String()                // 生成唯一用户ID
		passwordHash := utils.HashPassword(password) // 密码哈希
		pinHash := utils.HashPassword(pin)           // PIN码哈希
		// 写入用户表
		_, err := config.DB.Exec("INSERT INTO [User] (UserID, Username, PasswordHash, Email, PINHash) VALUES (@p1, @p2, @p3, @p4, @p5)", userID, username, passwordHash, email, pinHash)
		if err != nil {
			http.Error(w, "注册失败", 500)
			return
		}
		// 注册后自动为用户生成ECC和RSA证书
		// --- ECC证书生成 ---
		certID_ECC := uuid.New().String()                                        // 证书ID
		certPath_ECC := filepath.Join("static/certs", certID_ECC+".pem")         // 证书文件路径
		privPath_ECC := filepath.Join("static/certs", certID_ECC+"_private.pem") // 私钥文件路径
		validFrom := time.Now()                                                  // 有效期起始
		validTo := validFrom.AddDate(5, 0, 0)                                    // 有效期5年
		privECC, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)            // 生成ECC私钥
		tmplECC := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),      // 序列号
			Subject:      pkix.Name{CommonName: "User ECC Cert"}, // 主题
			NotBefore:    validFrom,
			NotAfter:     validTo,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment, // 用途：数字签名和不可否认性
		}
		certDER_ECC, _ := x509.CreateCertificate(rand.Reader, &tmplECC, &tmplECC, &privECC.PublicKey, privECC) // 生成自签名证书
		bECC, _ := x509.MarshalECPrivateKey(privECC)                                                           // 编码私钥
		privPEM_ECC := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bECC})                     // PEM格式私钥
		certPEM_ECC := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER_ECC})                 // PEM格式证书
		pubKeyDER_ECC, _ := x509.MarshalPKIXPublicKey(&privECC.PublicKey)                                      // 公钥DER
		pubKeyPEM_ECC := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER_ECC}))      // PEM格式公钥
		issuerDN_ECC := tmplECC.Subject.String()                                                               // 颁发者信息
		os.MkdirAll("static/certs", 0755)                                                                      // 确保目录存在
		os.WriteFile(certPath_ECC, certPEM_ECC, 0644)                                                          // 写入证书文件
		os.WriteFile(privPath_ECC, privPEM_ECC, 0600)                                                          // 写入私钥文件
		algoECC := "ECC"                                                                                       // 算法类型
		// 写入证书表
		_, err = config.DB.Exec("INSERT INTO [Cert] (CertID, UserID, Location, IssuerDN, ValidFrom, ValidTo, PublicKey, Algo) VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8)",
			certID_ECC, userID, certPath_ECC, issuerDN_ECC, validFrom, validTo, pubKeyPEM_ECC, algoECC)
		if err != nil {
			fmt.Println("注册ECC证书写入失败：", err)
		}
		// --- RSA证书生成 ---
		certID_RSA := uuid.New().String()                                        // 证书ID
		certPath_RSA := filepath.Join("static/certs", certID_RSA+".pem")         // 证书文件路径
		privPath_RSA := filepath.Join("static/certs", certID_RSA+"_private.pem") // 私钥文件路径
		privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)                         // 生成RSA私钥
		tmplRSA := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),      // 序列号
			Subject:      pkix.Name{CommonName: "User RSA Cert"}, // 主题
			NotBefore:    validFrom,
			NotAfter:     validTo,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment, // 用途：数字签名和不可否认性
		}
		certDER_RSA, _ := x509.CreateCertificate(rand.Reader, &tmplRSA, &tmplRSA, &privRSA.PublicKey, privRSA)              // 生成自签名证书
		privPEM_RSA := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privRSA)}) // PEM格式私钥
		certPEM_RSA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER_RSA})                              // PEM格式证书
		pubKeyDER_RSA, _ := x509.MarshalPKIXPublicKey(&privRSA.PublicKey)                                                   // 公钥DER
		pubKeyPEM_RSA := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER_RSA}))                   // PEM格式公钥
		issuerDN_RSA := tmplRSA.Subject.String()                                                                            // 颁发者信息
		os.WriteFile(certPath_RSA, certPEM_RSA, 0644)                                                                       // 写入证书文件
		os.WriteFile(privPath_RSA, privPEM_RSA, 0600)                                                                       // 写入私钥文件
		algoRSA := "RSA"                                                                                                    // 算法类型
		// 写入证书表
		_, err = config.DB.Exec("INSERT INTO [Cert] (CertID, UserID, Location, IssuerDN, ValidFrom, ValidTo, PublicKey, Algo) VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8)",
			certID_RSA, userID, certPath_RSA, issuerDN_RSA, validFrom, validTo, pubKeyPEM_RSA, algoRSA)
		if err != nil {
			fmt.Println("注册RSA证书写入失败：", err)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// LoginHandler 处理用户登录页面的GET和POST请求
// GET: 渲染登录页面
// POST: 校验用户名密码，生成JWT写入cookie
// 登录流程：
// 1. 校验用户名、密码
// 2. 查询用户表，校验密码哈希
// 3. 生成JWT Token，写入cookie
// 4. 跳转到首页
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 渲染登录页面
		t, _ := template.ParseFiles("templates/login.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username") // 用户名
		password := r.FormValue("password") // 密码
		var user models.User
		// 查询用户信息
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
		// 生成JWT
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

// LogoutHandler 处理用户登出，清除token cookie
// 登出流程：
// 1. 清空token cookie
// 2. 跳转到登录页
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

// IndexHandler 处理首页展示，根据token判断是否登录，渲染用户名
// 首页流程：
// 1. 检查token cookie，解析JWT
// 2. 判断是否登录，渲染用户名
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

// 电子签章系统主程序入口，负责初始化数据库、注册路由、启动Web服务
package main

import (
	"log"
	"net/http"
	"signature_sys/config"
	"signature_sys/handlers"
	"signature_sys/middleware"
)

func main() {
	// 初始化数据库连接，确保全局可用
	config.InitDB()

	// 路由注册，绑定URL到对应的处理函数
	// 首页
	http.HandleFunc("/", handlers.IndexHandler)
	// 用户注册、登录、登出
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/logout", handlers.LogoutHandler)
	// 签章图片相关，需登录后才能访问
	http.HandleFunc("/seal/upload", middleware.AuthMiddleware(handlers.SealUploadHandler))
	http.HandleFunc("/seal/list", middleware.AuthMiddleware(handlers.SealListHandler))
	http.HandleFunc("/seal/delete", middleware.AuthMiddleware(handlers.SealDeleteHandler))
	// PDF文档相关，需登录
	http.HandleFunc("/document/upload", middleware.AuthMiddleware(handlers.DocumentUploadHandler))
	http.HandleFunc("/document/list", middleware.AuthMiddleware(handlers.DocumentListHandler))
	http.HandleFunc("/document/delete", middleware.AuthMiddleware(handlers.DocumentDeleteHandler))
	// PDF签章相关，需登录
	http.HandleFunc("/sign/pdf", middleware.AuthMiddleware(handlers.SignPDFHandler))          // 盖章处理
	http.HandleFunc("/sign/pdf/form", middleware.AuthMiddleware(handlers.SignPDFPageHandler)) // 盖章页面
	http.HandleFunc("/sign/preview", handlers.SignPDFPreviewHandler)
	// PDF验签相关
	http.HandleFunc("/verify/pdf/page", handlers.VerifyPDFPageHandler)
	http.HandleFunc("/verify/pdf", handlers.VerifyPDFHandler)
	// 静态资源（CSS、图片、证书、文档等）
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// 启动Web服务，监听8080端口
	log.Println("Server started at http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

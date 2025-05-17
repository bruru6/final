package main

import (
	"log"
	"net/http"
	"signature_sys/config"
	"signature_sys/handlers"
	"signature_sys/middleware"
)

func main() {
	// 初始化数据库
	config.InitDB()

	// 路由
	http.HandleFunc("/", handlers.IndexHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/seal/upload", middleware.AuthMiddleware(handlers.SealUploadHandler))
	http.HandleFunc("/seal/list", middleware.AuthMiddleware(handlers.SealListHandler))
	http.HandleFunc("/seal/delete", middleware.AuthMiddleware(handlers.SealDeleteHandler))
	http.HandleFunc("/document/upload", middleware.AuthMiddleware(handlers.DocumentUploadHandler))
	http.HandleFunc("/sign/pdf", middleware.AuthMiddleware(handlers.SignPDFHandler))
	http.HandleFunc("/sign/pdf/form", middleware.AuthMiddleware(handlers.SignPDFPageHandler))
	http.HandleFunc("/sign/preview", handlers.SignPDFPreviewHandler)
	http.HandleFunc("/document/list", middleware.AuthMiddleware(handlers.DocumentListHandler))
	http.HandleFunc("/document/delete", middleware.AuthMiddleware(handlers.DocumentDeleteHandler))
	http.HandleFunc("/verify/pdf", handlers.VerifyPDFHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server started at :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

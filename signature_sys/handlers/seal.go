package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"signature_sys/config"
	"signature_sys/middleware"
	"strings"

	"github.com/google/uuid"
)

// handlers/seal.go
// 本文件实现了签章图片相关的HTTP处理逻辑，包括签章图片上传、列表展示、删除等功能。
// 涉及文件上传、哈希计算、数据库操作、用户认证等。

// 签章图片上传页面和处理
// GET: 渲染上传页面
// POST: 处理图片上传，计算哈希，保存图片，写入数据库
func SealUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 渲染上传页面
		t, _ := template.ParseFiles("templates/seal_upload.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		// 处理图片上传
		file, header, err := r.FormFile("sealimg") // 获取上传的图片文件和文件头
		if err != nil {
			// 如果文件上传失败，返回400错误
			http.Error(w, "文件上传失败", 400)
			return
		}
		defer file.Close() // 关闭文件句柄

		// 计算图片哈希
		hasher := sha256.New()            // 新建SHA256哈希器
		tee := io.TeeReader(file, hasher) // tee用于边读边哈希
		// 保存图片到 static/seals 目录
		os.MkdirAll("static/seals", 0755)                                              // 确保目录存在
		sealID := uuid.New().String()                                                  // 生成唯一签章ID
		imgPath := filepath.Join("static/seals", sealID+filepath.Ext(header.Filename)) // 拼接图片保存路径
		out, err := os.Create(imgPath)                                                 // 创建图片文件
		if err != nil {
			// 如果保存图片失败，返回500错误
			http.Error(w, "保存图片失败", 500)
			return
		}
		defer out.Close()                              // 关闭输出文件
		io.Copy(out, tee)                              // 写入图片并计算哈希
		imgHash := hex.EncodeToString(hasher.Sum(nil)) // 获取图片哈希值

		// 获取当前登录用户ID
		userID, _ := middleware.GetCurrentUser(r)
		if userID == "" {
			// 如果用户未登录，返回401错误
			http.Error(w, "请先登录", 401)
			return
		}
		// 将签章信息写入数据库
		_, err = config.DB.Exec("INSERT INTO [Seal] (SealID, UserID, ImageHash, Location) VALUES (@p1, @p2, @p3, @p4)", sealID, userID, imgHash, imgPath)
		if err != nil {
			// 如果数据库写入失败，返回500错误
			http.Error(w, "数据库写入失败", 500)
			return
		}
		// 返回上传成功信息
		// fmt.Fprintf(w, "上传成功，图片哈希：%s", imgHash)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// 签章图片列表页面
// 展示当前用户所有签章图片，支持前端查找（已在模板实现）
func SealListHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		// 如果用户未登录，重定向到登录页面
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// 查询当前用户的签章图片信息
	rows, err := config.DB.Query("SELECT SealID, ImageHash, Location FROM [Seal] WHERE UserID=@p1", userID)
	if err != nil {
		// 如果数据库查询失败，返回500错误
		http.Error(w, "数据库查询失败", 500)
		return
	}
	defer rows.Close() // 关闭结果集
	var seals []struct {
		SealID    string // 签章ID
		ImageHash string // 图片哈希
		Location  string // 图片路径
		FileName  string // 图片文件名
	}
	for rows.Next() {
		var s struct {
			SealID    string
			ImageHash string
			Location  string
			FileName  string
		}
		rows.Scan(&s.SealID, &s.ImageHash, &s.Location)
		s.Location = strings.ReplaceAll(s.Location, "\\", "/")
		s.FileName = filepath.Base(s.Location) // 提取文件名
		seals = append(seals, s)
	}
	// 渲染签章列表页面
	t, _ := template.ParseFiles("templates/seal_list.html")
	t.Execute(w, map[string]interface{}{"Seals": seals})
}

// 删除签章图片
// 仅支持POST，校验用户，删除数据库记录和图片文件
func SealDeleteHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		// 如果用户未登录，重定向到登录页面
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		// 如果请求方法不是POST，返回405错误
		http.Error(w, "仅支持POST", 405)
		return
	}
	// 获取签章ID
	sealID := r.FormValue("seal_id")
	if sealID == "" {
		// 如果签章ID为空，返回400错误
		http.Error(w, "参数错误", 400)
		return
	}
	// 查询图片路径
	var imgPath string
	err := config.DB.QueryRow("SELECT Location FROM [Seal] WHERE SealID=@p1 AND UserID=@p2", sealID, userID).Scan(&imgPath)
	if err != nil {
		// 如果未找到图片，返回404错误
		http.Error(w, "未找到图片", 404)
		return
	}
	// 删除数据库记录
	_, err = config.DB.Exec("DELETE FROM [Seal] WHERE SealID=@p1 AND UserID=@p2", sealID, userID)
	if err != nil {
		// 如果数据库删除失败，返回500错误
		http.Error(w, "数据库删除失败", 500)
		return
	}
	// 删除文件
	os.Remove(imgPath)
	// 重定向到签章列表页面
	http.Redirect(w, r, "/seal/list", http.StatusSeeOther)
}

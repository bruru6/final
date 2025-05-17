package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"signature_sys/config"
	"signature_sys/middleware"

	"github.com/google/uuid"
)

// 签章图片上传页面和处理
func SealUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		t, _ := template.ParseFiles("templates/seal_upload.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		file, header, err := r.FormFile("sealimg")
		if err != nil {
			http.Error(w, "文件上传失败", 400)
			return
		}
		defer file.Close()

		// 计算图片哈希
		hasher := sha256.New()
		tee := io.TeeReader(file, hasher)
		// 保存图片到 static/seals 目录
		os.MkdirAll("static/seals", 0755)
		sealID := uuid.New().String()
		imgPath := filepath.Join("static/seals", sealID+filepath.Ext(header.Filename))
		out, err := os.Create(imgPath)
		if err != nil {
			http.Error(w, "保存图片失败", 500)
			return
		}
		defer out.Close()
		io.Copy(out, tee)
		imgHash := hex.EncodeToString(hasher.Sum(nil))

		// 获取当前登录用户ID
		userID, _ := middleware.GetCurrentUser(r)
		if userID == "" {
			http.Error(w, "请先登录", 401)
			return
		}
		_, err = config.DB.Exec("INSERT INTO [Seal] (SealID, UserID, ImageHash, Location) VALUES (@p1, @p2, @p3, @p4)", sealID, userID, imgHash, imgPath)
		if err != nil {
			http.Error(w, "数据库写入失败", 500)
			return
		}
		fmt.Fprintf(w, "上传成功，图片哈希：%s", imgHash)
	}
}

// 签章图片列表页面
func SealListHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	rows, err := config.DB.Query("SELECT SealID, ImageHash, Location FROM [Seal] WHERE UserID=@p1", userID)
	if err != nil {
		http.Error(w, "数据库查询失败", 500)
		return
	}
	defer rows.Close()
	var seals []struct {
		SealID    string
		ImageHash string
		Location  string
	}
	for rows.Next() {
		var s struct {
			SealID    string
			ImageHash string
			Location  string
		}
		rows.Scan(&s.SealID, &s.ImageHash, &s.Location)
		seals = append(seals, s)
	}
	t, _ := template.ParseFiles("templates/seal_list.html")
	t.Execute(w, map[string]interface{}{"Seals": seals})
}

// 删除签章图片
func SealDeleteHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST", 405)
		return
	}
	sealID := r.FormValue("seal_id")
	if sealID == "" {
		http.Error(w, "参数错误", 400)
		return
	}
	// 查询图片路径
	var imgPath string
	err := config.DB.QueryRow("SELECT Location FROM [Seal] WHERE SealID=@p1 AND UserID=@p2", sealID, userID).Scan(&imgPath)
	if err != nil {
		http.Error(w, "未找到图片", 404)
		return
	}
	// 删除数据库记录
	_, err = config.DB.Exec("DELETE FROM [Seal] WHERE SealID=@p1 AND UserID=@p2", sealID, userID)
	if err != nil {
		http.Error(w, "数据库删除失败", 500)
		return
	}
	// 删除文件
	os.Remove(imgPath)
	http.Redirect(w, r, "/seal/list", http.StatusSeeOther)
}

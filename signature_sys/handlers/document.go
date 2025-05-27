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
	"strconv"

	"github.com/google/uuid"
	"github.com/pdfcpu/pdfcpu/pkg/api"
)

// DocumentUploadHandler 处理PDF文档上传页面和上传逻辑
// GET: 渲染上传页面
// POST: 处理PDF上传，计算哈希，保存文件，写入数据库
func DocumentUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 渲染上传页面
		t, _ := template.ParseFiles("templates/document_upload.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		// 处理文件上传
		file, header, err := r.FormFile("pdf") // 获取上传的PDF文件和文件头
		if err != nil {
			http.Error(w, "文件上传失败", 400)
			return
		}
		defer file.Close() // 关闭文件句柄，防止资源泄漏

		// 计算PDF哈希值，用于唯一标识文件
		hasher := sha256.New()            // 新建SHA256哈希器
		tee := io.TeeReader(file, hasher) // tee用于边读边哈希

		// 创建保存目录
		os.MkdirAll("static/docs", 0755) // 确保目录存在

		// 生成文档唯一ID并保存文件
		docID := uuid.New().String()                                                 // 生成唯一文档ID
		pdfPath := filepath.Join("static/docs", docID+filepath.Ext(header.Filename)) // 拼接PDF保存路径
		out, err := os.Create(pdfPath)                                               // 创建PDF文件
		if err != nil {
			http.Error(w, "保存PDF失败", 500)
			return
		}
		defer out.Close() // 关闭输出文件
		io.Copy(out, tee) // 写入PDF并计算哈希

		// 计算文件哈希值
		fileHash := hex.EncodeToString(hasher.Sum(nil)) // 获取PDF哈希值

		// 获取当前登录用户ID
		userID, _ := middleware.GetCurrentUser(r)
		if userID == "" {
			http.Error(w, "请先登录", 401)
			return
		}

		// 将文档信息写入数据库，增加OriginalName字段
		_, err = config.DB.Exec("INSERT INTO [Document] (DocID, UserID, FileHash, Location, OriginalName) VALUES (@p1, @p2, @p3, @p4, @p5)", docID, userID, fileHash, pdfPath, header.Filename)
		if err != nil {
			http.Error(w, "数据库写入失败", 500)
			return
		}

		// 返回上传成功信息，重定向到首页
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// DocumentListHandler 展示当前用户所有PDF文档列表
func DocumentListHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// 查询用户的所有文档
	rows, err := config.DB.Query("SELECT DocID, FileHash, Location, OriginalName FROM [Document] WHERE UserID=@p1", userID)
	if err != nil {
		http.Error(w, "数据库查询失败", 500)
		return
	}
	defer rows.Close() // 关闭结果集

	// 构造文档列表，包含原始文件名
	var docs []struct {
		DocID        string // 文档ID
		FileHash     string // 文件哈希
		Location     string // 文件路径
		OriginalName string // 原始文件名
	}
	for rows.Next() {
		var d struct {
			DocID        string
			FileHash     string
			Location     string
			OriginalName string
		}
		rows.Scan(&d.DocID, &d.FileHash, &d.Location, &d.OriginalName)
		docs = append(docs, d)
	}

	// 渲染文档列表页面
	t, _ := template.ParseFiles("templates/document_list.html")
	t.Execute(w, map[string]interface{}{"Docs": docs})
}

// DocumentDeleteHandler 删除PDF文档（仅POST，校验用户，删除数据库记录和PDF文件）
func DocumentDeleteHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// 校验请求方法
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST", 405)
		return
	}

	// 获取文档ID
	docID := r.FormValue("doc_id")
	if docID == "" {
		http.Error(w, "参数错误", 400)
		return
	}

	// 查询文件路径
	var pdfPath string
	err := config.DB.QueryRow("SELECT Location FROM [Document] WHERE DocID=@p1 AND UserID=@p2", docID, userID).Scan(&pdfPath)
	if err != nil {
		http.Error(w, "未找到文档", 404)
		return
	}

	// 删除数据库记录
	_, err = config.DB.Exec("DELETE FROM [Document] WHERE DocID=@p1 AND UserID=@p2", docID, userID)
	if err != nil {
		http.Error(w, "数据库删除失败", 500)
		return
	}

	// 删除文件（忽略删除失败）
	os.Remove(pdfPath)

	// 重定向到文档列表页面
	http.Redirect(w, r, "/document/list", http.StatusSeeOther)
}

// SignPDFPreviewHandler PDF签章预览接口（生成临时PDF，不保存数据库）
// POST: 根据参数生成带签章的预览PDF，返回预览路径
func SignPDFPreviewHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Error(w, "请先登录", 401)
		return
	}

	// 校验请求方法
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST", 405)
		return
	}

	// 获取文档ID和签章ID及参数
	docID := r.FormValue("doc_id")      // 文档ID
	sealID := r.FormValue("seal_id")    // 签章ID
	scale := r.FormValue("scale")       // 缩放比例
	rotation := r.FormValue("rotation") // 旋转角度

	// 查询PDF和签章图片路径
	var pdfPath, sealPath string
	err := config.DB.QueryRow("SELECT Location FROM [Document] WHERE DocID=@p1 AND UserID=@p2", docID, userID).Scan(&pdfPath)
	if err != nil {
		http.Error(w, "未找到PDF", 404)
		return
	}
	err = config.DB.QueryRow("SELECT Location FROM [Seal] WHERE SealID=@p1 AND UserID=@p2", sealID, userID).Scan(&sealPath)
	if err != nil {
		http.Error(w, "未找到签章图片", 404)
		return
	}

	// 生成临时预览PDF路径
	outputPath := pdfPath + ".preview.pdf"

	// 解析参数
	s, _ := strconv.ParseFloat(scale, 64)     // 缩放比例
	rf, _ := strconv.ParseFloat(rotation, 64) // 旋转角度

	// 构造pdfcpu图片水印参数字符串
	wmParam := fmt.Sprintf("pos:bl, scale:%.2f, rot:%.2f", s, rf)

	// 盖章
	err = api.AddImageWatermarksFile(
		pdfPath,    // 输入PDF
		outputPath, // 输出PDF
		nil,        // 选中页（nil为全部）
		false,      // 单独处理每页（false即可）
		sealPath,   // 图片路径
		wmParam,    // 水印参数
		nil,        // 配置
	)
	if err != nil {
		http.Error(w, "PDF预览生成失败:"+err.Error(), 500)
		return
	}

	// 返回静态路径（去掉static/前缀）
	previewURL := "/" + outputPath
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"preview_url": "%s"}`, previewURL)
}

// VerifyPDFPageHandler PDF验签页面，展示用户证书列表，区分ECC和RSA，渲染验签页面
func VerifyPDFPageHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// 查询用户证书，直接使用Algo字段
	certRows, err := config.DB.Query("SELECT CertID, Location, Algo FROM [Cert] WHERE UserID=@p1", userID)
	if err != nil {
		// Handle error appropriately, perhaps return an empty list or an error page
		fmt.Println("查询用户证书失败:", err)
		// For now, just proceed with potentially empty certs slice
	}
	defer certRows.Close()

	var certs []struct{ CertID, Location, Algo string }
	for certRows.Next() {
		var c struct{ CertID, Location, Algo string }
		err := certRows.Scan(&c.CertID, &c.Location, &c.Algo)
		if err != nil {
			fmt.Println("扫描证书数据失败:", err)
			continue // Skip this row and continue with the next
		}
		certs = append(certs, c)
	}

	// 渲染验签页面
	t, err := template.ParseFiles("templates/verify_pdf.html")
	if err != nil {
		http.Error(w, "加载模板失败", 500)
		fmt.Println("加载模板失败:", err)
		return
	}
	t.Execute(w, map[string]interface{}{"Certs": certs})
}

package handlers

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"signature_sys/config"
	"signature_sys/middleware"
	"signature_sys/utils"
	"strconv"

	"github.com/google/uuid"
	"github.com/pdfcpu/pdfcpu/pkg/api"
)

// PDF文档上传页面和处理
func DocumentUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		t, _ := template.ParseFiles("templates/document_upload.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		file, header, err := r.FormFile("pdf")
		if err != nil {
			http.Error(w, "文件上传失败", 400)
			return
		}
		defer file.Close()
		// 计算PDF哈希
		hasher := sha256.New()
		tee := io.TeeReader(file, hasher)
		os.MkdirAll("static/docs", 0755)
		docID := uuid.New().String()
		pdfPath := filepath.Join("static/docs", docID+filepath.Ext(header.Filename))
		out, err := os.Create(pdfPath)
		if err != nil {
			http.Error(w, "保存PDF失败", 500)
			return
		}
		defer out.Close()
		io.Copy(out, tee)
		fileHash := hex.EncodeToString(hasher.Sum(nil))
		userID, _ := middleware.GetCurrentUser(r)
		if userID == "" {
			http.Error(w, "请先登录", 401)
			return
		}
		_, err = config.DB.Exec("INSERT INTO [Document] (DocID, UserID, FileHash, Location) VALUES (@p1, @p2, @p3, @p4)", docID, userID, fileHash, pdfPath)
		if err != nil {
			http.Error(w, "数据库写入失败", 500)
			return
		}
		fmt.Fprintf(w, "上传成功，文档哈希：%s", fileHash)
	}
}

// PDF文档列表页面
func DocumentListHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	rows, err := config.DB.Query("SELECT DocID, FileHash, Location FROM [Document] WHERE UserID=@p1", userID)
	if err != nil {
		http.Error(w, "数据库查询失败", 500)
		return
	}
	defer rows.Close()
	var docs []struct {
		DocID    string
		FileHash string
		Location string
	}
	for rows.Next() {
		var d struct {
			DocID    string
			FileHash string
			Location string
		}
		rows.Scan(&d.DocID, &d.FileHash, &d.Location)
		docs = append(docs, d)
	}
	t, _ := template.ParseFiles("templates/document_list.html")
	t.Execute(w, map[string]interface{}{"Docs": docs})
}

// 删除PDF文档
func DocumentDeleteHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST", 405)
		return
	}
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
	// 删除文件
	os.Remove(pdfPath)
	http.Redirect(w, r, "/document/list", http.StatusSeeOther)
}

// 签章页面（表单）
func SignPDFPageHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// 查询用户文档
	docsRows, _ := config.DB.Query("SELECT DocID, Location FROM [Document] WHERE UserID=@p1", userID)
	var docs []struct{ DocID, Location string }
	for docsRows.Next() {
		var d struct{ DocID, Location string }
		docsRows.Scan(&d.DocID, &d.Location)
		docs = append(docs, d)
	}
	docsRows.Close()
	// 查询用户签章图片
	sealsRows, _ := config.DB.Query("SELECT SealID, Location FROM [Seal] WHERE UserID=@p1", userID)
	var seals []struct{ SealID, Location string }
	for sealsRows.Next() {
		var s struct{ SealID, Location string }
		sealsRows.Scan(&s.SealID, &s.Location)
		seals = append(seals, s)
	}
	sealsRows.Close()
	t, _ := template.ParseFiles("templates/sign_pdf.html")
	t.Execute(w, map[string]interface{}{"Docs": docs, "Seals": seals})
}

// PDF文档签章处理（实际盖章）
func SignPDFHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST", 405)
		return
	}
	docID := r.FormValue("doc_id")
	sealID := r.FormValue("seal_id")
	posX := r.FormValue("pos_x")
	posY := r.FormValue("pos_y")
	scale := r.FormValue("scale")
	rotation := r.FormValue("rotation")
	pin := r.FormValue("pin")
	// 校验PIN码
	var pinHash string
	err := config.DB.QueryRow("SELECT PINHash FROM [User] WHERE UserID=@p1", userID).Scan(&pinHash)
	if err != nil || !utils.CheckPassword(pin, pinHash) {
		http.Error(w, "PIN码错误", 401)
		return
	}
	// 获取PDF和图片路径
	var pdfPath, sealPath string
	err = config.DB.QueryRow("SELECT Location FROM [Document] WHERE DocID=@p1 AND UserID=@p2", docID, userID).Scan(&pdfPath)
	if err != nil {
		http.Error(w, "未找到PDF", 404)
		return
	}
	err = config.DB.QueryRow("SELECT Location FROM [Seal] WHERE SealID=@p1 AND UserID=@p2", sealID, userID).Scan(&sealPath)
	if err != nil {
		http.Error(w, "未找到签章图片", 404)
		return
	}
	// 生成新PDF路径
	var outputPath string
	// pdfcpu图片水印参数说明：dx, dy 单位是points（1/72英寸），pos:bl表示以左下角为锚点
	// 预览时生成临时PDF，签章时生成正式PDF
	preview := r.FormValue("preview") == "1"
	if preview {
		outputPath = pdfPath + ".preview.pdf"
	} else {
		outputPath = pdfPath + ".signed.pdf"
	}
	// 解析参数
	s, _ := strconv.ParseFloat(scale, 64)
	rf, _ := strconv.ParseFloat(rotation, 64)
	x, _ := strconv.ParseFloat(posX, 64)
	y, _ := strconv.ParseFloat(posY, 64)
	// 构造pdfcpu图片水印参数字符串（兼容老版本pdfcpu，使用dx/dy）
	wmParam := fmt.Sprintf("pos:bl, scale:%.2f, rot:%.2f, dx:%.2f, dy:%.2f", s, rf, x, y)
	// 盖章（叠加图片水印）
	err = api.AddImageWatermarksFile(
		pdfPath,
		outputPath,
		nil,
		false,
		sealPath,
		wmParam,
		nil,
	)
	if err != nil {
		http.Error(w, "PDF盖章失败:"+err.Error(), 500)
		return
	}
	if preview {
		// 预览时直接返回预览PDF路径
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"preview":"/%s"}`, outputPath)
		return
	}
	// 数字签名部分：对签章后PDF做SHA256哈希并用RSA私钥签名
	// 1. 读取签章后PDF内容
	pdfFile, err := os.Open(outputPath)
	if err != nil {
		http.Error(w, "签章PDF读取失败", 500)
		return
	}
	hasher := sha256.New()
	io.Copy(hasher, pdfFile)
	pdfFile.Close()
	hashSum := hasher.Sum(nil)
	// 2. 读取本地RSA私钥（测试用，后续支持用户上传/绑定）
	privKeyPath := "config/test_rsa_private.pem"
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		http.Error(w, "读取私钥失败", 500)
		return
	}
	block, _ := pem.Decode(privKeyData)
	if block == nil {
		http.Error(w, "私钥解析失败", 500)
		return
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "私钥格式错误", 500)
		return
	}
	// 3. 用私钥对哈希签名
	signature, err := rsa.SignPKCS1v15(nil, privKey, crypto.SHA256, hashSum)
	if err != nil {
		http.Error(w, "签名失败", 500)
		return
	}
	signatureHex := hex.EncodeToString(signature)
	// 4. 写入签章日志（假设SignLog表有SignatureValue、SignAlgo字段）
	_, err = config.DB.Exec("INSERT INTO [SignLog] (DocID, UserID, SealID, PositionX, PositionY, Scale, Rotation, SignatureValue, SignAlgo, SignTime) VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,GETDATE())",
		docID, userID, sealID, x, y, s, int(rf), signatureHex, "RSA-SHA256")
	if err != nil {
		http.Error(w, "签章日志写入失败", 500)
		return
	}
	fmt.Fprintf(w, "签章成功，已生成新PDF：<a href='/%s' target='_blank'>下载/预览</a>", outputPath)
}

// PDF签章预览接口（生成临时PDF，不保存数据库）
func SignPDFPreviewHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		http.Error(w, "请先登录", 401)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST", 405)
		return
	}
	docID := r.FormValue("doc_id")
	sealID := r.FormValue("seal_id")
	posX := r.FormValue("pos_x")
	posY := r.FormValue("pos_y")
	scale := r.FormValue("scale")
	rotation := r.FormValue("rotation")
	// 获取PDF和图片路径
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
	s, _ := strconv.ParseFloat(scale, 64)
	rf, _ := strconv.ParseFloat(rotation, 64)
	x, _ := strconv.ParseFloat(posX, 64)
	y, _ := strconv.ParseFloat(posY, 64)
	// 构造pdfcpu图片水印参数字符串（兼容老版本pdfcpu，使用dx/dy）
	wmParam := fmt.Sprintf("pos:bl, scale:%.2f, rot:%.2f, dx:%.2f, dy:%.2f", s, rf, x, y)
	// 盖章（叠加图片水印）
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

// 签章验证页面和处理
func VerifyPDFHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		t, _ := template.ParseFiles("templates/verify_pdf.html")
		t.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		file, header, err := r.FormFile("pdf")
		if err != nil {
			http.Error(w, "文件上传失败", 400)
			return
		}
		defer file.Close()
		// 保存临时文件
		tmpPath := filepath.Join("static/docs", "verify_"+header.Filename)
		out, err := os.Create(tmpPath)
		if err != nil {
			http.Error(w, "保存临时文件失败", 500)
			return
		}
		defer out.Close()
		io.Copy(out, file)
		// 计算哈希
		f, _ := os.Open(tmpPath)
		hasher := sha256.New()
		io.Copy(hasher, f)
		f.Close()
		fileHash := hex.EncodeToString(hasher.Sum(nil))
		// 查询签章记录
		rows, err := config.DB.Query("SELECT UserID, SealID, PositionX, PositionY, Scale, Rotation, SignTime FROM [SignLog] WHERE DocID IN (SELECT DocID FROM [Document] WHERE FileHash=@p1)", fileHash)
		if err != nil {
			http.Error(w, "数据库查询失败", 500)
			return
		}
		defer rows.Close()
		var logs []struct {
			UserID    string
			SealID    string
			SealPath  string
			PositionX float64
			PositionY float64
			Scale     float64
			Rotation  int
			SignTime  string
		}
		for rows.Next() {
			var userID, sealID, signTime, sealPath string
			var posX, posY, scale float64
			var rotation int
			rows.Scan(&userID, &sealID, &posX, &posY, &scale, &rotation, &signTime)
			config.DB.QueryRow("SELECT Location FROM [Seal] WHERE SealID=@p1", sealID).Scan(&sealPath)
			logs = append(logs, struct {
				UserID    string
				SealID    string
				SealPath  string
				PositionX float64
				PositionY float64
				Scale     float64
				Rotation  int
				SignTime  string
			}{
				UserID:    userID,
				SealID:    sealID,
				SealPath:  sealPath,
				PositionX: posX,
				PositionY: posY,
				Scale:     scale,
				Rotation:  rotation,
				SignTime:  signTime,
			})
		}
		t, _ := template.ParseFiles("templates/verify_pdf.html")
		t.Execute(w, map[string]interface{}{"SignLogs": logs})
		os.Remove(tmpPath)
	}
}

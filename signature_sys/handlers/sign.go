package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"signature_sys/config"
	"signature_sys/middleware"
	"signature_sys/utils"
	"strconv"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// 实现了PDF签章相关的HTTP处理逻辑，包括签章页面、签章处理、证书/签章/文档选择等。
// 涉及PDF水印、签名算法、参数校验、数据库操作、路径处理、前后端JSON通信等。

// 签章页面（表单）
// 展示当前用户所有文档、签章图片、证书，渲染签章表单
func SignPDFPageHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		// 如果未登录，重定向到登录页面
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// 查询用户文档，带原始文件名
	docsRows, _ := config.DB.Query("SELECT DocID, Location, OriginalName FROM [Document] WHERE UserID=@p1", userID)
	var docs []struct{ DocID, Location, OriginalName string }
	for docsRows.Next() {
		var d struct{ DocID, Location, OriginalName string }
		docsRows.Scan(&d.DocID, &d.Location, &d.OriginalName)
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
	// 查询用户证书，直接用Algo字段
	certRows, _ := config.DB.Query("SELECT CertID, Location, Algo FROM [Cert] WHERE UserID=@p1", userID)
	var certs []struct{ CertID, Location, Algo string }
	for certRows.Next() {
		var c struct{ CertID, Location, Algo string }
		certRows.Scan(&c.CertID, &c.Location, &c.Algo)
		certs = append(certs, c)
	}
	certRows.Close()
	// 渲染HTML模板，传递文档、签章图片、证书数据
	t, _ := template.ParseFiles("templates/sign_pdf.html")
	t.Execute(w, map[string]interface{}{"Docs": docs, "Seals": seals, "Certs": certs})
}

// PDF文档签章处理
// POST: 校验PIN码，获取PDF/图片/证书路径，生成签章PDF，返回JSON响应
func SignPDFHandler(w http.ResponseWriter, r *http.Request) {
	// 获取当前登录用户ID
	userID, _ := middleware.GetCurrentUser(r)
	if userID == "" {
		// 如果未登录，重定向到登录页面
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// 仅支持POST请求
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"msg":"仅支持POST"}`)
		return
	}
	// 获取表单参数
	docID := r.FormValue("doc_id")      // 文档ID
	sealID := r.FormValue("seal_id")    // 签章图片ID
	scale := r.FormValue("scale")       // 缩放比例
	rotation := r.FormValue("rotation") // 旋转角度
	certID := r.FormValue("cert_id")    // 证书ID
	pin := r.FormValue("pin")           // PIN码
	page := r.FormValue("page")         // 页码
	posX := r.FormValue("pos_x")        // X坐标
	posY := r.FormValue("pos_y")        // Y坐标

	// fmt.Printf("[SignPDFHandler] docID=%s, sealID=%s, scale=%s, rotation=%s, certID=%s, pin=%s, page=%s, posX=%s, posY=%s\n", docID, sealID, scale, rotation, certID, pin, page, posX, posY)

	// 校验PIN码
	var pinHash string
	err := config.DB.QueryRow("SELECT PINHash FROM [User] WHERE UserID=@p1", userID).Scan(&pinHash)
	if err != nil || !utils.CheckPassword(pin, pinHash) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] PIN码校验失败:", err)
		fmt.Fprintf(w, `{"success":false,"msg":"PIN码错误"}`)
		return
	}
	// 获取PDF和图片路径
	var pdfPath, sealPath string
	err = config.DB.QueryRow("SELECT Location FROM [Document] WHERE DocID=@p1 AND UserID=@p2", docID, userID).Scan(&pdfPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] 未找到PDF:", err)
		fmt.Fprintf(w, `{"success":false,"msg":"未找到PDF"}`)
		return
	}
	err = config.DB.QueryRow("SELECT Location FROM [Seal] WHERE SealID=@p1 AND UserID=@p2", sealID, userID).Scan(&sealPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] 未找到签章图片:", err)
		fmt.Fprintf(w, `{"success":false,"msg":"未找到签章图片"}`)
		return
	}
	// 获取证书路径
	var certPath string
	err = config.DB.QueryRow("SELECT Location FROM [Cert] WHERE CertID=@p1 AND UserID=@p2", certID, userID).Scan(&certPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] 未找到证书:", err)
		fmt.Fprintf(w, `{"success":false,"msg":"未找到证书"}`)
		return
	}
	// 生成新PDF路径
	var outputPath string
	preview := r.FormValue("preview") == "1" // 是否预览
	if preview {
		outputPath = pdfPath + ".preview.pdf"
	} else {
		outputPath = pdfPath + "img.pdf"
	}
	// 解析参数
	s, _ := strconv.ParseFloat(scale, 64)     // 缩放比例
	rf, _ := strconv.ParseFloat(rotation, 64) // 旋转角度
	pageNum := page                           // 页码
	x, _ := strconv.ParseFloat(posX, 64)      // X坐标
	y, _ := strconv.ParseFloat(posY, 64)      // Y坐标
	// 构造水印参数，使用相对位置，offset 用空格分隔两个数值
	wmParam := fmt.Sprintf("pos:bl,offset:%d %d,scale:%.2f,rot:%.2f", int(x), int(y), s, rf)
	conf := model.NewDefaultConfiguration()
	err = api.AddImageWatermarksFile(
		pdfPath,
		outputPath,
		[]string{pageNum}, // 只在选定的页面添加水印
		false,             // 单独处理每页
		sealPath,
		wmParam,
		conf,
	)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] PDF盖章失败:", err)
		fmt.Fprintf(w, `{"success":false,"msg":"PDF盖章失败: %s"}`, err.Error())
		return
	}
	if preview {
		// 如果是预览模式，直接返回预览PDF路径
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"preview":"/%s"}`, outputPath)
		return
	}

	// ----------- PDF签名域定义（签名前必须有签名域） --------------
	// 生成带签名域的PDF，供后续数字签名使用
	withFieldPath := outputPath[:len(certPath)-7] + "addfield.pdf"
	sigFieldName := "Signature1" // 签名域名称，可自定义
	// 读取印章图片宽高（像素），如需可用于签名域定位
	sealFile, err := os.Open(sealPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"msg":"无法打开印章图片: %s"}`, err.Error())
		return
	}
	// 可选：解析图片尺寸（如需精确定位签名域）
	// imgCfg, _, err := image.DecodeConfig(sealFile)
	sealFile.Close()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"msg":"无法解析印章图片: %s"}`, err.Error())
		return
	}
	// 签名域区域参数（此处为不可见签名域，可根据需要调整为可见并精确定位）
	fieldSpec := fmt.Sprintf("%s/%d,%d,%d,%d/%s", pageNum, 0, 0, 0, 0, sigFieldName)
	cmdField := exec.Command(
		"pyhanko", "sign", "addfields",
		"--field", fieldSpec,
		outputPath, withFieldPath,
	)
	if out, err := cmdField.CombinedOutput(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] 创建签名域失败:", err, string(out))
		fmt.Fprintf(w, `{"success":false,"msg":"创建签名域失败: %s, %s"}`, err.Error(), string(out))
		return
	}
	outputPath = withFieldPath

	// ----------- PDF数字签名（标准PDF签名，写入PDF结构） --------------
	privPath := certPath[:len(certPath)-4] + "_private.pem"
	signedPath := outputPath[:len(certPath)-12] + ".signed.pdf"
	cmd := exec.Command(
		"pyhanko", "sign", "addsig", "pemder",
		"--cert", certPath,
		"--key", privPath,
		"--no-pass",
		outputPath, signedPath,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] PDF数字签名失败:", err, string(out))
		fmt.Fprintf(w, `{"success":false,"msg":"PDF数字签名失败: %s, %s"}`, err.Error(), string(out))
		return
	}

	// 计算签名后PDF的哈希
	pdfFile, err := os.Open(signedPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] 签章PDF读取失败:", err)
		fmt.Fprintf(w, `{"success":false,"msg":"签章PDF读取失败"}`)
		return
	}
	hasher := sha256.New()
	io.Copy(hasher, pdfFile)
	pdfFile.Close()
	hashSum := hasher.Sum(nil)
	fileHash := hex.EncodeToString(hashSum)
	// 更新[Document]表的FileHash字段
	_, err = config.DB.Exec("UPDATE [Document] SET FileHash=@p1 WHERE DocID=@p2", fileHash, docID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("[SignPDFHandler] 更新文档哈希失败:", err)
		fmt.Fprintf(w, `{"success":false,"msg":"更新文档哈希失败"}`)
		return
	}

	// 写入签章日志（不存储签名值）
	_, err = config.DB.Exec(`INSERT INTO SignLog 
    	(UserID, DocID, SealID, CertID, SignAlgorithm, SignatureValue, PositionX, PositionY, Scale, Rotation, SignTime) 
    	VALUES (@p1, @p2, @p3, @p4, @p5, NULL, @p6, @p7, @p8, @p9, GETDATE())`,
		userID, docID, sealID, certID, "pyHanko", x, y, s, int(rf))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"msg":"签章日志写入失败"}`)
		return
	}
	// 返回成功响应，始终返回JSON格式
	w.Header().Set("Content-Type", "application/json")
	pdfUrl := "/" + strings.ReplaceAll(signedPath, "\\", "/")
	resp := map[string]interface{}{
		"success": true,
		"msg":     "签章成功，已生成新PDF",
		"pdf_url": pdfUrl,
	}
	jsonStr, _ := json.Marshal(resp)
	fmt.Fprint(w, string(jsonStr))
}

package handlers

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"signature_sys/config"
)

// VerifyPDFHandler 处理PDF验签请求
// 前端上传PDF和证书ID，后端查找证书，调用pyHanko命令行进行PDF数字签名验签，返回验签结果
func VerifyPDFHandler(w http.ResponseWriter, r *http.Request) {
	// 只允许POST请求，确保接口安全性
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST", 405)
		return
	}
	// 获取上传的PDF文件，使用FormFile方法解析multipart/form-data
	file, _, err := r.FormFile("pdf")
	if err != nil {
		http.Error(w, "PDF文件上传失败", 400)
		return
	}
	defer file.Close() // 关闭文件句柄，防止资源泄漏
	// 获取证书ID，确保前端传递了必要参数
	certID := r.FormValue("cert_id")
	if certID == "" {
		http.Error(w, "证书ID缺失", 400)
		return
	}
	// 计算PDF哈希（SHA256），用于后续签名验证（可选，便于日志或溯源）
	hasher := sha256.New()
	pdfBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "读取PDF失败", 500)
		return
	}
	hasher.Write(pdfBytes)
	// 将上传的PDF保存为临时文件，供pyHanko命令行使用
	tmpPdf := "verify_tmp.pdf"
	os.WriteFile(tmpPdf, pdfBytes, 0644)
	// 查找证书路径，从数据库中获取证书文件的存储位置
	var certPath string
	err = config.DB.QueryRow("SELECT Location FROM [Cert] WHERE CertID=@p1", certID).Scan(&certPath)
	if err != nil {
		http.Error(w, "未找到证书", 404)
		return
	}
	// 读取证书文件，解析PEM格式，确保证书文件有效
	certData, err := os.ReadFile(certPath)
	if err != nil {
		http.Error(w, "读取证书文件失败", 500)
		return
	}
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		http.Error(w, "证书文件格式错误", 500)
		return
	}
	// 用pyHanko命令行直接验签，--no-strict-syntax参数可兼容部分PDF语法问题
	cmd := exec.Command("pyhanko", "sign", "validate", tmpPdf, "--trust", certPath, "--no-strict-syntax")
	verifyOut, err := cmd.CombinedOutput()
	println("[VerifyPDFHandler] pyHanko输出:", string(verifyOut))
	os.Remove(tmpPdf) // 删除临时文件，保持环境整洁
	// 处理验签结果，返回提示
	if err != nil {
		w.WriteHeader(200)
		fmt.Fprintf(w, "验签失败！")
		return
	}
	w.WriteHeader(200)
	fmt.Fprintf(w, "验签成功！")
}

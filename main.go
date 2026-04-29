package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/wuyuhang/midun/audit"
	"github.com/wuyuhang/midun/vc"
	"github.com/wuyuhang/midun/zkp"
)

// 全局凭证存储
var credStore = vc.NewCredentialStore()
var auditLog = audit.NewAuditLog()

// 统一响应结构体
type Response struct {
	Status  string `json:"status,omitempty"`
	Valid   bool   `json:"valid,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ZKP验证请求结构体
type ZKPVerifyRequest struct {
	Proof        string   `json:"proof"`
	PublicInputs []string `json:"public_inputs"`
}

// VC 签发请求结构体 (不再包含 Attributes，由后端自动生成)
type VCIssueRequest struct {
	UserID       string   `json:"user_id"`
	Proof        string   `json:"proof"`
	PublicInputs []string `json:"public_inputs"`
}

// 全局配置常量
const (
	VerificationKeyPath = "./zkp-circuit/verification.key"
	ValidAPIKey         = "midun-dev-key-2026"
)

// 生成随机临时文件路径，避免并发冲突
func tempProofPath() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "./tmp_proof_" + hex.EncodeToString(b) + ".json"
}

// 健康检查接口
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Status: "ok"})
}

// 根路径处理
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Error: "not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Status: "ok", Message: "密盾服务在线"})
}

// VC 签发接口处理函数
func handleVCIssue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}

	var req VCIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "invalid request body"})
		return
	}

	if req.UserID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "user_id cannot be empty"})
		return
	}

	// 强制验证 ZKP 证明，失败则直接拒绝签发
	tmpPath := tempProofPath()
	if err := os.WriteFile(tmpPath, []byte(req.Proof), 0600); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "invalid proof"})
		return
	}
	defer os.Remove(tmpPath)

	validProof, err := zkp.VerifyAgeProof(tmpPath, VerificationKeyPath)
	if err != nil || !validProof {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "zkp verification failed, credential issuance denied"})
		return
	}

	// 验证通过后，由后端根据验证结果自动生成声明
	verifiedAttributes := map[string]interface{}{
		"verified": "age_over_18",
	}

	cred, err := vc.IssueCredential(req.UserID, verifiedAttributes)
	if err != nil {
		log.Printf("VC issuance error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "credential issuance failed: " + err.Error()})
		return
	}

	if !vc.VerifyCredential(cred) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "credential verification failed after issuance"})
		return
	}

	credStore.Save(cred)
	auditLog.Record(req.UserID, "ISSUE", "credential issued")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cred)
}

// ZKP 验证接口处理函数
func handleZKPVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}

	var req ZKPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "invalid request body"})
		return
	}

	if req.Proof == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "proof cannot be empty"})
		return
	}

	tmpPath := tempProofPath()
	if err := os.WriteFile(tmpPath, []byte(req.Proof), 0600); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "failed to process proof"})
		return
	}
	defer os.Remove(tmpPath)

	valid, err := zkp.VerifyAgeProof(tmpPath, VerificationKeyPath)
	if err != nil {
		log.Printf("ZKP verification error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "proof verification failed: " + err.Error()})
		return
	}

	if valid {
		json.NewEncoder(w).Encode(Response{Valid: true, Message: "zkp verification passed"})
	} else {
		json.NewEncoder(w).Encode(Response{Valid: false, Message: "zkp verification failed"})
	}
}

// VC 凭证列表查询
func handleVCList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}
	creds := credStore.List()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(creds)
}

// VC 单个凭证查询
func handleVCGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}
	userID := r.URL.Path[len("/v1/vc/credentials/"):]
	if userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "user_id is required"})
		return
	}
	cred := credStore.Get(userID)
	if cred == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Error: "credential not found"})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cred)
}

// VC 凭证吊销
func handleVCDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}
	userID := r.URL.Path[len("/v1/vc/credentials/"):]
	if userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "user_id is required"})
		return
	}
	if credStore.Delete(userID) {
		auditLog.Record(userID, "REVOKE", "credential revoked")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{Message: "credential revoked"})
	} else {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Error: "credential not found"})
	}
}

// API Key 认证中间件
func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(Response{Error: "missing X-API-Key header"})
			return
		}
		if apiKey != ValidAPIKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(Response{Error: "invalid X-API-Key"})
			return
		}
		next(w, r)
	}
}

// 审计日志查询
func handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}
	logs := auditLog.List()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(logs)
}

// 审计链验证
func handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}
	valid := auditLog.VerifyChain()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Valid: valid, Message: "audit chain integrity check"})
}

// CORS 中间件
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// VC 验证接口处理函数
func handleVCVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}

	var cred vc.Credential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "invalid request body"})
		return
	}

	result := "failed"
	if vc.VerifyCredential(&cred) {
		result = "passed"
	}
	auditLog.Record(cred.UserID, "VC_VERIFY", "verification result: "+result)

	if result == "passed" {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{Valid: true, Message: "credential verified"})
	} else {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{Valid: false, Message: "credential verification failed"})
	}
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/health", corsMiddleware(handleHealth))
	mux.HandleFunc("/v1/zkp/verify", corsMiddleware(apiKeyMiddleware(handleZKPVerify)))
	mux.HandleFunc("/v1/vc/issue", corsMiddleware(apiKeyMiddleware(handleVCIssue)))
	mux.HandleFunc("/v1/vc/verify", corsMiddleware(apiKeyMiddleware(handleVCVerify)))
	mux.HandleFunc("/v1/audit/logs", corsMiddleware(apiKeyMiddleware(handleAuditLogs)))
	mux.HandleFunc("/v1/audit/verify", corsMiddleware(apiKeyMiddleware(handleAuditVerify)))

	mux.HandleFunc("/v1/vc/credentials", corsMiddleware(apiKeyMiddleware(handleVCList)))
	mux.HandleFunc("/v1/vc/credentials/", corsMiddleware(apiKeyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handleVCGet(w, r)
		case "DELETE":
			handleVCDelete(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		}
	})))

	addr := "0.0.0.0:8090"
	log.Printf("密盾 API 服务启动，监听 %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

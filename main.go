package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/wuyuhang/midun/zkp"
)

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

// 全局配置常量
const (
	VerificationKeyPath = "./zkp-circuit/verification.key"
	TempProofPath       = "./tmp_proof.json"
	ValidAPIKey         = "midun-dev-key-2026"
)

// 健康检查接口
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Status: "ok"})
}

// ZKP 验证接口处理函数（需要 API Key 认证）
func handleZKPVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 1. 仅接受 POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Error: "method not allowed"})
		return
	}

	// 2. 解析请求体
	var req ZKPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "invalid request body"})
		return
	}

	// 3. 校验 proof 非空
	if req.Proof == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "proof cannot be empty"})
		return
	}

	// 4. 将 proof 写入临时文件
	if err := os.WriteFile(TempProofPath, []byte(req.Proof), 0600); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "failed to process proof"})
		return
	}
	defer os.Remove(TempProofPath)

	// 5. 调用真实 ZoKrates 验证
	valid, err := zkp.VerifyAgeProof(TempProofPath, VerificationKeyPath)
	if err != nil {
		log.Printf("ZKP verification error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "proof verification failed: " + err.Error()})
		return
	}

	// 6. 返回结果
	if valid {
		json.NewEncoder(w).Encode(Response{Valid: true, Message: "zkp verification passed"})
	} else {
		json.NewEncoder(w).Encode(Response{Valid: false, Message: "zkp verification failed"})
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

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/zkp/verify", apiKeyMiddleware(handleZKPVerify))

	addr := "0.0.0.0:8090"
	log.Printf("密盾 API 服务启动，监听 %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

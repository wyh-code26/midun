package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// 请求体结构
type ZKPVerifyRequest struct {
	Proof        string   `json:"proof"`
	PublicInputs []string `json:"public_inputs"`
}

// 响应体结构
type ZKPVerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// API Key 认证中间件
func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusUnauthorized)
			return
		}
		// 临时硬编码 API Key，后续改为环境变量
		if apiKey != "midun-dev-key-2026" {
			http.Error(w, `{"error":"invalid API Key"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ZKP 验证接口处理函数
func handleZKPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ZKPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// 目前返回模拟验证通过，后续接入 ZoKrates 验证逻辑
	resp := ZKPVerifyResponse{
		Valid:   true,
		Message: "mock verification passed",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// 健康检查接口
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	mux := http.NewServeMux()

	// 健康检查（无需认证）
	mux.HandleFunc("/health", handleHealth)

	// ZKP 验证接口（需要 API Key）
	mux.HandleFunc("/v1/zkp/verify", apiKeyMiddleware(handleZKPVerify))

	addr := "0.0.0.0:8090"
	log.Printf("密盾 API 服务启动，监听 %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

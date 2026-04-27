package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// AuditEntry 审计日志条目
type AuditEntry struct {
	Timestamp   int64  `json:"timestamp"`
	UserID      string `json:"user_id"`
	Operation   string `json:"operation"`
	Detail      string `json:"detail"`
	PrevHash    string `json:"prev_hash"`
	CurrentHash string `json:"current_hash"`
}

// AuditLog 审计日志存储（链式哈希）
type AuditLog struct {
	mu    sync.RWMutex
	chain []AuditEntry
}

// NewAuditLog 创建审计日志实例
func NewAuditLog() *AuditLog {
	return &AuditLog{
		chain: make([]AuditEntry, 0),
	}
}

// Record 记录一条审计日志
func (a *AuditLog) Record(userID, operation, detail string) *AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := AuditEntry{
		Timestamp: time.Now().Unix(),
		UserID:    userID,
		Operation: operation,
		Detail:    detail,
	}

	// 链式哈希：当前哈希 = SHA256(前一块哈希 + 当前条目内容)
	if len(a.chain) > 0 {
		entry.PrevHash = a.chain[len(a.chain)-1].CurrentHash
	} else {
		entry.PrevHash = "0" // 创世块
	}

	// 计算当前条目的哈希
	payload, _ := json.Marshal(struct {
		Timestamp int64  `json:"timestamp"`
		UserID    string `json:"user_id"`
		Operation string `json:"operation"`
		Detail    string `json:"detail"`
		PrevHash  string `json:"prev_hash"`
	}{
		Timestamp: entry.Timestamp,
		UserID:    entry.UserID,
		Operation: entry.Operation,
		Detail:    entry.Detail,
		PrevHash:  entry.PrevHash,
	})
	hash := sha256.Sum256(payload)
	entry.CurrentHash = hex.EncodeToString(hash[:])

	a.chain = append(a.chain, entry)
	return &entry
}

// List 列出所有审计日志
func (a *AuditLog) List() []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]AuditEntry, len(a.chain))
	copy(result, a.chain)
	return result
}

// VerifyChain 验证整条链的完整性
func (a *AuditLog) VerifyChain() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for i := range a.chain {
		if i == 0 {
			continue
		}
		if a.chain[i].PrevHash != a.chain[i-1].CurrentHash {
			return false
		}
	}
	return true
}

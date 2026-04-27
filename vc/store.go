package vc

import (
	"sync"
)

// CredentialStore 凭证存储接口（内存实现，后续可切换 SQLite）
type CredentialStore struct {
	mu    sync.RWMutex
	creds map[string]*Credential
}

// NewCredentialStore 创建凭证存储实例
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		creds: make(map[string]*Credential),
	}
}

// Save 保存凭证
func (s *CredentialStore) Save(cred *Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[cred.UserID] = cred
}

// Get 根据 userID 获取凭证
func (s *CredentialStore) Get(userID string) *Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.creds[userID]
}

// List 列出所有凭证
func (s *CredentialStore) List() []*Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Credential, 0, len(s.creds))
	for _, cred := range s.creds {
		result = append(result, cred)
	}
	return result
}

// Delete 根据 userID 删除凭证
func (s *CredentialStore) Delete(userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.creds[userID]; exists {
		delete(s.creds, userID)
		return true
	}
	return false
}

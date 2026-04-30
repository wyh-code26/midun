package vc

import (
	"encoding/json"
	"sync"
)

type CredentialStore struct {
	mu    sync.RWMutex
	creds map[string]string
}

func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		creds: make(map[string]string),
	}
}

func (s *CredentialStore) Save(cred *Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, _ := json.Marshal(cred)
	encrypted, err := encrypt(data)
	if err != nil {
		return
	}
	s.creds[cred.UserID] = encrypted
}

func (s *CredentialStore) Get(userID string) *Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	enc, ok := s.creds[userID]
	if !ok {
		return nil
	}
	plain, err := decrypt(enc)
	if err != nil {
		return nil
	}
	var cred Credential
	_ = json.Unmarshal(plain, &cred)
	return &cred
}

func (s *CredentialStore) List() []*Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Credential, 0, len(s.creds))
	for _, enc := range s.creds {
		plain, err := decrypt(enc)
		if err != nil {
			continue
		}
		var cred Credential
		_ = json.Unmarshal(plain, &cred)
		result = append(result, &cred)
	}
	return result
}

func (s *CredentialStore) Delete(userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.creds[userID]
	if exists {
		delete(s.creds, userID)
	}
	return exists
}

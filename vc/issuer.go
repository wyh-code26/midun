package vc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

// Credential 凭证结构
type Credential struct {
	UserID     string            `json:"user_id"`
	Attributes map[string]interface{} `json:"attributes"`
	IssuedAt   int64             `json:"iat"`
	ExpiresAt  int64             `json:"exp"`
	Signature  string            `json:"signature"`
}

// IssueCredential 签发凭证
// 读取私钥 → 构建凭证 → 序列化 → 签名 → 返回
func IssueCredential(userID string, attributes map[string]interface{}) (*Credential, error) {
	// 1. 加载私钥
	privateKey, err := loadPrivateKey()
	if err != nil {
		return nil, err
	}

	// 2. 构建凭证
	now := time.Now().Unix()
	cred := &Credential{
		UserID:     userID,
		Attributes: attributes,
		IssuedAt:   now,
		ExpiresAt:  now + 3600, // 1 小时有效期
	}

	// 3. 序列化凭证（不含签名部分）
	credJSON, err := json.Marshal(struct {
		UserID     string                 `json:"user_id"`
		Attributes map[string]interface{}  `json:"attributes"`
		IssuedAt   int64                  `json:"iat"`
		ExpiresAt  int64                  `json:"exp"`
	}{
		UserID:     cred.UserID,
		Attributes: cred.Attributes,
		IssuedAt:   cred.IssuedAt,
		ExpiresAt:  cred.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}

	// 4. 签名
	hash := sha256.Sum256(credJSON)
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	// 5. 把签名附上
	cred.Signature = base64.StdEncoding.EncodeToString(sig)

	return cred, nil
}

// loadPrivateKey 从文件加载 ECDSA 私钥
func loadPrivateKey() (*ecdsa.PrivateKey, error) {
	pemData, err := os.ReadFile("vc-private.pem")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, err
	}

	// 尝试 PKCS8 格式解析
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key.(*ecdsa.PrivateKey), nil
	}

	// 回退到 SEC1 格式（EC 专用）
	return x509.ParseECPrivateKey(block.Bytes)
}

// VerifyCredential 验证凭证签名
func VerifyCredential(cred *Credential) bool {
	// 1. 加载公钥
	publicKey, err := loadPublicKey()
	if err != nil {
		return false
	}

	// 2. 序列化凭证（不含签名）
	credJSON, err := json.Marshal(struct {
		UserID     string                 `json:"user_id"`
		Attributes map[string]interface{}  `json:"attributes"`
		IssuedAt   int64                  `json:"iat"`
		ExpiresAt  int64                  `json:"exp"`
	}{
		UserID:     cred.UserID,
		Attributes: cred.Attributes,
		IssuedAt:   cred.IssuedAt,
		ExpiresAt:  cred.ExpiresAt,
	})
	if err != nil {
		return false
	}

	// 3. 解码签名
	sig, err := base64.StdEncoding.DecodeString(cred.Signature)
	if err != nil {
		return false
	}

	// 4. 验证
	hash := sha256.Sum256(credJSON)
	return ecdsa.VerifyASN1(publicKey, hash[:], sig)
}

// loadPublicKey 从文件加载 ECDSA 公钥
func loadPublicKey() (*ecdsa.PublicKey, error) {
	pemData, err := os.ReadFile("vc-public.pem")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*ecdsa.PublicKey), nil
}

// 确保 asn1 和 big 被使用（签名/验证的底层依赖）
var _ = asn1.Marshal
var _ = big.NewInt

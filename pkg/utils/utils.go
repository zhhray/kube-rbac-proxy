package utils

import (
	"crypto/tls"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// 在所有 os.ReadFile 调用前添加安全检查
func SafeReadFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)

	// 防止目录遍历攻击
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid file path")
	}

	return os.ReadFile(cleanPath)
}

func SafeInt32Convert(val uint32) (int32, error) {
	if val > math.MaxInt32 {
		return 0, fmt.Errorf("value %d exceeds max int32", val)
	}
	return int32(val), nil
}

// 创建安全的 TLS 配置模板
func CreateSecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

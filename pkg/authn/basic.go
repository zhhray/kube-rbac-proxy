package authn

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/klog/v2"
)

type BasicOAuthHandler struct {
	oidcTokenEndpoint string
	clientID          string
	clientSecret      string
	ldapID            string
	httpClient        *http.Client
}

func NewBasicOAuthHandler(oidcURL, clientID, clientSecret, ldapID string) *BasicOAuthHandler {
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
	}

	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: transCfg}
	return &BasicOAuthHandler{
		oidcTokenEndpoint: oidcURL + "/token",
		clientID:          clientID,
		clientSecret:      clientSecret,
		ldapID:            ldapID,
		httpClient:        httpClient,
	}
}

func (h *BasicOAuthHandler) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	// 1. 仅处理未携带 Bearer Token 的请求
	if HasBearerToken(req) {
		return nil, false, nil // 跳过处理，交给后续认证器
	}

	// 2. 检查是否是 Docker Registry 请求
	if !IsDockerRegistryRequest(req) {
		return nil, false, nil
	}

	// 3. 解析 Basic Auth
	username, password, ok := parseBasicAuth(req)
	if !ok {
		// 不返回错误，让后续处理返回 401
		return nil, false, nil
	}

	// 4. 获取 OIDC Token
	token, err := h.getOIDCToken(username, password)
	if err != nil {
		klog.Errorf("OIDC token exchange failed: %v", err)
		return nil, false, nil
	}

	// 5. 修改请求头并返回继续验证
	req.Header.Set("Authorization", "Bearer "+token)
	return nil, false, nil // 返回 false 以继续链式验证
}

// 解析 Basic Auth
func parseBasicAuth(r *http.Request) (string, string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return "", "", false
	}

	return creds[0], creds[1], true
}

// 调用 OIDC Token 端点
func (h *BasicOAuthHandler) getOIDCToken(username, password string) (string, error) {
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("username", username)
	form.Add("password", password)
	form.Add("scope", "openid profile offline_access email groups ext")
	if h.ldapID != "" {
		form.Add("conn_id", h.ldapID)
	}

	form.Add("client_id", h.clientID)
	form.Add("client_secret", h.clientSecret)

	req, _ := http.NewRequest("POST", h.oidcTokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("oidc token request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		BearerToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %v", err)
	}
	klog.V(5).Infof("get oidc token response: %v", tokenResp)

	return tokenResp.BearerToken, nil
}

// 判断是否为 Docker Registry 请求
func IsDockerRegistryRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/v2/") ||
		strings.HasPrefix(r.URL.Path, "/v1/") ||
		r.URL.Path == "/" // 处理根路径探测
}

// 检查是否携带 Bearer Token
func HasBearerToken(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	return strings.HasPrefix(authHeader, "Bearer ")
}

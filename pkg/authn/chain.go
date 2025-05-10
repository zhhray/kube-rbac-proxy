package authn

import (
	"context"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// 实现链式认证接口
type ChainedAuthenticator struct {
	authenticators []authenticator.Request
}

func NewChainedAuthenticator(auths ...authenticator.Request) *ChainedAuthenticator {
	return &ChainedAuthenticator{
		authenticators: auths,
	}
}

func cloneRequest(req *http.Request) *http.Request {
	reqCopy := req.Clone(context.Background())
	// 显式复制关键字段
	reqCopy.URL = &(*req.URL) // 深拷贝 URL
	reqCopy.Host = req.Host
	reqCopy.Header = make(http.Header)
	for k, v := range req.Header {
		reqCopy.Header[k] = v
	}
	return reqCopy
}

// 修改链式认证器的同步逻辑
func (c *ChainedAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	reqCopy := cloneRequest(req)
	var lastErr error

	for _, auth := range c.authenticators {
		resp, ok, err := auth.AuthenticateRequest(reqCopy)
		if ok {
			// 将修改后的 Header 同步回原始请求
			req.Header = reqCopy.Header.Clone()
			return resp, true, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	// 同步最后一次修改的 Header（即使认证失败）
	req.Header = reqCopy.Header.Clone()
	return nil, false, lastErr
}

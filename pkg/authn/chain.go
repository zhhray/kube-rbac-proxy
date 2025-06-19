package authn

import (
	"context"
	"net/http"

	"github.com/alauda/apiserver/pkg/authentication/authenticator"
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
	reqCopy.URL = &(*req.URL) // 深拷贝 URL 对象
	reqCopy.Header = req.Header.Clone()
	return reqCopy
}

// 修改链式认证器的同步逻辑
func (c *ChainedAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	// 深拷贝请求对象
	reqCopy := cloneRequest(req)
	var lastErr error

	for _, auth := range c.authenticators {
		resp, ok, err := auth.AuthenticateRequest(reqCopy)
		if ok {
			// 将修改后的 Header 同步到原始请求
			for k, vv := range reqCopy.Header {
				req.Header.Del(k) // 先删除原有 Header
				for _, v := range vv {
					req.Header.Add(k, v)
				}
			}
			return resp, true, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return nil, false, lastErr
}

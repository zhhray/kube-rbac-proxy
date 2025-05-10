package authn

import (
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

func (c *ChainedAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	for _, auth := range c.authenticators {
		resp, ok, err := auth.AuthenticateRequest(req)
		if ok {
			// 认证成功立即返回，不继续后续验证
			return resp, true, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
	return nil, false, nil
}

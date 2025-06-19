package authn

import (
	"net/http"
	"strings"

	"github.com/alauda/apiserver/pkg/authentication/authenticator"
	"github.com/alauda/apiserver/pkg/authentication/user"
	"golang.org/x/net/context"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// 新增 ServiceAccount 认证器
type ServiceAccountAuthenticator struct {
	kubeClient kubernetes.Interface
}

func NewServiceAccountAuthenticator(kubeClient kubernetes.Interface) *ServiceAccountAuthenticator {
	return &ServiceAccountAuthenticator{
		kubeClient: kubeClient,
	}
}

func (a *ServiceAccountAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	// 1. 仅处理 Bearer Token 请求
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, false, nil // 非 Bearer Token，跳过
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, false, nil // 空 Token，跳过
	}

	return verifyServiceAccountToken(req.Context(), a.kubeClient, token)
}

// 验证 ServiceAccount Token
func verifyServiceAccountToken(ctx context.Context, client kubernetes.Interface, token string) (*authenticator.Response, bool, error) {
	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := client.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		klog.Errorf("ServiceAccount TokenReview failed: %v", err)
		return nil, false, nil // 网络错误，跳过以允许其他认证器处理
	}

	if !result.Status.Authenticated {
		klog.Warning("ServiceAccount TokenReview Authenticated false")
		return nil, false, nil // Token 无效，跳过
	}

	// 4. 提取用户信息（ServiceAccount 格式为 system:serviceaccount:<namespace>:<sa-name>）
	userInfo := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   result.Status.User.Username,
			Groups: result.Status.User.Groups,
		},
	}

	klog.Infof("Authenticated ServiceAccount: %s", userInfo.User.GetName())
	return userInfo, true, nil
}

package authn

import (
	"net/http"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
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

	// 2. 调用 TokenReview API 验证 Token
	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := a.kubeClient.AuthenticationV1().TokenReviews().Create(req.Context(), tokenReview, metav1.CreateOptions{})
	if err != nil {
		klog.Errorf("ServiceAccount TokenReview failed: %v", err)
		return nil, false, nil // 网络错误，跳过以允许其他认证器处理
	}

	// 3. 检查 TokenReview 结果
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

package filters

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type NamespaceChecker struct {
	client kubernetes.Interface
}

func NewNamespaceChecker(client kubernetes.Interface) *NamespaceChecker {
	return &NamespaceChecker{
		client: client,
	}
}

// CheckNamespace 检查命名空间是否存在（带缓存）
func (n *NamespaceChecker) CheckNamespace(namespace string) (bool, error) {
	// 查询 Kubernetes API
	_, err := n.client.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check namespace: %w", err)
	}

	return true, nil
}

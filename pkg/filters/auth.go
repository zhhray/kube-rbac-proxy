/*
Copyright 2022 the kube-rbac-proxy maintainers All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package filters

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
)

func WithAuthentication(
	authReq authenticator.Request,
	audiences []string,
	handler http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if len(audiences) > 0 {
			ctx = authenticator.WithAudiences(ctx, audiences)
			req = req.WithContext(ctx)
		}

		res, ok, err := authReq.AuthenticateRequest(req)
		if err != nil {
			klog.Errorf("Unable to authenticate the request due to an error: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		req = req.WithContext(request.WithUser(req.Context(), res.User))
		handler.ServeHTTP(w, req)
	}
}

func WithAuthorization(
	authz authorizer.Authorizer,
	cfg *authz.Config,
	namespaceChecker *NamespaceChecker, // 新增参数
	handler http.HandlerFunc,
) http.HandlerFunc {
	getRequestAttributes := proxy.
		NewKubeRBACProxyAuthorizerAttributesGetter(cfg).
		GetRequestAttributes

	return func(w http.ResponseWriter, req *http.Request) {
		u, ok := request.UserFrom(req.Context())
		if !ok {
			http.Error(w, "user not in context", http.StatusBadRequest)
			return
		}

		// Get authorization attributes
		allAttrs := getRequestAttributes(u, req)
		if len(allAttrs) == 0 {
			msg := "Bad Request. The request or configuration is malformed."
			klog.V(2).Info(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		klog.Infof("will check authorization for allAttrs: %+v", allAttrs)
		for _, attrs := range allAttrs {
			res := attrs.GetResource()
			if authn.IsDockerRegistryRequest(req) {
				res = "images"
			}

			namespace := attrs.GetNamespace()
			// 检查命名空间存在性
			exists, err := namespaceChecker.CheckNamespace(namespace)
			if err != nil {
				klog.Errorf("Namespace check failed: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !exists {
				msg := fmt.Sprintf("Namespace %s does not exist", namespace)
				klog.Errorf("Namespace check failed: %s", msg)
				http.Error(w, msg, http.StatusNotFound)
				return
			}

			// Authorize
			authorized, reason, err := authz.Authorize(req.Context(), attrs)
			if err != nil {
				msg := fmt.Sprintf("Authorization error (namespace=%s, user=%s, verb=%s, resource=%s)", namespace, u.GetName(), attrs.GetVerb(), res)
				klog.Errorf("%s: %s", msg, err)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
			if authorized != authorizer.DecisionAllow {
				msg := fmt.Sprintf("Forbidden (namespace=%s, user=%s, verb=%s, resource=%s)", namespace, u.GetName(), attrs.GetVerb(), res)
				klog.V(2).Infof("%s. Reason: %q.", msg, reason)
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}

		klog.Infof("successfully check authorization for allAttrs: %+v", allAttrs)
		handler.ServeHTTP(w, req)
	}
}

// WithAuthHeaders adds identity information to the headers.
// Must not be used, if connection is not encrypted with TLS.
func WithAuthHeaders(cfg *authn.AuthnHeaderConfig, handler http.HandlerFunc) http.HandlerFunc {
	if !cfg.Enabled {
		return handler
	}

	return func(w http.ResponseWriter, req *http.Request) {
		u, ok := request.UserFrom(req.Context())
		if ok {
			// Seemingly well-known headers to tell the upstream about user's identity
			// so that the upstream can achieve the original goal of delegating RBAC authn/authz to kube-rbac-proxy
			req.Header.Set(cfg.UserFieldName, u.GetName())
			req.Header.Set(cfg.GroupsFieldName, strings.Join(u.GetGroups(), cfg.GroupSeparator))
		}

		handler.ServeHTTP(w, req)
	}
}

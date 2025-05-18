FROM build-harbor.alauda.cn/ops/distroless-static-nonroot:12-alauda-202503180545

ARG BINARY=kube-rbac-proxy-linux-amd64
COPY _output/$BINARY /usr/local/bin/kube-rbac-proxy

ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]

FROM build-harbor.alauda.cn/ops/distroless-static:20220806

ARG BINARY=kube-rbac-proxy-linux-amd64
COPY _output/$BINARY /usr/local/bin/kube-rbac-proxy
EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]

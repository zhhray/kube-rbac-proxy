FROM docker-mirrors.alauda.cn/library/golang:1.24-alpine as builder

ENV GONOSUMDB="*/*,*.*" \
    GOPROXY="https://build-nexus.alauda.cn/repository/golang/,direct"

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
COPY pkg/ pkg/
COPY cmd/ cmd/

ENV CGO_ENABLED=0
RUN go build --installsuffix cgo -o kube-rbac-proxy cmd/kube-rbac-proxy/main.go

FROM build-harbor.alauda.cn/ops/distroless-static-nonroot:12-alauda-202503180545
COPY --from=builder /workspace/kube-rbac-proxy /usr/local/bin/kube-rbac-proxy

ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]

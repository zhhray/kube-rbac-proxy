FROM docker-mirrors.alauda.cn/library/golang:1.24.4-alpine as builder

ENV GONOSUMDB="*/*,*.*" \
    GOPROXY="https://build-nexus.alauda.cn/repository/golang/,direct"

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
COPY pkg/ pkg/
COPY cmd/ cmd/

ENV CGO_ENABLED=0
RUN go build --installsuffix cgo -o kube-rbac-proxy cmd/kube-rbac-proxy/main.go

FROM build-harbor.alauda.cn/ops/alpine:3.20

RUN echo "http://mirrors.aliyun.com/alpine/edge/main" >> /etc/apk/repositories \
    && echo "http://mirrors.aliyun.com/alpine/edge/testing" >> /etc/apk/repositories \
    && echo "http://mirrors.aliyun.com/alpine/edge/community" >> /etc/apk/repositories \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk update \
    && apk upgrade \
    && apk add --no-cache ca-certificates && update-ca-certificates \
    && rm -rf /usr/bin/nc

COPY --from=builder /workspace/kube-rbac-proxy /usr/local/bin/kube-rbac-proxy

ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]

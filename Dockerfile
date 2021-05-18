# syntax = docker/dockerfile:experimental
# Build the manager binary
FROM golang:1.16-alpine as builder

ENV GRPC_HEALTH_PROBE_VERSION="v0.3.6"
RUN wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe

WORKDIR /workspace

RUN apk add --no-cache git

# Copy the Go Modules manifests
COPY go.mod go.sum /workspace/

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY config config
COPY server server
COPY proto proto

# Build
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o collector

# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot as runner
WORKDIR /
COPY --from=builder /workspace/collector .
COPY --from=builder /bin/grpc_health_probe .
USER nonroot:nonroot

ENTRYPOINT ["./collector"]

FROM golang:1.15.10-alpine3.13

ENV GO111MODULE="on"
ENV PROTOC_VERSION="3.13.0-r2"
ENV PROTOC_GEN_GO_VERSION="v1.25.0"
ENV PROTOC_GEN_GO_GRPC_VERSION="v1.0.1"
ENV PROTOC_GEN_GRPC_GATEWAY_VERSION="v2.2.0"
ENV GOOGLE_APIS_VERSION="fb6fa4cfb16917da8dc5d23c2494d422dd3e9cd4"

RUN apk update && apk add \
    protoc=${PROTOC_VERSION} \
    protobuf-dev=${PROTOC_VERSION} \
    curl \
    bash

RUN go get google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}
RUN go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}
RUN go get github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@${PROTOC_GEN_GRPC_GATEWAY_VERSION}

WORKDIR /collector

ENTRYPOINT ["/collector/scripts/generate/entrypoint.sh"]

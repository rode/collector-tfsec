FROM golang:1.17.0-alpine3.14

ENV PROTOC_VERSION="3.15.7-r1"
ENV PROTOC_GEN_GO_VERSION="v1.27.1"
ENV PROTOC_GEN_GO_GRPC_VERSION="v1.1.0"
ENV PROTOC_GEN_GRPC_GATEWAY_VERSION="v2.6.0"
ENV GOOGLE_APIS_VERSION="fb6fa4cfb16917da8dc5d23c2494d422dd3e9cd4"

RUN apk update && apk add \
    protoc=${PROTOC_VERSION} \
    protobuf-dev=${PROTOC_VERSION} \
    curl \
    bash

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}
RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@${PROTOC_GEN_GRPC_GATEWAY_VERSION}

WORKDIR /collector

ENTRYPOINT ["/collector/scripts/generate/entrypoint.sh"]

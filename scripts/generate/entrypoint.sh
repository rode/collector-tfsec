#!/usr/bin/env bash

GOOGLE_API_PROTOS_DIR="/collector/protodeps/googleapis/google/api"
GOOGLE_API_PROTOS=("annotations" "client" "field_behavior" "http" "resource")
mkdir -p ${GOOGLE_API_PROTOS_DIR}
cd ${GOOGLE_API_PROTOS_DIR}
for api in ${GOOGLE_API_PROTOS[@]} ; do
    curl --silent -LO https://raw.githubusercontent.com/googleapis/googleapis/${GOOGLE_APIS_VERSION}/google/api/${api}.proto
done

GOOGLE_API_RPC_PROTOS_DIR="/collector/protodeps/googleapis/google/rpc"
GOOGLE_API_RPC_PROTOS=("status")
mkdir -p ${GOOGLE_API_RPC_PROTOS_DIR}
cd ${GOOGLE_API_RPC_PROTOS_DIR}
for api in ${GOOGLE_API_RPC_PROTOS[@]} ; do
    curl --silent -LO https://raw.githubusercontent.com/googleapis/googleapis/${GOOGLE_APIS_VERSION}/google/rpc/${api}.proto
done

cd /collector
protoc -I . \
  -I ./protodeps/googleapis \
  --go_out=. \
  --go_opt=paths=source_relative \
  --go-grpc_out=require_unimplemented_servers=false:. \
  --go-grpc_opt=paths=source_relative \
  --grpc-gateway_out=. \
  --grpc-gateway_opt paths=source_relative \
  ./proto/v1alpha1/*.proto

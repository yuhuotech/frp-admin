#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

go_bin="$(go env GOPATH)/bin"
PATH="$PATH:$go_bin"
export PATH

if command -v buf >/dev/null 2>&1; then
  exec buf generate
fi

command -v protoc >/dev/null 2>&1 || {
  echo "protoc or buf is required" >&2
  exit 1
}
command -v protoc-gen-go >/dev/null 2>&1 || {
  echo "protoc-gen-go is required: go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6" >&2
  exit 1
}
command -v protoc-gen-go-grpc >/dev/null 2>&1 || {
  echo "protoc-gen-go-grpc is required: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1" >&2
  exit 1
}

rm -rf gen/go
mkdir -p gen/go
protoc -I proto \
  --go_out=gen/go --go_opt=paths=source_relative \
  --go-grpc_out=gen/go --go-grpc_opt=paths=source_relative \
  proto/frpadmin/agent/v1/agent.proto

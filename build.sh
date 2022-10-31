#!/bin/sh

go mod tidy

ALL_GOOS=(darwin linux)
ALL_GOARCH=(amd64)

for GOOS in ${ALL_GOOS[@]}; do
  for GOARCH in ${ALL_GOARCH[@]}; do
    name="${GOOS}-${GOARCH}"
    GOOS=${GOOS} GOARCH=${GOARCH} go build -o build/${name}/tink-aead-cli main.go
  done
done

#!/bin/sh

go mod tidy

VERSION="v0.0.2"
ALL_GOOS=(darwin linux)
ALL_GOARCH=(amd64)

for GOOS in ${ALL_GOOS[@]}; do
  for GOARCH in ${ALL_GOARCH[@]}; do
    name="${GOOS}-${GOARCH}-${VERSION}"
    GOOS=${GOOS} GOARCH=${GOARCH} go build -o build/${name}/tink-aead-cli main.go
    zip build/${name}.zip build/${name}/
  done
done

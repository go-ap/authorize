#!/usr/bin/env bash

set -e

_workdir=${1:-../}
_image_name=${2:-auth/builder}

_context=$(realpath "${_workdir}")

_builder=$(buildah from docker.io/library/golang:1.24-alpine)

buildah run "${_builder}" /sbin/apk update
buildah run "${_builder}" /sbin/apk add make bash openssl upx

buildah config --env GO111MODULE=on "${_builder}"
buildah config --env GOWORK=off "${_builder}"

buildah copy --ignorefile "${_context}/.containerignore" --contextdir "${_context}" "${_builder}" "${_context}" /go/src/app

buildah config --workingdir /go/src/app "${_builder}"

buildah run "${_builder}" make go.sum
buildah run "${_builder}" go mod vendor

buildah commit "${_builder}" "${_image_name}"

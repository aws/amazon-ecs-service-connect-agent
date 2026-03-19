#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="sc-agent-builder"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile.build" "$SCRIPT_DIR"

CACHE_DIR="${SCRIPT_DIR}/.go-cache"
mkdir -p "$CACHE_DIR"

docker run --rm \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --user "$(id -u):$(id -g)" \
  -v "$SCRIPT_DIR":/build \
  -v "$CACHE_DIR":/cache \
  -e GOCACHE=/cache/gocache \
  -e GOMODCACHE=/cache/gomodcache \
  -e HOME=/tmp \
  "$IMAGE_NAME" \
  "$@"

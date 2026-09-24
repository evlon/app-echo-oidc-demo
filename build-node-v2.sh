#!/bin/bash
# 在节点上执行的构建脚本（由本机 scp 上传后 ssh 调用）
set -euo pipefail

REMOTE_DIR="/tmp/echo-oidc-demo-v2"
HARBOR="dockerhub.kubekey.local:31104/library"
TAG="20260924-aiapi3hop-v2"
IMAGE="echo-oidc-demo:${TAG}"
HARBOR_IMAGE="${HARBOR}/echo-oidc-demo:${TAG}"

cd "$REMOTE_DIR"

# 修 Dockerfile 的占位符 FROM 为真实 Harbor 基础镜像
sed -i 's#registry.example.com/library/node:22-slim#dockerhub.kubekey.local:31104/library/node:22-slim#' Dockerfile
echo "── Dockerfile FROM 行 ──"
grep -n '^FROM' Dockerfile

echo "── 构建镜像 ${IMAGE} ──"
docker build -t "$IMAGE" . 2>&1 | tail -20

echo "── 打 tag 并推送 ${HARBOR_IMAGE} ──"
docker tag "$IMAGE" "$HARBOR_IMAGE"
docker push "$HARBOR_IMAGE" 2>&1 | tail -5

echo "── 新镜像 digest ──"
docker inspect --format '{{index .RepoDigests 0}}' "$HARBOR_IMAGE" 2>/dev/null || docker images --digests | grep "$TAG"
echo "DONE"

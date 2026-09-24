#!/bin/bash
# ============================================================================
# 构建 echo-oidc-demo 镜像并推送到内网镜像仓库（在 K8S 节点原生构建 arm64）
#
# 纯 Node ESM 零依赖 → 直接打包四个 .mjs + package.json 即可。
# 一个镜像同时承载 echo-server / echo-a / echo-b / echo-c 四个服务，
# 由 deployment 的 command 决定跑哪个。
#
# ── 用法 ───────────────────────────────────────────────────────────────────
#   bash build.sh [tag]
#   默认 tag = 日期 YYYYMMDD
# ============================================================================
set -euo pipefail

TAG="${1:-$(date +%Y%m%d)}"
DEMO_DIR="/e/ai-works/app-echo-oidc-demo"
HARBOR="registry.example.com/library"
IMAGE="echo-oidc-demo:${TAG}"
HARBOR_IMAGE="${HARBOR}/echo-oidc-demo:${TAG}"
REMOTE_DIR="/tmp/echo-oidc-demo-build"

echo "════════ 1. 打包构建上下文（零依赖，仅源码）════════"
STAGE="/tmp/echo-oidc-demo-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"

cp    "$DEMO_DIR/echo-server.mjs" "$STAGE/"
cp    "$DEMO_DIR/echo-a.mjs"      "$STAGE/"
cp    "$DEMO_DIR/echo-b.mjs"      "$STAGE/"
cp    "$DEMO_DIR/echo-c.mjs"      "$STAGE/"
cp    "$DEMO_DIR/package.json"    "$STAGE/"
cp    "$DEMO_DIR/Dockerfile"      "$STAGE/"

TARBALL="/tmp/echo-oidc-demo-ctx.tar.gz"
tar -czf "$TARBALL" -C "$STAGE" .
echo "  ✅ 打包完成: $(du -h "$TARBALL" | cut -f1)"

echo
echo "════════ 2. 上传到节点 ════════"
ssh ai-k8s "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
scp -q "$TARBALL" ai-k8s:"$REMOTE_DIR/ctx.tar.gz"
ssh ai-k8s "cd $REMOTE_DIR && tar -xzf ctx.tar.gz && rm ctx.tar.gz && ls -la"
echo "  ✅ 上传完成"

echo
echo "════════ 3. 节点上构建镜像（arm64 原生）════════"
ssh ai-k8s "cd $REMOTE_DIR && docker build -t $IMAGE . 2>&1 | tail -15"
echo "  ✅ 构建完成: $IMAGE"

echo
echo "════════ 4. 推送到镜像仓库 ════════"
ssh ai-k8s "docker tag $IMAGE $HARBOR_IMAGE && docker push $HARBOR_IMAGE 2>&1 | tail -5"
echo "  ✅ 已推送: $HARBOR_IMAGE"

echo
echo "════════ 5. 验证 ════════"
skopeo inspect --insecure-policy --tls-verify=false \
  "docker://registry.example.com/library/echo-oidc-demo:${TAG}" 2>/dev/null \
  | grep -E '"Architecture"|"Os"|"Name"' || echo "  （skopeo 检查跳过）"

echo
echo "✅ 完成：$HARBOR_IMAGE"
echo "   部署：把 deploy/echo-a.yaml、deploy/echo-b.yaml 里 image 改为 $HARBOR_IMAGE 后 kubectl apply"
echo "   网关：higress-cli 建路由 demo-a/demo-b + 应用 gateway/jwt-auth-echo-a.json、jwt-auth-echo-b.json"

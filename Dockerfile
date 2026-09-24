# ============================================================================
# echo-oidc-demo 容器镜像 —— 「一个企业业务应用怎么打入内网镜像」
#
# 纯 Node ESM、零依赖（无 node_modules、无第三方包），直接在 K8S 节点
# 原生构建 arm64（本机是 x86_64 / 节点是 aarch64，且节点无出公网，
# 基础镜像必须先入内网镜像仓库）。
#
# ── 四个服务共用一个镜像 ──────────────────────────────────────────────────
#   echo-server.mjs  —— 单跳身份回显（原示例，端口 8080）
#   echo-a.mjs       —— 身份透传第一跳（入口，调 echo-b）
#   echo-b.mjs       —— 身份透传第二跳（中间跳，透传调 echo-c）
#   echo-c.mjs       —— 身份透传第三跳（链式末端，读网关注入身份）
#   通过容器启动命令（deployment 里的 command）选择跑哪个服务。
#
# ── 基础镜像 ──────────────────────────────────────────────────────────────
#   内网镜像仓库 registry.example.com/library/node:22-slim（arm64），与其它业务服务一致。
#
# ── 为什么这样写 ──────────────────────────────────────────────────────────
#   这是给业务开发看的「最小可参考形态」：
#   1. 源码 COPY 进 /app（零依赖，无需 node_modules）；
#   2. 健康检查 /health 供 K8S probe；
#   3. 若业务需要访问 *.example.com 内网自签 HTTPS，挂 NODE_EXTRA_CA_CERTS
#      （echo-a 要调 https://demo-b.example.com，故 deploy/echo-a.yaml 挂了
#        企业根证书 company-root-ca）。
# ============================================================================
FROM registry.example.com/library/node:22-slim

ENV TZ=Asia/Shanghai
ENV NODE_ENV=production

WORKDIR /app

COPY echo-server.mjs    /app/echo-server.mjs
COPY echo-a.mjs         /app/echo-a.mjs
COPY echo-b.mjs         /app/echo-b.mjs
COPY echo-c.mjs         /app/echo-c.mjs
COPY package.json       /app/package.json

EXPOSE 8080

# 默认跑单跳 echo-server；echo-a / echo-b / echo-c 由 deployment 的 command 覆盖
CMD ["node", "echo-server.mjs"]

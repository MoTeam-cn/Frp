#!/usr/bin/env bash
# ci-upload.sh - 上传 frp 单个二进制包到 apiServer（MoSign-v2 鉴权）
#
# 用法：
#   ./ci-upload.sh <version> <component> <platform> <arch> <file_path> [release_notes] [release_url]
#
# 参数：
#   version        frp 语义化版本号（如 0.61.0）
#   component      组件类型：client | server
#   platform       平台：windows | macos | linux
#   arch           架构：x86_64 | aarch64 | i686 | armv7
#   file_path      本地压缩包路径
#   release_notes  可选，更新日志（Markdown）
#   release_url    可选，GitHub Release 页面 URL
#
# 环境变量：
#   MOLAUNCH_ACTION_PUSH_KEY  MoSign-v2 签名密钥（必填）
#   API_BASE_URL              apiServer 基础 URL（默认 https://api.molaunch.moiu.cn）
#
# 流程：
#   1. 计算文件大小和 SHA256
#   2. 调用 POST /v3/ci/frp/presign-upload 获取 S3 预签名 PUT URL
#   3. curl PUT 直传文件到 S3
#   4. 调用 POST /v3/ci/frp/releases 注册版本到 apiServer
#
# See: docs/updater/design.md §6 MoSign-v2 协议
#      api-server/src/controllers/v3/ci.rs（frp_presign_upload + create_frp_release）

set -euo pipefail

# ===== 参数校验 =====
if [ "$#" -lt 5 ]; then
  echo "Usage: $0 <version> <component> <platform> <arch> <file_path> [release_notes] [release_url]"
  echo ""
  echo "  version        frp version (e.g. 0.61.0)"
  echo "  component      client | server"
  echo "  platform       windows | macos | linux"
  echo "  arch           x86_64 | aarch64 | i686 | armv7"
  echo "  file_path      local archive path"
  echo "  release_notes  optional, markdown"
  echo "  release_url    optional, GitHub release URL"
  exit 1
fi

VERSION="$1"
COMPONENT="$2"
PLATFORM="$3"
ARCH="$4"
FILE_PATH="$5"
RELEASE_NOTES="${6:-}"
RELEASE_URL="${7:-}"

API_BASE_URL="${API_BASE_URL:-https://api.molaunch.moiu.cn}"

# ===== 环境校验 =====
if [ -z "${MOLAUNCH_ACTION_PUSH_KEY:-}" ]; then
  echo "::error::MOLAUNCH_ACTION_PUSH_KEY 环境变量未设置"
  exit 1
fi

if [ ! -f "$FILE_PATH" ]; then
  echo "::error::文件不存在: $FILE_PATH"
  exit 1
fi

case "$COMPONENT" in
  client|server) ;;
  *) echo "::error::component 非法（仅 client / server）: $COMPONENT"; exit 1 ;;
esac

case "$PLATFORM" in
  windows|macos|linux) ;;
  *) echo "::error::platform 非法（仅 windows / macos / linux）: $PLATFORM"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|aarch64|i686|armv7) ;;
  *) echo "::error::arch 非法（仅 x86_64 / aarch64 / i686 / armv7）: $ARCH"; exit 1 ;;
esac

# ===== 文件元数据 =====
FILENAME=$(basename "$FILE_PATH")
# 兼容 Linux/macOS 的 stat
if stat -c%s "$FILE_PATH" >/dev/null 2>&1; then
  FILE_SIZE=$(stat -c%s "$FILE_PATH")
else
  FILE_SIZE=$(stat -f%z "$FILE_PATH")
fi
# 兼容 Linux/macOS 的 sha256
if command -v sha256sum >/dev/null 2>&1; then
  FILE_SHA256=$(sha256sum "$FILE_PATH" | awk '{print $1}')
else
  FILE_SHA256=$(shasum -a 256 "$FILE_PATH" | awk '{print $1}')
fi
FILE_HASH="sha256:$FILE_SHA256"

echo "::group::上传 $COMPONENT $VERSION $PLATFORM/$ARCH ($FILENAME, $FILE_SIZE bytes)"

# 调试输出：key 长度和前缀（不泄露完整 key，用于对比云端配置）
echo "  [debug] push_key length=${#MOLAUNCH_ACTION_PUSH_KEY}" >&2
echo "  [debug] push_key prefix=${MOLAUNCH_ACTION_PUSH_KEY:0:8}..." >&2

# ===== MoSign-v2 签名函数 =====
# 输出格式：timestamp|nonce|signature
#
# 用 Node 的 crypto 模块计算 SHA256 和 HMAC，避免 shell/openssl 版本差异：
# - openssl dgst -sha256 -r 的 -r（BSD 格式）在不同 openssl 版本输出不一致
# - openssl dgst -sha256 -hmac 在某些版本可能把 key 当作选项参数
# - Node crypto 行为确定，且 key 通过环境变量传递，不泄露到进程列表
sign_request() {
  local method="$1"
  local path="$2"
  local body_file="$3"

  MOLAUNCH_ACTION_PUSH_KEY="${MOLAUNCH_ACTION_PUSH_KEY}" node -e '
    const crypto = require("crypto");
    const fs = require("fs");

    const method = process.argv[1];
    const path = process.argv[2];
    const bodyFile = process.argv[3];
    const key = process.env.MOLAUNCH_ACTION_PUSH_KEY;

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomBytes(16).toString("hex");
    const body = fs.readFileSync(bodyFile);
    const bodySha256 = crypto.createHash("sha256").update(body).digest("hex");

    // string-to-sign = METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256_HEX
    // 注意：末尾不加换行，与服务端 format!() 一致
    const stringToSign = [method, path, timestamp, nonce, bodySha256].join("\n");
    const signature = crypto.createHmac("sha256", key).update(stringToSign).digest("hex");

    // 调试输出到 stderr（不干扰 stdout 的正式输出）
    console.error("[sign-debug] method=" + method);
    console.error("[sign-debug] path=" + path);
    console.error("[sign-debug] timestamp=" + timestamp);
    console.error("[sign-debug] nonce=" + nonce);
    console.error("[sign-debug] body_sha256=" + bodySha256);
    console.error("[sign-debug] body_size=" + body.length);
    console.error("[sign-debug] key_length=" + key.length);
    console.error("[sign-debug] signature=" + signature);

    // 正式输出到 stdout：timestamp|nonce|signature
    console.log(timestamp + "|" + nonce + "|" + signature);
  ' "$method" "$path" "$body_file"
}

# ===== Step 1: 获取 S3 预签名 PUT URL =====
cat > /tmp/presign-payload.json <<EOF
{
  "version": "${VERSION}",
  "component": "${COMPONENT}",
  "platform": "${PLATFORM}",
  "filenames": ["${FILENAME}"]
}
EOF

SIGN_INFO=$(sign_request "POST" "/v3/ci/frp/presign-upload" /tmp/presign-payload.json)
TIMESTAMP=$(echo "$SIGN_INFO" | cut -d'|' -f1)
NONCE=$(echo "$SIGN_INFO" | cut -d'|' -f2)
SIGNATURE=$(echo "$SIGN_INFO" | cut -d'|' -f3)

echo "请求预签名上传 URL..."
# 注意：必须使用 --data-binary @file 而非 -d @file
# curl -d @file 会剥离文件中的 \r 和 \n，导致服务端收到的 body 与脚本计算 SHA256 的原文不一致，
# 进而 MoSign-v2 签名校验失败。--data-binary 保留原始字节，保证两端 SHA256 一致。
HTTP_STATUS=$(curl -sS -o /tmp/presign-response.json -w "%{http_code}" \
  -X POST "${API_BASE_URL}/v3/ci/frp/presign-upload" \
  -H "Content-Type: application/json" \
  -H "X-MoSign-Version: MoSign-v2" \
  -H "X-MoSign-Timestamp: ${TIMESTAMP}" \
  -H "X-MoSign-Nonce: ${NONCE}" \
  -H "X-MoSign-Signature: ${SIGNATURE}" \
  --data-binary @/tmp/presign-payload.json)

if [ "$HTTP_STATUS" != "200" ]; then
  echo "::error::预签名请求失败 (HTTP $HTTP_STATUS):"
  cat /tmp/presign-response.json >&2
  exit 1
fi

# 解析响应（使用 Node 跨平台兼容，无需 jq）
# 注意：apiServer 设计为 HTTP 200 + body.code 区分业务错误，
# 所以 HTTP 200 也可能是签名校验失败（code=1004），需检查 body.code
node <<'NODE_SCRIPT'
const fs = require('fs');
const raw = fs.readFileSync('/tmp/presign-response.json', 'utf8');
let resp;
try {
  resp = JSON.parse(raw);
} catch (e) {
  console.error('::error::预签名响应非 JSON：' + raw);
  process.exit(1);
}

// 业务错误（如 code=1004 签名校验失败）→ 打印完整响应到 stderr，方便排查
if (resp.code !== 1) {
  console.error('::error::预签名业务错误 (code=' + resp.code + '): ' + (resp.msg || ''));
  console.error('完整响应：' + raw);
  process.exit(1);
}

if (!resp.data || !Array.isArray(resp.data.uploads) || resp.data.uploads.length === 0) {
  console.error('::error::预签名响应格式异常: ' + raw);
  process.exit(1);
}
const item = resp.data.uploads[0];
fs.writeFileSync('/tmp/presign-item.json', JSON.stringify(item));
console.log('已获取预签名 URL（有效期 ' + resp.data.expires_in + ' 秒）');
console.log('  download_key: ' + item.download_key);
NODE_SCRIPT

UPLOAD_URL=$(node -e "const m=require('/tmp/presign-item.json');process.stdout.write(m.upload_url)")
DOWNLOAD_KEY=$(node -e "const m=require('/tmp/presign-item.json');process.stdout.write(m.download_key)")

# ===== Step 2: 上传文件到 S3 =====
echo "上传 $FILE_PATH -> S3 (key=$DOWNLOAD_KEY)"
curl -sS -X PUT --upload-file "$FILE_PATH" "$UPLOAD_URL"
if [ $? -ne 0 ]; then
  echo "::error::S3 上传失败"
  exit 1
fi
echo "S3 上传完成"

# ===== Step 3: 注册版本到 apiServer =====
# 转义 release_notes 为 JSON 字符串
ESCAPED_NOTES=$(node -e "process.stdout.write(JSON.stringify(process.argv[1] || ''))" "$RELEASE_NOTES")

cat > /tmp/release-payload.json <<EOF
{
  "version": "${VERSION}",
  "component": "${COMPONENT}",
  "platform": "${PLATFORM}",
  "arch": "${ARCH}",
  "download_url": "${DOWNLOAD_KEY}",
  "signature": "",
  "file_size": ${FILE_SIZE},
  "file_hash": "${FILE_HASH}",
  "release_notes": ${ESCAPED_NOTES},
  "release_url": "${RELEASE_URL}",
  "rollout_pct": 100
}
EOF

SIGN_INFO=$(sign_request "POST" "/v3/ci/frp/releases" /tmp/release-payload.json)
TIMESTAMP=$(echo "$SIGN_INFO" | cut -d'|' -f1)
NONCE=$(echo "$SIGN_INFO" | cut -d'|' -f2)
SIGNATURE=$(echo "$SIGN_INFO" | cut -d'|' -f3)

echo "注册版本到 apiServer..."
HTTP_STATUS=$(curl -sS -o /tmp/register-response.txt -w "%{http_code}" \
  -X POST "${API_BASE_URL}/v3/ci/frp/releases" \
  -H "Content-Type: application/json" \
  -H "X-MoSign-Version: MoSign-v2" \
  -H "X-MoSign-Timestamp: ${TIMESTAMP}" \
  -H "X-MoSign-Nonce: ${NONCE}" \
  -H "X-MoSign-Signature: ${SIGNATURE}" \
  --data-binary @/tmp/release-payload.json)

if [ "$HTTP_STATUS" != "200" ]; then
  echo "::error::版本注册失败 (HTTP $HTTP_STATUS):"
  cat /tmp/register-response.txt
  exit 1
fi

echo "::endgroup::"
echo "✓ 已注册 $COMPONENT $VERSION $PLATFORM/$ARCH"

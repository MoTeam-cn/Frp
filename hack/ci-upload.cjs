#!/usr/bin/env node
/**
 * ci-upload.cjs — 上传 frp 单个二进制包到 apiServer（MoSign-v2 鉴权）
 *
 * 纯 Node.js 实现，消除 shell/Node 数据传递导致的签名不一致问题：
 * - JSON.stringify() 生成 body Buffer，签名和 HTTP 请求使用同一个 Buffer
 * - 无 heredoc / curl / shell 变量展开，行为确定
 *
 * 用法：
 *   node ci-upload.cjs <version> <component> <platform> <arch> <file_path> [release_notes] [release_url]
 *
 * 参数：
 *   version        frp 语义化版本号（如 0.70.1）
 *   component      组件类型：client | server
 *   platform       平台：windows | macos | linux
 *   arch           架构：x86_64 | aarch64 | i686 | armv7
 *   file_path      本地压缩包路径
 *   release_notes  可选，更新日志（Markdown）
 *   release_url    可选，GitHub Release 页面 URL
 *
 * 环境变量：
 *   MOLAUNCH_ACTION_PUSH_KEY  MoSign-v2 签名密钥（必填）
 *   API_BASE_URL              apiServer 基础 URL（默认 https://api.molaunch.moiu.cn）
 *
 * 流程：
 *   1. 计算文件大小和 SHA256
 *   2. POST /v3/ci/frp/presign-upload 获取 S3 预签名 PUT URL
 *   3. PUT 直传文件到 S3
 *   4. POST /v3/ci/frp/releases 注册版本到 apiServer
 *
 * See: api-server/src/utils/mosign_v2.rs（签名协议）
 *      api-server/src/controllers/v3/ci.rs（frp_presign_upload + create_frp_release）
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// ===== 参数解析 =====
const args = process.argv.slice(2);
if (args.length < 5) {
  console.error('Usage: node ci-upload.cjs <version> <component> <platform> <arch> <file_path> [release_notes] [release_url]');
  console.error('');
  console.error('  version        frp version (e.g. 0.70.1)');
  console.error('  component      client | server');
  console.error('  platform       windows | macos | linux');
  console.error('  arch           x86_64 | aarch64 | i686 | armv7');
  console.error('  file_path      local archive path');
  console.error('  release_notes  optional, markdown');
  console.error('  release_url    optional, GitHub release URL');
  process.exit(1);
}

const VERSION = args[0];
const COMPONENT = args[1];
const PLATFORM = args[2];
const ARCH = args[3];
const FILE_PATH = args[4];
const RELEASE_NOTES = args[5] || '';
const RELEASE_URL = args[6] || '';

const API_BASE_URL = process.env.API_BASE_URL || 'https://api.molaunch.moiu.cn';
const PUSH_KEY = process.env.MOLAUNCH_ACTION_PUSH_KEY;

// ===== 环境校验 =====
if (!PUSH_KEY) {
  console.error('::error::MOLAUNCH_ACTION_PUSH_KEY 环境变量未设置');
  process.exit(1);
}
if (!fs.existsSync(FILE_PATH)) {
  console.error(`::error::文件不存在: ${FILE_PATH}`);
  process.exit(1);
}

// 参数校验
if (!['client', 'server'].includes(COMPONENT)) {
  console.error(`::error::component 非法（仅 client / server）: ${COMPONENT}`);
  process.exit(1);
}
if (!['windows', 'macos', 'linux'].includes(PLATFORM)) {
  console.error(`::error::platform 非法（仅 windows / macos / linux）: ${PLATFORM}`);
  process.exit(1);
}
if (!['x86_64', 'aarch64', 'i686', 'armv7'].includes(ARCH)) {
  console.error(`::error::arch 非法（仅 x86_64 / aarch64 / i686 / armv7）: ${ARCH}`);
  process.exit(1);
}

// ===== MoSign-v2 签名 =====
// string-to-sign = METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256_HEX
// signature = HMAC-SHA256(push_key, string_to_sign).hex()
function signRequest(method, reqPath, bodyBuffer) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodySha256 = crypto.createHash('sha256').update(bodyBuffer).digest('hex');
  const stringToSign = [method, reqPath, timestamp, nonce, bodySha256].join('\n');
  const signature = crypto.createHmac('sha256', PUSH_KEY).update(stringToSign).digest('hex');
  return { timestamp, nonce, signature };
}

// ===== HTTP 请求封装（支持 HTTPS + 自动重定向） =====
function httpRequest(targetUrl, options, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const lib = u.protocol === 'https:' ? https : http;
    const headers = Object.assign({}, options.headers || {});
    if (body) headers['Content-Length'] = Buffer.byteLength(body);

    const req = lib.request(u, { method: options.method, headers }, (res) => {
      // 处理 3xx 重定向（S3 可能返回 307 临时重定向）
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume(); // 丢弃当前响应体
        httpRequest(res.headers.location, options, body).then(resolve, reject);
        return;
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ===== 主流程 =====
async function main() {
  const FILENAME = path.basename(FILE_PATH);
  const fileBuffer = fs.readFileSync(FILE_PATH);
  const FILE_SIZE = fileBuffer.length;
  const FILE_SHA256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  const FILE_HASH = `sha256:${FILE_SHA256}`;

  console.log(`::group::上传 ${COMPONENT} ${VERSION} ${PLATFORM}/${ARCH} (${FILENAME}, ${FILE_SIZE} bytes)`);

  // ===== Step 1: 获取 S3 预签名 PUT URL =====
  // body 用 JSON.stringify 生成，签名和请求共用同一个 Buffer，保证 SHA256 一致
  const presignPath = '/v3/ci/frp/presign-upload';
  const presignBody = Buffer.from(JSON.stringify({
    version: VERSION,
    component: COMPONENT,
    platform: PLATFORM,
    filenames: [FILENAME],
  }));

  const presignSign = signRequest('POST', presignPath, presignBody);
  console.log('请求预签名上传 URL...');

  const presignResp = await httpRequest(`${API_BASE_URL}${presignPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-MoSign-Version': 'MoSign-v2',
      'X-MoSign-Timestamp': presignSign.timestamp,
      'X-MoSign-Nonce': presignSign.nonce,
      'X-MoSign-Signature': presignSign.signature,
    },
  }, presignBody);

  let presignData;
  try {
    presignData = JSON.parse(presignResp.body.toString());
  } catch (e) {
    console.error(`::error::预签名响应非 JSON（HTTP ${presignResp.status}）: ${presignResp.body.toString().slice(0, 500)}`);
    process.exit(1);
  }

  // HTTP 200 + body.code 区分业务错误（code=1004 签名校验失败等）
  if (presignData.code !== 1) {
    console.error(`::error::预签名业务错误 (code=${presignData.code}): ${presignData.msg || ''}`);
    console.error(`完整响应：${presignResp.body.toString()}`);
    process.exit(1);
  }

  if (!presignData.data || !Array.isArray(presignData.data.uploads) || presignData.data.uploads.length === 0) {
    console.error(`::error::预签名响应格式异常: ${presignResp.body.toString()}`);
    process.exit(1);
  }

  const uploadItem = presignData.data.uploads[0];
  const UPLOAD_URL = uploadItem.upload_url;
  const DOWNLOAD_KEY = uploadItem.download_key;
  console.log(`已获取预签名 URL（有效期 ${presignData.data.expires_in} 秒）`);
  console.log(`  download_key: ${DOWNLOAD_KEY}`);

  // ===== Step 2: 上传文件到 S3 =====
  console.log(`上传 ${FILE_PATH} -> S3 (key=${DOWNLOAD_KEY})`);
  const s3Resp = await httpRequest(UPLOAD_URL, {
    method: 'PUT',
    // S3 presigned URL 只签了 host 头，不要额外设置 Content-Type 等头
    headers: {},
  }, fileBuffer);

  if (s3Resp.status < 200 || s3Resp.status >= 300) {
    console.error(`::error::S3 上传失败 (HTTP ${s3Resp.status})`);
    console.error(s3Resp.body.toString().slice(0, 500));
    process.exit(1);
  }
  console.log('S3 上传完成');

  // ===== Step 3: 注册版本到 apiServer =====
  const releasePath = '/v3/ci/frp/releases';
  const releaseBody = Buffer.from(JSON.stringify({
    version: VERSION,
    component: COMPONENT,
    platform: PLATFORM,
    arch: ARCH,
    download_url: DOWNLOAD_KEY,
    signature: '',
    file_size: FILE_SIZE,
    file_hash: FILE_HASH,
    release_notes: RELEASE_NOTES,
    release_url: RELEASE_URL,
    rollout_pct: 100,
  }));

  const releaseSign = signRequest('POST', releasePath, releaseBody);
  console.log('注册版本到 apiServer...');

  const releaseResp = await httpRequest(`${API_BASE_URL}${releasePath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-MoSign-Version': 'MoSign-v2',
      'X-MoSign-Timestamp': releaseSign.timestamp,
      'X-MoSign-Nonce': releaseSign.nonce,
      'X-MoSign-Signature': releaseSign.signature,
    },
  }, releaseBody);

  let releaseData;
  try {
    releaseData = JSON.parse(releaseResp.body.toString());
  } catch (e) {
    console.error(`::error::注册响应非 JSON（HTTP ${releaseResp.status}）: ${releaseResp.body.toString().slice(0, 500)}`);
    process.exit(1);
  }

  if (releaseData.code !== 1) {
    console.error(`::error::版本注册失败 (code=${releaseData.code}): ${releaseData.msg || ''}`);
    console.error(`完整响应：${releaseResp.body.toString()}`);
    process.exit(1);
  }

  console.log('::endgroup::');
  console.log(`✓ 已注册 ${COMPONENT} ${VERSION} ${PLATFORM}/${ARCH} (id=${releaseData.data?.id})`);
}

main().catch((err) => {
  console.error(`::error::${err.message}`);
  console.error(err.stack);
  process.exit(1);
});

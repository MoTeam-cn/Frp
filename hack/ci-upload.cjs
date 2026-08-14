#!/usr/bin/env node
/**
 * ci-upload.cjs — 上传 frp 单个二进制包到 apiServer（MoSign-v2 鉴权，纯 Node 实现）
 * 用法: node ci-upload.cjs <version> <component> <platform> <arch> <file_path> [release_notes] [release_url]
 * 环境变量: MOLAUNCH_ACTION_PUSH_KEY（必填）/ MOLAUNCH_ACTION_PUSH_SERVER（必填，apiServer 地址）
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

const API_BASE_URL = process.env.MOLAUNCH_ACTION_PUSH_SERVER;
const PUSH_KEY = process.env.MOLAUNCH_ACTION_PUSH_KEY;

// ===== 环境校验 =====
if (!API_BASE_URL) {
  console.error('::error::MOLAUNCH_ACTION_PUSH_SERVER 环境变量未设置');
  process.exit(1);
}
if (!PUSH_KEY) {
  console.error('::error::MOLAUNCH_ACTION_PUSH_KEY 环境变量未设置');
  process.exit(1);
}
if (!fs.existsSync(FILE_PATH)) {
  console.error(`::error::文件不存在: ${FILE_PATH}`);
  process.exit(1);
}
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
      // 3xx 重定向（S3 307）
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        httpRequest(res.headers.location, options, body).then(resolve, reject);
        return;
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
    });
    req.on('error', (err) => {
      err.networkError = true;
      reject(err);
    });
    if (body) req.write(body);
    req.end();
  });
}

// ===== S3 上传辅助 =====

// Cloudflare 回源源站错误码（520~527、530）自动重试，403 等鉴权错误不重试
const RETRYABLE_STATUS = new Set([520, 521, 522, 523, 524, 525, 526, 527, 530]);
const MAX_RETRIES = 3;

async function s3PutWithRetry(uploadUrl, buffer, label) {
  for (let attempt = 1; ; attempt++) {
    try {
      const resp = await httpRequest(uploadUrl, { method: 'PUT', headers: {} }, buffer);
      if (resp.status >= 200 && resp.status < 300) return resp;
      const err = new Error(`${label} S3 上传失败 (HTTP ${resp.status}): ${resp.body.toString().slice(0, 500)}`);
      err.code = 'UPLOAD_FAILED';
      err.httpStatus = resp.status;
      throw err;
    } catch (err) {
      const retryable = err.code === 'UPLOAD_FAILED' && RETRYABLE_STATUS.has(err.httpStatus)
        || err.networkError;
      if (!retryable || attempt > MAX_RETRIES) throw err;
      const delay = Math.min(1000 * 2 ** (attempt - 1), 8000);
      console.log(`::warning::${label} 上传失败 (${err.httpStatus ? `HTTP ${err.httpStatus}` : err.code})，${delay}ms 后第 ${attempt} 次重试（共最多 ${MAX_RETRIES} 次）...`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
}

// 单次 PUT 上传（小文件）
function uploadSingle(item, buffer, label) {
  return s3PutWithRetry(item.upload_url, buffer, label);
}

// MoSign-v2 API POST（签名 + 请求 + Cloudflare 回源错误重试）
// 与 s3PutWithRetry 同一套 RETRYABLE_STATUS / MAX_RETRIES 退避策略，
// 每次尝试重新签名（timestamp/nonce 每次生成）
async function apiPostWithRetry(reqPath, bodyBuffer, label) {
  for (let attempt = 1; ; attempt++) {
    try {
      const sign = signRequest('POST', reqPath, bodyBuffer);
      const resp = await httpRequest(`${API_BASE_URL}${reqPath}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-MoSign-Version': 'MoSign-v2',
          'X-MoSign-Timestamp': sign.timestamp,
          'X-MoSign-Nonce': sign.nonce,
          'X-MoSign-Signature': sign.signature,
        },
      }, bodyBuffer);
      if (resp.status >= 200 && resp.status < 300) return resp;
      const err = new Error(`${label} API 请求失败 (HTTP ${resp.status}): ${resp.body.toString().slice(0, 500)}`);
      err.code = 'API_FAILED';
      err.httpStatus = resp.status;
      throw err;
    } catch (err) {
      const retryable = err.code === 'API_FAILED' && RETRYABLE_STATUS.has(err.httpStatus)
        || err.networkError;
      if (!retryable || attempt > MAX_RETRIES) throw err;
      const delay = Math.min(1000 * 2 ** (attempt - 1), 8000);
      console.log(`::warning::${label} API 请求失败 (${err.httpStatus ? `HTTP ${err.httpStatus}` : err.code})，${delay}ms 后第 ${attempt} 次重试（共最多 ${MAX_RETRIES} 次）...`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
}

// 分片上传（大文件）：按 part_number 顺序 PUT 各分片，收集 ETag
async function uploadMultipart(item, buffer, label) {
  const { upload_id, part_size, parts } = item.multipart;
  console.log(`${label}分片上传开始: ${parts.length} 片 x ${part_size} 字节 (upload_id=${upload_id})`);
  const uploadedParts = [];
  for (const part of parts) {
    const start = (part.part_number - 1) * part_size;
    const end = Math.min(start + part_size, buffer.length);
    const chunk = buffer.subarray(start, end);
    const resp = await s3PutWithRetry(part.upload_url, chunk, `${label} 分片 ${part.part_number}`);
    const etag = resp.headers.etag;
    if (!etag) {
      const err = new Error(`${label} 分片 ${part.part_number} 响应缺少 ETag`);
      err.code = 'UPLOAD_FAILED';
      throw err;
    }
    uploadedParts.push({ part_number: part.part_number, etag });
    console.log(`  分片 ${part.part_number}/${parts.length} 完成 (${chunk.length} bytes)`);
  }
  return uploadedParts;
}

// 回传 upload_id + 分片 ETag 列表，由服务端合并
// updater 与 frp 两类对象共用 /v3/ci/complete-upload（download_key 区分）
async function completeMultipartUpload(item, parts) {
  const completePath = '/v3/ci/complete-upload';
  const completeBody = Buffer.from(JSON.stringify({
    upload_id: item.multipart.upload_id,
    download_key: item.download_key,
    parts,
  }));
  console.log('完成分片上传（CompleteMultipartUpload）...');

  const resp = await apiPostWithRetry(completePath, completeBody, '完成分片');

  let data;
  try {
    data = JSON.parse(resp.body.toString());
  } catch (e) {
    const err = new Error(`完成分片响应非 JSON（HTTP ${resp.status}）: ${resp.body.toString().slice(0, 500)}`);
    err.code = 'UPLOAD_FAILED';
    throw err;
  }

  if (data.code !== 1) {
    const err = new Error(`完成分片失败 (code=${data.code}): ${data.msg || ''}\n完整响应：${resp.body.toString()}`);
    err.code = 'UPLOAD_FAILED';
    throw err;
  }
  console.log('分片上传完成');
}

// 有 multipart 凭证走分片，否则单次 PUT
async function uploadToS3(item, buffer, label) {
  if (item.multipart && item.multipart.parts && item.multipart.parts.length > 0) {
    const parts = await uploadMultipart(item, buffer, label);
    await completeMultipartUpload(item, parts);
    return;
  }
  if (!item.upload_url) {
    const err = new Error(`${label} 预签名响应缺少 upload_url 且无分片凭证`);
    err.code = 'UPLOAD_FAILED';
    throw err;
  }
  console.log(`上传${label}: -> S3`);
  await uploadSingle(item, buffer, label);
  console.log(`${label}上传完成`);
}

// ===== 主流程 =====
async function main() {
  const FILENAME = path.basename(FILE_PATH);
  const fileBuffer = fs.readFileSync(FILE_PATH);
  const FILE_SIZE = fileBuffer.length;
  const FILE_HASH = `sha256:${crypto.createHash('sha256').update(fileBuffer).digest('hex')}`;

  console.log(`::group::上传 ${COMPONENT} ${VERSION} ${PLATFORM}/${ARCH} (${FILENAME}, ${FILE_SIZE} bytes)`);

  // ===== Step 1: 获取 S3 预签名上传 URL =====
  const presignPath = '/v3/ci/frp/presign-upload';
  const presignBody = Buffer.from(JSON.stringify({
    version: VERSION,
    component: COMPONENT,
    platform: PLATFORM,
    filenames: [FILENAME],
    // 服务端据此判断是否分片（超过分片阈值返回 multipart 凭证）
    sizes: [FILE_SIZE],
  }));

  console.log('请求预签名上传 URL...');

  const presignResp = await apiPostWithRetry(presignPath, presignBody, '预签名');

  let presignData;
  try {
    presignData = JSON.parse(presignResp.body.toString());
  } catch (e) {
    console.error(`::error::预签名响应非 JSON（HTTP ${presignResp.status}）: ${presignResp.body.toString().slice(0, 500)}`);
    process.exit(1);
  }

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
  console.log(`已获取预签名 URL（有效期 ${presignData.data.expires_in} 秒）`);
  console.log(`  download_key: ${uploadItem.download_key}`);

  // ===== Step 2: 上传文件到 S3（大文件走分片上传，小文件单次 PUT） =====
  await uploadToS3(uploadItem, fileBuffer, '压缩包');

  // ===== Step 3: 注册版本到 apiServer =====
  const releasePath = '/v3/ci/frp/releases';
  const releaseBody = Buffer.from(JSON.stringify({
    version: VERSION,
    component: COMPONENT,
    platform: PLATFORM,
    arch: ARCH,
    download_url: uploadItem.download_key,
    signature: '',
    file_size: FILE_SIZE,
    file_hash: FILE_HASH,
    release_notes: RELEASE_NOTES,
    release_url: RELEASE_URL,
    rollout_pct: 100,
  }));

  console.log('注册版本到 apiServer...');

  const releaseResp = await apiPostWithRetry(releasePath, releaseBody, '注册版本');

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

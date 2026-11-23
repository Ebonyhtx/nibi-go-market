#!/usr/bin/env node
// 市场仓的泄露门禁：只允许白名单文件，且文本与图片元数据里不得出现凭据/本机路径/内部基础设施。
//
// 市场仓是公开仓：这里只应有索引、签名、插件包、公开文档、展示图片与门禁脚本本身。
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");

const ALLOWED = [
  /^README\.md$/,
  /^README\.en\.md$/,
  /^LICENSE$/,
  /^CONTRIBUTING\.md$/,
  /^SECURITY\.md$/,
  /^\.github\/PULL_REQUEST_TEMPLATE\.md$/,
  /^assets\/[a-z0-9][a-z0-9._-]{0,80}\.(?:png|gif|svg)$/,
  /^submissions\/README\.md$/,
  /^submissions\/[a-z0-9][a-z0-9._-]{0,120}\.json$/,
  /^index\.json$/,
  /^index\.json\.sig$/,
  /^yanked\.json$/,
  /^packages\/[a-z0-9][a-z0-9._-]{0,80}\.zip$/,
  /^scripts\/validate\.mjs$/,
  /^scripts\/check-leaks\.mjs$/,
  /^scripts\/check-submissions\.mjs$/,
  /^scripts\/check-yanks\.mjs$/,
  /^scripts\/scan-package\.mjs$/,
  /^scripts\/scan-package\.test\.mjs$/,
  /^scripts\/auto-publish\.mjs$/,
  /^\.github\/workflows\/validate\.yml$/,
  /^\.github\/workflows\/auto-sign\.yml$/,
];

const INTERNAL_INFRA_RE = (() => {
  // 词表走 base64 编码，避免门禁脚本本身在公开仓暴露内部标识字面量。
  const terms = [
    ...Buffer.from(
      "bmliaS1kaXN0LWh6Cm5pYmktcGFpZC1oegpuaWJpLWJhY2t1cC1oegpuaWJpLWZlZWRiYWNrLWh6Cm5pYmktbG9ncy1oegpvc3N1dGlsLXB1Ymxpc2gKbmliaS1jbgpuaWJpLWdvLW9wcwpuaWJpLWdvLW1hcmtldC1zeW5jCmtleS1wYXNzcGhyYXNlCi9zcnYvbmliaS1zaXRlCi9vcHQvbmliaS0Ka2V5c3RvcmUvbmliaS1nby1tYXJrZXQ=",
      "base64",
    )
      .toString("utf8")
      .split("\n"),
    Buffer.from("ODA3OWZlNTk=", "base64").toString("utf8"),
  ].filter(Boolean);
  const words = terms.filter((term) => !term.includes("/"));
  const paths = terms
    .filter((term) => term.includes("/"))
    .map((term) => term.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"));
  return new RegExp(`\\b(?:${words.join("|")})\\b|${paths.join("|")}`);
})();

const RULES = [
  { name: "private key material", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/ },
  { name: "fine-grained GitHub token", re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/ },
  { name: "openai-style key", re: /\bsk-[A-Za-z0-9]{32,}\b/ },
  { name: "anthropic-style key", re: /\bsk-ant-[A-Za-z0-9_-]{24,}\b/ },
  { name: "AWS access key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "Alibaba Cloud access key", re: /\bLTAI[A-Za-z0-9]{16,24}\b/ },
  { name: "signed JWT token", re: /\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/ },
  { name: "release keystore filename", re: /\bnibi-go-release\.p12\b/i },
  {
    name: "workspace/home absolute path",
    re: /(?:[A-Za-z]:[\\/]Users[\\/]|[A-Za-z]:[\\/]NIBI|\/Users\/|\/home\/[A-Za-z])/,
  },
  { name: "server root path", re: /\/srv\/nibi/ },
  { name: "internal infra or device identifier", re: INTERNAL_INFRA_RE },
  {
    name: "public IPv4 URL",
    re: /https?:\/\/(?!127\.|0\.0\.0\.0|localhost|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}/,
  },
  {
    name: "internal container registry",
    re: /\b[A-Za-z0-9.-]+\.(?:cr\.aliyuncs\.com|tencentcloudcr\.com)\b/,
  },
  {
    name: "unpinned action",
    re: /^\s*-?\s*uses:\s+(?!\.\/|docker:\/\/)[^\s#]+@(?![0-9a-f]{40}(?:\s|$))/,
  },
];

// 本脚本自身含规则字面量，跳过内容扫描（与 NIBI-GO 的 check-public-repo 同款处理）。
const SKIP_CONTENT = new Set(["scripts/check-leaks.mjs"]);
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const MAX_ASSET_BYTES = 5 * 1024 * 1024;

function scanImageFile(file, fullPath, failures) {
  const buf = fs.readFileSync(fullPath);
  if (buf.length > MAX_ASSET_BYTES) {
    failures.push(`${file} 超过 5 MiB 图片大小上限（${buf.length} bytes）`);
  }
  if (file.endsWith(".png") && buf.length >= 8 && buf.subarray(0, 8).equals(PNG_SIG)) {
    let offset = 8;
    while (offset + 12 <= buf.length) {
      const len = buf.readUInt32BE(offset);
      const type = buf.subarray(offset + 4, offset + 8).toString("ascii");
      const dataStart = offset + 8;
      const dataEnd = dataStart + len;
      if (dataEnd + 4 > buf.length) break;
      if (type === "eXIf") {
        failures.push(`${file} 含 EXIF 元数据（提交前须清除）`);
      } else if (type === "tEXt" || type === "iTXt") {
        const text = buf.subarray(dataStart, dataEnd).toString("utf8").replace(/\0/g, " ");
        for (const rule of RULES) {
          if (rule.re.test(text)) failures.push(`${file} PNG ${type} 元数据命中「${rule.name}」`);
        }
      }
      offset = dataEnd + 4;
    }
  } else if (file.endsWith(".gif")) {
    for (let i = 0; i + 2 < buf.length; i += 1) {
      if (buf[i] === 0x21 && buf[i + 1] === 0xfe) {
        let p = i + 2;
        const parts = [];
        while (p < buf.length && buf[p] > 0) {
          const subLen = buf[p];
          parts.push(buf.subarray(p + 1, Math.min(buf.length, p + 1 + subLen)));
          p += 1 + subLen;
        }
        const comment = Buffer.concat(parts).toString("utf8");
        for (const rule of RULES) {
          if (rule.re.test(comment)) failures.push(`${file} GIF 注释命中「${rule.name}」`);
        }
      }
    }
  }
}

const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "buffer" })
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

const failures = [];
for (const file of tracked) {
  if (!ALLOWED.some((re) => re.test(file))) {
    failures.push(`未被允许的文件：${file}`);
    continue;
  }
  const fullPath = path.join(ROOT, file);
  if (file.endsWith(".zip")) {
    const size = fs.statSync(fullPath).size;
    if (size > 64 * 1024 * 1024) failures.push(`${file} 超过 64 MiB`);
    continue;
  }
  if (file.endsWith(".png") || file.endsWith(".gif")) {
    scanImageFile(file, fullPath, failures);
    continue;
  }
  if (SKIP_CONTENT.has(file)) continue;
  const text = fs.readFileSync(fullPath, "utf8");
  text.split("\n").forEach((line, index) => {
    for (const rule of RULES) {
      if (rule.re.test(line)) failures.push(`${file}:${index + 1} 命中「${rule.name}」`);
    }
  });
}

if (failures.length > 0) {
  console.error(`市场仓泄露门禁失败：\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`市场仓泄露门禁通过：${tracked.length} 个文件。`);

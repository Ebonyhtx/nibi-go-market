#!/usr/bin/env node
// 市场仓的泄露门禁：只允许白名单文件，且文本里不得出现凭据/本机路径/内部基础设施。
//
// 市场仓是公开仓：这里只应有索引、签名、插件包、README 与门禁脚本本身。
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");

const ALLOWED = [
  /^README\.md$/,
  /^index\.json$/,
  /^index\.json\.sig$/,
  /^packages\/[a-z0-9][a-z0-9._-]{0,80}\.zip$/,
  /^scripts\/validate\.mjs$/,
  /^scripts\/check-leaks\.mjs$/,
  /^\.github\/workflows\/validate\.yml$/,
];

const RULES = [
  { name: "private key material", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/ },
  { name: "fine-grained GitHub token", re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/ },
  { name: "openai-style key", re: /\bsk-[A-Za-z0-9]{32,}\b/ },
  { name: "AWS access key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "workspace/home absolute path", re: /(?:[A-Za-z]:[\/]Users|[A-Za-z]:[\/]NIBI|\/Users\/|\/home\/)/ },
  { name: "server root path", re: /\/srv\/nibi/ },
  {
    name: "internal infra identifier",
    re: /\b(?:nibi-dist-hz|nibi-paid-hz|nibi-backup-hz|nibi-feedback-hz|nibi-logs-hz|ossutil-publish|nibi-cn)\b/,
  },
  {
    name: "public IPv4 URL",
    re: /https?:\/\/(?!127\.|0\.0\.0\.0|localhost)\d{1,3}(?:\.\d{1,3}){3}/,
  },
];

// 本脚本自身含规则字面量，跳过内容扫描（与 NIBI-GO 的 check-public-repo 同款处理）。
const SKIP_CONTENT = new Set(["scripts/check-leaks.mjs"]);

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
  if (file.endsWith(".zip")) {
    const size = fs.statSync(path.join(ROOT, file)).size;
    if (size > 64 * 1024 * 1024) failures.push(`${file} 超过 64 MiB`);
    continue;
  }
  if (SKIP_CONTENT.has(file)) continue;
  const text = fs.readFileSync(path.join(ROOT, file), "utf8");
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

#!/usr/bin/env node
// 待审提交的门禁（NIBI-GO 独立手机市场）：
// - 标准 npm MCP（format: "npm"）：拉取 npm registry 元数据与 tarball，核验精确版本、SRI integrity、
//   纯 JS 入口，拒绝非 Linux os / gypfile / postinstall / 原生二进制；
// - 外部 HTTPS ZIP（format: "zip" + url，如 GitHub Releases）：下载校验 sha256/size，兼容标准
//   .nibi-plugin/.claude-plugin/.codex-plugin/skills 或 nibi-go.plugin.json；
// - 兼容旧版仓内 ZIP（packages/<id>-<version>.zip）。
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { scanNpmTarballBytes, scanPackage, scanZipBytes } from "./scan-package.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const KNOWN_CAPS = new Set(["view.v1", "slots.v1", "effects.v1", "mcp.v1"]);
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const VERSION_RE = /^\d{1,6}(?:\.\d{1,6}){0,2}(?:[-+][0-9A-Za-z.-]{1,32})?$/u;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const NPM_NAME_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/u;
const SRI_RE = /^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/u;
const GITHUB_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/u;
const NPM_REGISTRIES = ["https://registry.npmjs.org", "https://registry.npmmirror.com"];

// PR 作者由 workflow 注入；本地跑时为空，只做归属一致性（不做作者比对）。
const ACTOR = (process.env.PR_AUTHOR || process.env.GITHUB_ACTOR || "").trim();
const MAINTAINERS = new Set(
  (process.env.MARKET_MAINTAINERS || "Ebonyhtx")
    .split(",")
    .map((name) => name.trim().toLowerCase())
    .filter(Boolean),
);
const SKIP_NETWORK = process.env.MARKET_SKIP_NETWORK === "1";

const failures = [];
const fail = (message) => failures.push(message);

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${path.relative(ROOT, file)} 不是合法 JSON：${error.message}`);
    return null;
  }
}

function packagePinDigest(pkg) {
  if (!pkg || typeof pkg !== "object") return "";
  if (pkg.format === "npm") return `npm:${pkg.name}@${pkg.version}:${pkg.integrity}`;
  return `zip:${pkg.sha256}`;
}

function verifySri(bytes, integrity) {
  const match = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+=*)$/u.exec(integrity);
  if (!match) return false;
  const actual = createHash(match[1]).update(bytes).digest("base64");
  return actual === match[2];
}

async function fetchBuffer(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  } finally {
    clearTimeout(timer);
  }
}

async function verifyNpmSubmission(relative, data) {
  const pkg = data.package;
  if (typeof pkg.name !== "string" || !NPM_NAME_RE.test(pkg.name)) {
    fail(`${relative} package.name 不是合法 npm 包名`);
    return;
  }
  const pkgVer = pkg.version ?? data.version;
  if (pkgVer !== data.version) {
    fail(`${relative} package.version（${pkgVer}）必须与顶层 version（${data.version}）一致`);
    return;
  }
  if (typeof pkg.integrity !== "string" || !SRI_RE.test(pkg.integrity)) {
    fail(`${relative} package.integrity 必须是合法 SRI 摘要`);
    return;
  }
  if (SKIP_NETWORK) return;

  let doc = null;
  let lastError = null;
  for (const reg of NPM_REGISTRIES) {
    try {
      const buf = await fetchBuffer(`${reg}/${pkg.name}/${encodeURIComponent(pkgVer)}`);
      doc = JSON.parse(buf.toString("utf8"));
      break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!doc) {
    fail(`${relative} 无法从 npm registry 拉取 ${pkg.name}@${pkgVer}：${lastError?.message ?? "未知错误"}`);
    return;
  }
  if (doc.dist?.integrity !== pkg.integrity) {
    fail(
      `${relative} integrity 不匹配（提交 ${pkg.integrity}，registry ${doc.dist?.integrity ?? "缺失"}）`,
    );
  }
  if (Array.isArray(doc.os) && doc.os.length > 0) {
    const positives = doc.os.filter((item) => !String(item).startsWith("!"));
    const negatives = doc.os.filter((item) => String(item).startsWith("!"));
    if (
      negatives.includes("!linux") ||
      negatives.includes("!android") ||
      (positives.length > 0 && !positives.includes("linux") && !positives.includes("android"))
    ) {
      fail(`${relative} 的 npm 包 os=${doc.os.join(",")} 不兼容 Android 手机端`);
    }
  }
  if (!doc.bin && !doc.main) {
    fail(`${relative} 的 npm 包缺少可用 bin/main 入口`);
  }
  const tarballUrl = doc.dist?.tarball;
  if (typeof tarballUrl !== "string" || !tarballUrl.startsWith("https://")) {
    fail(`${relative} 缺少合法的 npm tarball 地址`);
    return;
  }
  let tgzBytes;
  try {
    tgzBytes = await fetchBuffer(tarballUrl);
  } catch (error) {
    fail(`${relative} 下载 npm tarball 失败：${error.message}`);
    return;
  }
  if (!verifySri(tgzBytes, pkg.integrity)) {
    fail(`${relative} 下载的 npm tarball 字节与 integrity 不匹配`);
    return;
  }
  const scan = scanNpmTarballBytes(tgzBytes, `${pkg.name}@${pkgVer}`);
  for (const item of scan.findings) {
    const line = `${relative} 扫描[${item.rule}] ${item.file}: ${item.detail}`;
    if (item.severity === "high") fail(line);
    else console.warn(`审查提示：${line}`);
  }
}

/** 读 zip 内的插件清单：兼容 nibi-go.plugin.json 与标准 .nibi/.claude/.codex-plugin/plugin.json。 */
function inspectZipManifest(zipPath) {
  const pyCode = [
    "import json, sys, zipfile",
    "z = zipfile.ZipFile(sys.argv[1])",
    "names = [n for n in z.namelist() if not n.endswith('/')]",
    "targets = ['nibi-go.plugin.json', '.nibi-plugin/plugin.json', '.claude-plugin/plugin.json', '.codex-plugin/plugin.json']",
    "found = None",
    "for t in targets:",
    "  for n in names:",
    "    if n == t or n.endswith('/' + t) and n.count('/') == t.count('/') + 1:",
    "      found = (t, z.read(n).decode('utf-8'))",
    "      break",
    "  if found: break",
    "if found:",
    "  print(json.dumps({'kind': found[0], 'text': found[1]}))",
    "elif any(n.endswith('SKILL.md') or '/commands/' in ('/' + n) for n in names):",
    "  print(json.dumps({'kind': 'skill-bundle', 'text': '{}'}))",
    "else:",
    "  sys.exit(2)",
  ].join("\n");
  for (const bin of ["python3", "python"]) {
    try {
      const out = execFileSync(bin, ["-c", pyCode, zipPath], { encoding: "utf8" });
      const parsed = JSON.parse(out);
      return { kind: parsed.kind, json: JSON.parse(parsed.text) };
    } catch {
      // 继续尝试下一个解释器
    }
  }
  return null;
}

const index = readJson(path.join(ROOT, "index.json")) ?? { plugins: [] };
const approved = new Map((index.plugins ?? []).map((plugin) => [plugin.id, plugin]));

const submissionDir = path.join(ROOT, "submissions");
const files = fs.existsSync(submissionDir)
  ? fs
      .readdirSync(submissionDir)
      .filter((name) => name.endsWith(".json"))
      .sort()
  : [];

const seen = new Set();
const isMaintainer = !ACTOR || MAINTAINERS.has(ACTOR.toLowerCase());

for (const name of files) {
  const relative = `submissions/${name}`;
  const data = readJson(path.join(ROOT, relative));
  if (!data) continue;
  const before = approved.get(data.id);

  if (data.schemaVersion !== 1) fail(`${relative} schemaVersion 必须是 1`);
  if (typeof data.id !== "string" || !ID_RE.test(data.id)) fail(`${relative} id 不合法`);
  if (typeof data.version !== "string" || !VERSION_RE.test(data.version)) fail(`${relative} version 不合法`);
  if (typeof data.name !== "string" || !data.name.trim()) fail(`${relative} name 必填`);
  if (typeof data.description === "string" && data.description.length > 280) fail(`${relative} description 超过 280 字`);
  if (typeof data.license !== "string" || !data.license.trim() || data.license === "UNLICENSED") {
    fail(`${relative} 必须声明 license（不接受 UNLICENSED）`);
  }
  if (typeof data.contact !== "string" || !data.contact.trim()) fail(`${relative} contact 必填`);
  if ("paid" in data) fail(`${relative} 不应声明 paid（付费条目由维护者发布）`);

  const publisher = data.publisher;
  if (
    !publisher ||
    typeof publisher !== "object" ||
    typeof publisher.name !== "string" ||
    !publisher.name.trim() ||
    typeof publisher.github !== "string" ||
    !GITHUB_RE.test(publisher.github)
  ) {
    fail(`${relative} 必须声明 publisher.name 与 publisher.github（GitHub 登录名）`);
  } else {
    if (!isMaintainer && publisher.github.toLowerCase() !== ACTOR.toLowerCase()) {
      fail(`${relative} publisher.github（@${publisher.github}）必须等于 PR 作者 @${ACTOR}`);
    }
    if (typeof data.source !== "string" || !data.source.trim()) {
      fail(`${relative} source 必填（用于核对插件归属）`);
    } else {
      const source = /^https:\/\/github\.com\/([^/]+)\/([^/#?]+)/iu.exec(data.source.trim());
      if (!source) {
        fail(`${relative} source 必须是 GitHub 仓库地址`);
      } else if (!isMaintainer && source[1].toLowerCase() !== publisher.github.toLowerCase()) {
        fail(`${relative} source 仓库 owner（@${source[1]}）必须等于 publisher.github（@${publisher.github}）`);
      }
    }
    if (before?.publisherGithub && before.publisherGithub.toLowerCase() !== publisher.github.toLowerCase()) {
      fail(`${relative} 插件 id ${data.id} 已归 @${before.publisherGithub} 所有，不能由 @${publisher.github} 更新`);
    }
    if (before && !before.publisherGithub && !isMaintainer) {
      fail(`${relative} 插件 id ${data.id} 是未绑定发布者的历史条目，只能由维护者更新`);
    }
  }
  if (data.runtime !== undefined && data.runtime !== "node" && data.runtime !== "declarative") {
    fail(`${relative} runtime 只能是 node/declarative`);
  }
  const caps = Array.isArray(data.caps) ? data.caps : [];
  for (const cap of caps) {
    if (!KNOWN_CAPS.has(cap)) fail(`${relative} 未知 caps：${cap}`);
  }

  const key = `${data.id}@${data.version}`;
  if (seen.has(key)) fail(`重复提交：${key}`);
  seen.add(key);
  if (name !== `${data.id}-${data.version}.json`) {
    fail(`${relative} 文件名必须是 ${data.id}-${data.version}.json`);
  }

  const pkg = data.package ?? {};
  if (pkg.format === "npm") {
    const normalizedPkg = { ...pkg, version: pkg.version ?? data.version };
    if (before && before.version === data.version && packagePinDigest(before.package) !== packagePinDigest(normalizedPkg)) {
      fail(`${relative} 与已上架的 ${key} 摘要不一致（同版本不可变）`);
    }
    await verifyNpmSubmission(relative, data);
    continue;
  }

  if (!SHA256_RE.test(pkg.sha256 ?? "")) fail(`${relative} package.sha256 必须是 64 位小写 hex`);
  if (!Number.isInteger(pkg.size) || pkg.size <= 0) fail(`${relative} package.size 必须是正整数`);

  if (typeof pkg.url === "string") {
    if (!pkg.url.startsWith("https://")) {
      fail(`${relative} package.url 必须是 https 地址`);
      continue;
    }
    if (before && before.version === data.version && packagePinDigest(before.package) !== `zip:${pkg.sha256}`) {
      fail(`${relative} 与已上架的 ${key} 摘要不一致（同版本不可变）`);
    }
    if (!SKIP_NETWORK) {
      try {
        const bytes = await fetchBuffer(pkg.url);
        if (bytes.length !== pkg.size) fail(`${relative} 远端 ZIP 大小与元数据不一致`);
        const digest = createHash("sha256").update(bytes).digest("hex");
        if (digest !== pkg.sha256) fail(`${relative} 远端 ZIP 摘要与元数据不一致`);
        const scan = scanZipBytes(bytes, relative);
        for (const item of scan.findings) {
          const line = `${relative} 扫描[${item.rule}] ${item.file}: ${item.detail}`;
          if (item.severity === "high") fail(line);
          else console.warn(`审查提示：${line}`);
        }
      } catch (error) {
        fail(`${relative} 拉取远端 ZIP 失败：${error.message}`);
      }
    }
    continue;
  }

  // 兼容旧版仓内 ZIP
  const expectedFile = `packages/${data.id}-${data.version}.zip`;
  if (pkg.file !== expectedFile) fail(`${relative} package.file 必须是 ${expectedFile}`);
  const zipPath = path.join(ROOT, expectedFile);
  if (!fs.existsSync(zipPath)) {
    fail(`${relative} 引用的包不存在：${expectedFile}`);
    continue;
  }
  const bytes = fs.readFileSync(zipPath);
  if (bytes.length !== pkg.size) fail(`${relative} 包大小与元数据不一致`);
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== pkg.sha256) fail(`${relative} 包摘要与元数据不一致`);

  if (before && before.version === data.version && packagePinDigest(before.package) !== `zip:${pkg.sha256}`) {
    fail(`${relative} 与已上架的 ${key} 摘要不一致（同版本不可变）`);
  }

  const manifestInfo = inspectZipManifest(zipPath);
  if (!manifestInfo) {
    fail(`${relative} 找不到合法插件清单或技能文件`);
  } else if (manifestInfo.kind === "nibi-go.plugin.json") {
    const manifest = manifestInfo.json;
    if (manifest.schemaVersion !== 1) fail(`${relative} 包内清单 schemaVersion 必须是 1`);
    if (manifest.id !== data.id) fail(`${relative} 包内清单 id（${manifest.id}）与提交不一致`);
    if (manifest.version !== data.version) fail(`${relative} 包内清单 version（${manifest.version}）与提交不一致`);
    if (manifest.name !== data.name) fail(`${relative} 包内清单 name（${manifest.name}）与提交不一致`);
  }

  const scan = scanPackage(zipPath, relative);
  for (const item of scan.findings) {
    const line = `${relative} 扫描[${item.rule}] ${item.file}: ${item.detail}`;
    if (item.severity === "high") fail(line);
    else console.warn(`审查提示：${line}`);
  }
}

if (failures.length > 0) {
  console.error(`提交门禁失败：\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`提交门禁通过：${files.length} 个待审提交。`);

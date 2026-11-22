#!/usr/bin/env node
// GitHub Actions 合并后自动发布并签名 index.json（也可本机 --dry-run 预演）：
//
// 流程：
// 1. 扫描 submissions/*.json，按版本前进合并进 index.json（整批只递增 1 次 revision）；
// 2. 若无变化则直接退出（不产生空提交）；
// 3. 从环境变量 NIBI_MARKET_SIGNING_KEY_JSON 读取 Ed25519 私钥 JWK 签发 index.json.sig；
// 4. 用内置公钥回读自检签名；失败不写坏状态。
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const RAW_PREFIX = "https://raw.githubusercontent.com/Ebonyhtx/nibi-go-market/main/";
const PUBLIC_KEY_HEX = "90c6acbb9a020d1d567807620250a56e5822e70324b894bbc3a03fe3a6a2fd04";
const dryRun = process.argv.includes("--dry-run");

function compareVersions(a, b) {
  const core = (value) => String(value).split(/[-+]/u)[0].split(".").map((part) => Number(part) || 0);
  const left = core(a);
  const right = core(b);
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

function packagePinDigest(pkg) {
  if (!pkg || typeof pkg !== "object") return "";
  if (pkg.format === "npm") return `npm:${pkg.name}@${pkg.version}:${pkg.integrity}`;
  return `zip:${pkg.sha256}`;
}

function resolvePackage(sub) {
  const raw = sub.package;
  if (raw.format === "npm") {
    return {
      format: "npm",
      name: raw.name,
      version: raw.version ?? sub.version,
      integrity: raw.integrity,
      ...(raw.size !== undefined ? { size: raw.size } : {}),
      ...(raw.bin !== undefined ? { bin: raw.bin } : {}),
      ...(raw.args !== undefined ? { args: raw.args } : {}),
      ...(raw.env !== undefined ? { env: raw.env } : {}),
      ...(raw.serverName !== undefined ? { serverName: raw.serverName } : {}),
      ...(raw.alwaysLoad !== undefined ? { alwaysLoad: raw.alwaysLoad } : {}),
      ...(raw.timeoutMs !== undefined ? { timeoutMs: raw.timeoutMs } : {}),
    };
  }
  if (typeof raw.url === "string") {
    return {
      format: "zip",
      url: raw.url,
      sha256: raw.sha256,
      size: raw.size,
    };
  }
  return {
    format: "zip",
    url: `${RAW_PREFIX}${raw.file}`,
    sha256: raw.sha256,
    size: raw.size,
  };
}

const indexPath = path.join(ROOT, "index.json");
const sigPath = path.join(ROOT, "index.json.sig");
const index = JSON.parse(fs.readFileSync(indexPath, "utf8"));

const submissionDir = path.join(ROOT, "submissions");
const files = fs.existsSync(submissionDir)
  ? fs
      .readdirSync(submissionDir)
      .filter((name) => name.endsWith(".json"))
      .sort()
  : [];

const pluginsById = new Map((index.plugins ?? []).map((plugin) => [plugin.id, plugin]));
const updatedIds = [];

// 同一 id 有多个历史提交文件时按版本号从小到大应用，确保最终落定最高版本。
const submissions = files
  .map((file) => JSON.parse(fs.readFileSync(path.join(submissionDir, file), "utf8")))
  .sort((a, b) => (a.id === b.id ? compareVersions(a.version, b.version) : a.id.localeCompare(b.id)));

for (const sub of submissions) {
  const pkg = resolvePackage(sub);
  const existing = pluginsById.get(sub.id);
  if (existing) {
    const cmp = compareVersions(sub.version, existing.version);
    if (cmp < 0) continue;
    if (cmp === 0) {
      if (packagePinDigest(existing.package) !== packagePinDigest(pkg)) {
        throw new Error(`同版本 ${sub.id}@${sub.version} 摘要冲突`);
      }
      continue;
    }
  }
  const entry = {
    id: sub.id,
    name: sub.name,
    version: sub.version,
    ...(sub.description ? { description: sub.description } : {}),
    ...(sub.kind ? { kind: sub.kind } : pkg.format === "npm" ? { kind: "mcp" } : {}),
    caps: sub.caps,
    ...(sub.runtime ? { runtime: sub.runtime } : pkg.format === "npm" ? { runtime: "node" } : {}),
    license: sub.license,
    ...(sub.homepage ? { homepage: sub.homepage } : {}),
    ...(sub.source ? { source: sub.source } : {}),
    ...(sub.publisher?.name ? { publisher: sub.publisher.name } : {}),
    ...(sub.publisher?.github ? { publisherGithub: sub.publisher.github } : {}),
    package: pkg,
  };
  pluginsById.set(sub.id, entry);
  updatedIds.push(`${sub.id}@${sub.version}`);
}

if (updatedIds.length === 0) {
  console.log("无新增或升级提交，index.json 无需更新。");
  process.exit(0);
}

const nextIndex = {
  ...index,
  revision: index.revision + 1,
  generatedAt: new Date().toISOString(),
  plugins: [...pluginsById.values()],
};
const nextBytes = Buffer.from(`${JSON.stringify(nextIndex, null, 2)}\n`, "utf8");

if (dryRun) {
  console.log(`[dry-run] 将更新 revision ${index.revision} → ${nextIndex.revision}：${updatedIds.join(", ")}`);
  process.exit(0);
}

const keyJsonRaw = (process.env.NIBI_MARKET_SIGNING_KEY_JSON || "").trim();
if (!keyJsonRaw) {
  console.error("缺少环境变量 NIBI_MARKET_SIGNING_KEY_JSON（请配置 GitHub Environment Secret）");
  process.exit(1);
}
const keyObj = JSON.parse(keyJsonRaw);
const privateJwk = keyObj.privateJwk ?? keyObj;
const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
const signatureHex = sign(null, nextBytes, privateKey).toString("hex");

// 落盘前先用内置公钥自检，确保签名匹配客户端信任根。
const spki = Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"),
  Buffer.from(PUBLIC_KEY_HEX, "hex"),
]);
const publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
if (!verify(null, nextBytes, publicKey, Buffer.from(signatureHex, "hex"))) {
  console.error("签名自检失败：环境变量私钥与内置公钥不匹配");
  process.exit(1);
}

fs.writeFileSync(indexPath, nextBytes);
fs.writeFileSync(sigPath, `${signatureHex}\n`);
console.log(`已自动发布并签名 revision ${nextIndex.revision}：${updatedIds.join(", ")}`);

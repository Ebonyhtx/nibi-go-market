#!/usr/bin/env node
// 市场仓的发布门禁：签名、schema、包摘要、revision/版本不变量。
// 只读；不接触私钥。CI 与本地都可以跑：node scripts/validate.mjs [--before <git-ref>]
import { createHash, createPublicKey, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const MARKET = "nibi-official";
const PUBLIC_KEY_HEX = "90c6acbb9a020d1d567807620250a56e5822e70324b894bbc3a03fe3a6a2fd04";
const RAW_PREFIX = "https://raw.githubusercontent.com/Ebonyhtx/nibi-go-market/main/";

const failures = [];
function fail(message) {
  failures.push(message);
}

function readIndexBytes(ref) {
  if (!ref) return null;
  try {
    return execFileSync("git", ["show", `${ref}:index.json`], { cwd: ROOT });
  } catch {
    return null;
  }
}

const indexBytes = fs.readFileSync(path.join(ROOT, "index.json"));
const signatureHex = fs.readFileSync(path.join(ROOT, "index.json.sig"), "utf8").trim();

// 1) 签名
const spki = Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"),
  Buffer.from(PUBLIC_KEY_HEX, "hex"),
]);
const publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
if (!/^[0-9a-f]{128}$/u.test(signatureHex)) fail("index.json.sig 必须是 128 位小写 hex");
else if (!verify(null, indexBytes, publicKey, Buffer.from(signatureHex, "hex"))) {
  fail("index.json 签名校验失败（漏签/改过/私钥不匹配）");
}

// 2) schema
let index;
try {
  index = JSON.parse(indexBytes.toString("utf8"));
} catch {
  fail("index.json 不是合法 JSON");
}
if (!index) {
  report();
} else {
  if (index.schemaVersion !== 1) fail("schemaVersion 必须是 1");
  if (index.market !== MARKET) fail(`market 必须是 ${MARKET}`);
  if (!Number.isInteger(index.revision) || index.revision < 1) fail("revision 必须是正整数");
  if (!Array.isArray(index.plugins)) fail("plugins 必须是数组");
  const seen = new Set();
  for (const plugin of index.plugins ?? []) {
    if (typeof plugin.id !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/u.test(plugin.id)) {
      fail(`插件 id 不合法：${plugin.id}`);
    } else if (seen.has(plugin.id)) {
      fail(`插件 id 重复：${plugin.id}`);
    } else seen.add(plugin.id);
    if (typeof plugin.version !== "string") fail(`${plugin.id} 缺少 version`);
    const pkg = plugin.package ?? {};
    if (typeof pkg.url !== "string" || !pkg.url.startsWith(RAW_PREFIX)) {
      fail(`${plugin.id} 的包地址必须在本仓 raw 前缀下`);
      continue;
    }
    const local = path.join(ROOT, pkg.url.slice(RAW_PREFIX.length));
    if (!fs.existsSync(local)) {
      fail(`${plugin.id} 的包文件不存在：${pkg.url.slice(RAW_PREFIX.length)}`);
      continue;
    }
    const bytes = fs.readFileSync(local);
    if (!/^[0-9a-f]{64}$/u.test(pkg.sha256 ?? "")) fail(`${plugin.id} 的 sha256 格式不对`);
    else if (createHash("sha256").update(bytes).digest("hex") !== pkg.sha256) {
      fail(`${plugin.id} 的包摘要与索引不一致`);
    }
    if (pkg.size !== bytes.length) fail(`${plugin.id} 的包大小与索引不一致`);
  }

  // 3) 与上一个提交比较：revision 只能前进，版本只能前进、同版本摘要不可变
  const beforeIndex = process.argv.includes("--before")
    ? readIndexBytes(process.argv[process.argv.indexOf("--before") + 1])
    : null;
  if (beforeIndex) {
    try {
      const before = JSON.parse(beforeIndex.toString("utf8"));
      if (index.revision < before.revision) {
        fail(`revision 倒退：${before.revision} → ${index.revision}`);
      } else if (index.revision === before.revision && !indexBytes.equals(beforeIndex)) {
        fail(`revision ${index.revision} 的字节与上一提交不一致`);
      }
      const known = new Map((before.plugins ?? []).map((plugin) => [plugin.id, plugin]));
      for (const plugin of index.plugins ?? []) {
        const prev = known.get(plugin.id);
        if (!prev) continue;
        const cmp = compareVersions(plugin.version, prev.version);
        if (cmp < 0) fail(`${plugin.id} 版本倒退：${prev.version} → ${plugin.version}`);
        if (cmp === 0 && plugin.package?.sha256 !== prev.package?.sha256) {
          fail(`${plugin.id} 同版本 ${plugin.version} 的包摘要变了`);
        }
      }
    } catch {
      fail("上一提交的 index.json 无法解析");
    }
  }
}

function compareVersions(a, b) {
  const core = (value) => String(value).split(/[-+]/u)[0].split(".").map((part) => Number(part) || 0);
  const left = core(a);
  const right = core(b);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const diff = (left[index] ?? 0) - (right[index] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

function report() {
  if (failures.length > 0) {
    console.error(`市场门禁失败：\n- ${failures.join("\n- ")}`);
    process.exit(1);
  }
  console.log(`市场门禁通过：revision ${index.revision}，${(index.plugins ?? []).length} 个插件。`);
  process.exit(0);
}

report();

#!/usr/bin/env node
// 待审提交的门禁：元数据、包文件、摘要、包内清单一致性与必要声明。
//
// 这里只校对“能不能进人工审查”，不代表上架；上架仍由维护者更新并签名 index.json。
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const KNOWN_CAPS = new Set(["view.v1", "slots.v1", "effects.v1", "mcp.v1"]);
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const VERSION_RE = /^\d{1,6}(?:\.\d{1,6}){0,2}(?:[-+][0-9A-Za-z.-]{1,32})?$/u;
const SHA256_RE = /^[0-9a-f]{64}$/u;

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

/** 读 zip 根目录的插件清单：python3 → python → unzip 依次尝试（CI/本地都可跑）。 */
function readManifest(zipPath) {
  const attempts = [
    () =>
      execFileSync(
        "python3",
        [
          "-c",
          "import sys,zipfile;sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read('nibi-go.plugin.json').decode('utf-8'))",
          zipPath,
        ],
        { encoding: "utf8" },
      ),
    () =>
      execFileSync(
        "python",
        [
          "-c",
          "import sys,zipfile;sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read('nibi-go.plugin.json').decode('utf-8'))",
          zipPath,
        ],
        { encoding: "utf8" },
      ),
    () => execFileSync("unzip", ["-p", zipPath, "nibi-go.plugin.json"], { encoding: "utf8" }),
  ];
  let lastError = null;
  for (const attempt of attempts) {
    try {
      return JSON.parse(attempt());
    } catch (error) {
      lastError = error;
    }
  }
  fail(`${path.relative(ROOT, zipPath)} 读不到根目录 nibi-go.plugin.json：${lastError?.message ?? "未知错误"}`);
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
for (const name of files) {
  const relative = `submissions/${name}`;
  const data = readJson(path.join(ROOT, relative));
  if (!data) continue;

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
  if (data.runtime !== undefined && data.runtime !== "node" && data.runtime !== "declarative") {
    fail(`${relative} runtime 只能是 node/declarative`);
  }
  const caps = Array.isArray(data.caps) ? data.caps : [];
  for (const cap of caps) {
    if (!KNOWN_CAPS.has(cap)) fail(`${relative} 未知 caps：${cap}`);
  }

  const pkg = data.package ?? {};
  const expectedFile = `packages/${data.id}-${data.version}.zip`;
  if (pkg.file !== expectedFile) fail(`${relative} package.file 必须是 ${expectedFile}`);
  if (!SHA256_RE.test(pkg.sha256 ?? "")) fail(`${relative} package.sha256 必须是 64 位小写 hex`);
  if (!Number.isInteger(pkg.size) || pkg.size <= 0) fail(`${relative} package.size 必须是正整数`);

  const key = `${data.id}@${data.version}`;
  if (seen.has(key)) fail(`重复提交：${key}`);
  seen.add(key);
  if (name !== `${data.id}-${data.version}.json`) {
    fail(`${relative} 文件名必须是 ${data.id}-${data.version}.json`);
  }

  const zipPath = path.join(ROOT, expectedFile);
  if (!fs.existsSync(zipPath)) {
    fail(`${relative} 引用的包不存在：${expectedFile}`);
    continue;
  }
  const bytes = fs.readFileSync(zipPath);
  if (bytes.length !== pkg.size) fail(`${relative} 包大小与元数据不一致`);
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== pkg.sha256) fail(`${relative} 包摘要与元数据不一致`);

  const before = approved.get(data.id);
  if (before) {
    if (before.version === data.version && before.package?.sha256 !== pkg.sha256) {
      fail(`${relative} 与已上架的 ${key} 摘要不一致（同版本不可变）`);
    }
  }

  const manifest = readManifest(zipPath);
  if (manifest) {
    if (manifest.schemaVersion !== 1) fail(`${relative} 包内清单 schemaVersion 必须是 1`);
    if (manifest.id !== data.id) fail(`${relative} 包内清单 id（${manifest.id}）与提交不一致`);
    if (manifest.version !== data.version) fail(`${relative} 包内清单 version（${manifest.version}）与提交不一致`);
    if (manifest.name !== data.name) fail(`${relative} 包内清单 name（${manifest.name}）与提交不一致`);
  }
}

if (failures.length > 0) {
  console.error(`提交门禁失败：\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`提交门禁通过：${files.length} 个待审提交。`);

#!/usr/bin/env node
// yanked.json 门禁：撤回记录的形状与跨文件一致性。
//
// 规则（与 NIBI-GO 的 packages/market-index/src/yank.ts 保持一致）：
// - 每条记录有 id/version/reason/yankedAt/revision，reason 非空且 ≤500 字；
// - 同一 (id, version) 只能撤回一次；
// - revision 按文件顺序严格递增；
// - 当前 index.json 里不得仍有与撤回记录同 (id, version) 的条目（更高版本可以回归）。
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const INDEX_FILE = path.join(ROOT, "index.json");
const YANK_FILE = path.join(ROOT, "yanked.json");

const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const VERSION_RE = /^\d{1,6}(?:\.\d{1,6}){0,2}(?:[-+][0-9A-Za-z.-]{1,32})?$/u;

const failures = [];
const fail = (message) => failures.push(message);

function readJson(file, label) {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${label} 不是合法 JSON：${error.message}`);
    return null;
  }
}

const index = readJson(INDEX_FILE, "index.json");
const yankLog = readJson(YANK_FILE, "yanked.json");
if (failures.length > 0) {
  console.error(`撤回记录门禁失败：\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
if (yankLog === null) {
  console.log("撤回记录门禁通过：没有 yanked.json（尚无撤回）。");
  process.exit(0);
}

if (yankLog.schemaVersion !== 1 || !Array.isArray(yankLog.entries)) {
  fail("yanked.json 必须形如 { schemaVersion: 1, entries: [...] }");
}
const plugins = Array.isArray(index?.plugins) ? index.plugins : [];
const seen = new Set();
let previousRevision = 0;

(yankLog.entries ?? []).forEach((entry, position) => {
  const label = `entries[${position}]`;
  if (typeof entry !== "object" || entry === null) {
    fail(`${label} 必须是对象`);
    return;
  }
  if (typeof entry.id !== "string" || !ID_RE.test(entry.id)) fail(`${label}.id 不合法`);
  if (typeof entry.version !== "string" || !VERSION_RE.test(entry.version)) {
    fail(`${label}.version 不合法`);
  }
  if (typeof entry.reason !== "string" || entry.reason.trim() === "" || entry.reason.length > 500) {
    fail(`${label}.reason 必须是 1–500 字的非空字符串`);
  }
  if (typeof entry.yankedAt !== "string" || Number.isNaN(Date.parse(entry.yankedAt))) {
    fail(`${label}.yankedAt 必须是 ISO 时间`);
  }
  if (!Number.isInteger(entry.revision) || entry.revision < 1) {
    fail(`${label}.revision 必须是正整数`);
    return;
  }
  if (entry.revision <= previousRevision) {
    fail(`${label}.revision 必须严格递增（上一条 ${previousRevision}，本条 ${entry.revision}）`);
  }
  previousRevision = Math.max(previousRevision, entry.revision);

  const key = `${entry.id}@${entry.version}`;
  if (seen.has(key)) fail(`${key} 重复撤回`);
  seen.add(key);

  const live = plugins.find((plugin) => plugin.id === entry.id);
  if (live && live.version === entry.version) {
    fail(`${key} 已撤回，但 index.json 里仍是这个版本`);
  }
});

if (failures.length > 0) {
  console.error(`撤回记录门禁失败：\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`撤回记录门禁通过：${yankLog.entries.length} 条记录。`);

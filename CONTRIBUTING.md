# 提交插件

NIBI-GO 的插件市场只分发经过审查的条目。提交通过 Pull Request 完成，通过自动化审查门禁与
维护者复核并合并后，由官方签名流水线更新并签名官方索引（`index.json` + `index.json.sig`）。

## 提交流程

1. Fork 本仓并新建分支。
2. 按插件类型准备包体与提交描述符 `submissions/<id>-<version>.json`：
   - **方式 A · 纯 JS npm MCP 包（推荐 MCP 插件）**：
     无需向 Git 仓库提交二进制或压缩包，只需把已发布到公共 npm registry 的精确版本与 SRI
     `integrity` 填进提交 JSON（禁止 `.node`/原生二进制及 `preinstall`/`install`/`postinstall` 脚本）：

     ```json
     {
       "schemaVersion": 1,
       "id": "npm.example.my-mcp",
       "name": "示例 MCP",
       "version": "1.0.0",
       "kind": "mcp",
       "description": "一句话说明它做什么（≤280 字）",
       "license": "MIT",
       "homepage": "https://github.com/example/my-mcp",
       "source": "https://github.com/example/my-mcp",
       "contact": "https://github.com/example/my-mcp/issues",
       "publisher": { "name": "Example Author", "github": "example" },
       "caps": ["mcp.v1", "slots.v1"],
       "runtime": "node",
       "package": {
         "format": "npm",
         "name": "@example/my-mcp",
         "version": "1.0.0",
         "integrity": "sha512-...",
         "bin": "my-mcp",
         "serverName": "my_mcp"
       }
     }
     ```

   - **方式 B · 外部 HTTPS Release ZIP（推荐技能 / 跨端扩展）**：
     将插件 ZIP 发布在本人 GitHub Release（`url` 必须 `https://`），在 `package` 中声明
     `"format": "zip"`、`"url"`、`"sha256"` 与 `"size"`；ZIP 内须带 `nibi-go.plugin.json`、
     `.nibi-plugin/.claude-plugin/.codex-plugin/plugin.json` 或 `SKILL.md` / `commands/*.md`：
     - 单包解压后 ≤ 32 MiB、文件数 ≤ 500、单文件 ≤ 16 MiB；路径不得越界（无 `..`、绝对路径）；
     - 不要包含凭据、本机路径或构建产物缓存。
   - **方式 C · 仓内 ZIP（历史兼容）**：放至 `packages/<id>-<version>.zip` 并填 `"file"` / `"sha256"` / `"size"`。

3. 开 PR 并勾选 PR 模板里的检查项。

> **不要修改 `index.json` / `index.json.sig`**：PR 中改动会导致签名校验失败。签名由合并后的
> 自动签名工作流（或维护者离线备份命令）统一签发。

## 插件 id 归属（强验证）

- `publisher.github` 必须是提交 PR 的 GitHub 账号；`source` 必须是同一账号名下的 GitHub
  仓库（`https://github.com/<publisher.github>/...`）。CI 不只看字段，还核对 PR 作者。
- 首次上架会把 `id` 绑定到该 GitHub 账号（写进签名索引的 `publisherGithub`）。之后同一
  `id` 的更新必须由同一账号提交；换账号会被门禁拒绝，避免 drive-by 抢注或接管。
- 组织/公司插件请由维护者走官方发布；公开 PR 只接受个人账号归属的插件，避免无法验证
  组织成员身份。
- 已有历史条目若尚未绑定发布者，只能由维护者更新；不要用公开 PR 去“认领”别人的 id。

## 恶意代码自动扫描（启发式）

`scripts/scan-package.mjs` 会解包 ZIP 或拉取 npm `.tgz` 并扫描所有条目。**high** 直接让 PR 失败，
**review** 打印给维护者人工确认（不是自动放行/自动定罪）：

- high：编码后 `eval`/`new Function`、反向 shell、挖矿、`rm -rf /`/`mkfs`/写块设备、
  读取 SSH/AWS/NIBI 凭据、`curl|sh`/PowerShell `-enc`、路径越界、符号链接、重复条目、
  zip bomb、`.git`/`.env` 等隐藏凭据文件；npm 包额外拦截 `.node`/ELF/PE/Mach-O 原生二进制、
  `gypfile` 编译声明及 `preinstall`/`install`/`postinstall` 钩子。
- review：`child_process`/`subprocess`/`os.system`、普通动态代码、base64 长载荷、
  环境变量与网络请求同时出现、持久化、ZIP 内原生二进制、打包 `node_modules`。

扫描是规则引擎，不是杀毒引擎；它降低明显恶意包进入人工审查的概率，但**不能证明安全**。
人工审查仍必须逐项看包内容。

## 审查标准（维护者）

机械门禁（CI `validate-market` 自动，只读无私钥）：

- 泄露门禁：仓库级白名单 + 凭据/本机路径/内部基础设施/图片 EXIF/Action SHA 校验；
- 扫描器夹具回归自检（`scripts/scan-package.test.mjs`）；
- `submissions/*.json` 字段合法，文件名与 `<id>-<version>.json` 一致；
- 包体拉取核验：npm 包校验精确版本、`dist.integrity`、兼容 `linux`/`android` 与 `bin`/`main` 入口；
  ZIP 包校验 `sha256`/`size` 与清单一致性；
- `caps` 只包含已知能力（`view.v1` / `slots.v1` / `effects.v1` / `mcp.v1`）；
- 必须声明 `license`（不接受 `UNLICENSED`）与可联系的 `contact`；
- `publisher.github` 等于 PR 作者，`source` 仓库 owner 等于 `publisher.github`；
- 已上架 id 的 `publisherGithub` 不可更换，未在提交里声明 `paid`；
- 撤回账本 `yanked.json` 与索引、签名、revision 单调性校验。

人工审查（必须逐项确认）：

- **许可**：`license` 与包内声明一致；包含第三方代码时有合规声明。
- **隐私**：不静默收集数据；任何联网/遥测在描述中如实说明。
- **权限面**：`caps` 与 `runtime` 最小化；不需要的贡献点不声明。
- **包内容**：与描述一致；无混淆的下载执行、无硬编码凭据、无越界路径、无与本插件无关的
  二进制；原生二进制必须说明用途与来源。
- **可维护性**：`source`/`homepage`/`contact` 可用；版本语义合理。

## 维护者发布

1. **自动签发（主流程）**：审查通过并合入 PR 到 `main` 后，受保护环境里的 `auto-sign-market`
   工作流（`scripts/auto-publish.mjs`）会自动扫描 `submissions/*.json`、按版本前进合并进
   `index.json`（整批 `revision +1`）、签发 `index.json.sig`、回读验签并推回 `main`。
2. **本机兜底命令**：如离线维护或在 NIBI-GO 仓手工处理单条提交，可执行：

```bash
pnpm market:publish ../nibi-go-market ../nibi-go-market/submissions/<id>-<version>.json [--dry-run]
```

它会在本机校验摘要、推进 `revision`、调用签名并回读验签；随后提交推送 `index.json` 与 `index.json.sig`。

## 版本与撤回

- 同一 `id` 的版本只能前进；**同一版本号的包摘要不可变**，需要改包必须发新版本。
- 发现安全问题或违规时，维护者会从索引撤回该条目，并把记录追加进 `yanked.json`
  （id、版本、理由、时间、生效 revision）。客户端下次刷新后不再提供安装/更新；
  已安装的本地副本不会被远程删除。
- 撤回后同一 `id` 可以以**更高版本**重新提交（修复后回归）；被撤回的版本号不能再次发布。
- 撤回记录是公开、追加式的，CI 会校验形状与一致性；理由文字同样经过泄露门禁。

维护者撤回命令（在 NIBI-GO 仓执行）：

```bash
pnpm market:yank ../nibi-go-market <插件 id> --reason "撤回原因"
# 可选 --version <版本>（与索引不一致会拒绝）、--dry-run、--key <keyId>
```

它会从 `index.json` 移除条目（`revision` +1）、签名并回读验签、追加 `yanked.json`；
之后提交并推送这三个文件。包文件保留在仓库里以便追溯。

- 付费条目不在公开提交流程内；由维护者在授权链就绪后单独发布。

## 命名

插件 `id` 使用小写字母/数字/`._-`，建议反向域名或作者前缀（例如 `com.example.plugin`），
避免与已有条目冲突。已在官方索引中的 `id` 归其发布者所有；重名需先与维护者确认。

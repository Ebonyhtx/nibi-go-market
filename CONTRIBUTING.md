# 提交插件

NIBI-GO 的插件市场只分发经过审查的条目。提交通过 Pull Request 完成，维护者审查后由维护者
更新并签名官方索引（`index.json`）。

## 提交流程

1. Fork 本仓并新建分支。
2. 准备插件包 `packages/<id>-<version>.zip`：
   - 包根目录必须有 `nibi-go.plugin.json`（GO 插件清单，`schemaVersion: 1`）；
   - 清单里的 `id`/`version` 必须与文件名、提交元数据一致；
   - 单包解压后 ≤ 32 MiB、文件数 ≤ 500、单文件 ≤ 16 MiB；路径不得越界（无 `..`、绝对路径）；
   - 不要包含凭据、本机路径或构建产物缓存。
3. 新增 `submissions/<id>-<version>.json`：

   ```json
   {
     "schemaVersion": 1,
     "id": "com.example.my-plugin",
     "name": "示例插件",
     "version": "1.0.0",
     "description": "一句话说明它做什么（≤280 字）",
     "license": "MIT",
     "homepage": "https://example.com/my-plugin",
     "source": "https://github.com/example/my-plugin",
     "contact": "mailto:dev@example.com",
     "caps": ["mcp.v1"],
     "runtime": "node",
     "package": {
       "file": "packages/com.example.my-plugin-1.0.0.zip",
       "sha256": "<64 位小写 hex>",
       "size": 12345
     }
   }
   ```

4. 开 PR 并勾选 PR 模板里的检查项。

> **不要修改 `index.json` / `index.json.sig`**：签名由维护者在本机完成，PR 中改动会导致
> 签名校验失败。CI 会校验提交元数据、包摘要、清单一致性与必要声明。

## 审查标准（维护者）

机械门禁（CI 自动）：

- `submissions/*.json` 字段合法，文件名与 `id`/`version` 一致；
- 包存在、`sha256`/`size` 与元数据一致，清单 `id`/`version`/`name` 与提交一致；
- `caps` 只包含已知能力（`view.v1` / `slots.v1` / `effects.v1` / `mcp.v1`）；
- 必须声明 `license`（不接受 `UNLICENSED`）与可联系的 `contact`；
- 未在提交里声明 `paid`（付费条目由维护者与授权链一起处理）；
- 泄露门禁：仓库级白名单 + 凭据/本机路径/内部基础设施扫描。

人工审查（必须逐项确认）：

- **许可**：`license` 与包内声明一致；包含第三方代码时有合规声明。
- **隐私**：不静默收集数据；任何联网/遥测在描述中如实说明。
- **权限面**：`caps` 与 `runtime` 最小化；不需要的贡献点不声明。
- **包内容**：与描述一致；无混淆的下载执行、无硬编码凭据、无越界路径、无与本插件无关的
  二进制；原生二进制必须说明用途与来源。
- **可维护性**：`source`/`homepage`/`contact` 可用；版本语义合理。

## 维护者发布

审查通过并合并 PR 后，在 NIBI-GO 仓执行：

```bash
pnpm market:publish ../nibi-go-market ../nibi-go-market/submissions/<id>-<version>.json
```

它会校验包摘要、把提交合并进 `index.json`（`revision` +1）、调用签名脚本并回读验签自检；
之后提交并推送 `index.json` 与 `index.json.sig`。服务器上的定时任务会自动把变更镜像到
分发 CDN。`--dry-run` 可先看 revision 变化。

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

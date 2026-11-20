# NIBI-GO 插件市场

NIBI-GO 的官方插件市场：保存**官方插件索引**与**插件包**，是 NIBI-GO 客户端“插件市场”
里可安装内容的权威来源；`dl.nibistudio.cn` 上的文件由本仓自动镜像。

## 对用户

- 客户端只接受**官方签名过的索引**，并按索引里的 `sha256` 校验每个插件包；被改动或残缺的
  包会被拒绝安装。
- 市场条目经过人工审查后才会进入官方索引；审查重点是许可、隐私、权限面与包内容
  （见 [CONTRIBUTING.md](CONTRIBUTING.md)）。
- 插件是**会运行的代码**：安装第三方插件等于在本机运行作者提供的程序。市场审查降低风险，
  但不等于安全保证；只安装你信任的条目。
- 安全问题请按 [SECURITY.md](SECURITY.md) 私下报告，不要开公开 issue。

## 对插件作者

新的插件通过 Pull Request 提交，**不要直接改 `index.json`**（它由维护者签名，PR 里的改动
无法通过校验）：

1. 把打包好的插件放进 `packages/<插件 id>-<版本>.zip`；
2. 新增 `submissions/<插件 id>-<版本>.json` 描述元数据与包摘要；
3. 开 PR，CI 会校验包结构、清单、摘要与必要声明，核对 `publisher.github`/PR 作者/
   `source` 仓库的归属一致性，并对包内代码做静态恶意模式扫描；
4. 维护者按 [CONTRIBUTING.md](CONTRIBUTING.md) 的清单审查，通过后由维护者更新并签名索引。

提交格式、版本规则与审查标准见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 仓库布局

| 路径 | 内容 |
|---|---|
| `index.json` / `index.json.sig` | 官方索引与其签名（客户端安装源） |
| `yanked.json` | 撤回（下架）记录：id、版本、理由、时间与生效 revision |
| `packages/` | 已进入或待审查的插件包（`.zip`） |
| `submissions/` | 待审 PR 的元数据（未签名，不代表已上架） |
| `scripts/` | CI 门禁（签名/摘要/版本/revision/泄露/提交格式/撤回记录） |
| `.github/workflows/` | 每次 push / PR 运行上述门禁 |

## 发布（维护者）

索引发布由维护者在本机完成：更新 `index.json`（`revision` +1）→ 用官方私钥签名 →
提交 `index.json` 与 `index.json.sig`。服务器上的定时任务会先把变更镜像到分发 CDN，
客户端刷新时按 `revision` 与签名双重校验，旧索引不会覆盖新索引。

私钥不参与本仓的任何流程；本仓只保存公开的索引、签名与插件包。

## 许可

本仓的元数据、脚本与文档按 [Apache-2.0](LICENSE) 提供；每个插件包以它在索引/提交元数据
中声明的 `license` 为准。

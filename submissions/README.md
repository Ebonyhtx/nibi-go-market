# submissions/

待审插件的元数据（支持纯 JS npm MCP 包、外部 HTTPS Release ZIP 与兼容仓内 ZIP）：

- 文件名：`<id>-<version>.json`
- 内容示例与字段说明见根目录 [CONTRIBUTING.md](../CONTRIBUTING.md)
- PR 门禁 `validate-market` 会自动校验：字段合法、npm tarball `integrity` / 远端 ZIP `sha256`+`size` 一致、
  `caps` 已知、`license`/`contact` 必填、不得声明 `paid`；
- 会核对 `publisher.github` 等于 PR 作者、`source` 仓库属于同一 GitHub 账号；已上架 `id` 的发布者绑定不可更换；
- 会对包内容运行静态扫描（`high` 阻断，npm 禁 `.node`/安装脚本；`review` 留给人工），规则见
  [CONTRIBUTING.md](../CONTRIBUTING.md) 的「恶意代码自动扫描」。

提交文件本身**不是上架凭证**：维护者人工复核并合并后，由 `auto-sign-market` 自动合入并签发
`index.json` + `index.json.sig` 作为客户端安装源。

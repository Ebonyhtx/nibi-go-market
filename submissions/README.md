# submissions/

待审插件的元数据。每个文件对应一个 `packages/<id>-<version>.zip`：

- 文件名：`<id>-<version>.json`
- 内容示例与字段说明见根目录 [CONTRIBUTING.md](../CONTRIBUTING.md)
- CI 会校验：字段合法、包存在、`sha256`/`size` 一致、包内清单 `id`/`version`/`name`
  与提交一致、`caps` 已知、`license`/`contact` 必填、不得声明 `paid`。

提交文件本身**不是上架凭证**：只有维护者更新并签名的 `index.json` 才是客户端安装源。

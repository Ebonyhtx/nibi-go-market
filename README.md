# nibi-go-market

NIBI-GO 的插件市场索引仓。客户端只认 **Ed25519 签名过的索引**；索引格式、验签与防回滚规则见
NIBI-GO 仓的 `docs/design/market-index.md`。

## 文件

- `index.json`：市场索引（`schemaVersion` / `market` / `revision` / `plugins`）。
- `index.json.sig`：对 `index.json` **原始字节**的 Ed25519 签名（128 位 hex）。
- 客户端默认源：`https://raw.githubusercontent.com/Ebonyhtx/nibi-go-market/main/index.json`
  与同路径 `.sig`。

## 发布一次索引

1. 修改 `index.json`，`revision` 必须比线上 +1（防回滚靠它，签名不保新鲜度）。
2. 在 NIBI-GO 仓签名：
   ```bash
   node scripts/market/sign-index.mjs ../nibi-go-market/index.json
   ```
3. 同时提交 `index.json` 与 `index.json.sig`。

> 私钥不在本仓：由运营者本机 `~/.nibi/market/` 保管（0600），备份在私有运维仓。
> 本仓只接收签名后的产物。

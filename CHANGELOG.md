# Changelog

## [Unreleased] - 2026-03-10

### Added

- **IP 端口数量过滤 (`-mpp`)**: 新增 `--max-ports-per-ip` / `-mpp` 参数，可设定单个 IP 允许的最大端口数阈值（推荐值: 50）。超过阈值的 IP 将被自动跳过，有效过滤蜜罐类资产。
- **IP 批量查询优化**: 重构 `ParseIPQuery()`，引入 `ipQueryBuilder` 表驱动模式和分批机制（默认每批 30 个 IP），替代原先的字符串拼接方式，提升可维护性和扩展性。
- **Quake 响应结构增强**:
  - 新增 `Code` 字段，支持 API 错误码检测及告警。
  - 新增 `EcdsaPublicKey` 结构体，支持 ECDSA 公钥解析。
  - 新增 `PageType2`、`CrlDistributionPoints`、`Time` 等字段。
  - `Data` 字段改用 `json.RawMessage` 延迟解析，提升容错性。
  - 证书 `Validity.Start` / `Validity.End` 从注释恢复为 `string` 类型。
  - 多个可选字段添加 `omitempty` 标签，减少空值序列化噪音。

### Changed

- **Quake 错误日志增强**: 解码失败时输出原始响应体，便于排查 API 异常。
- **引擎查询分发**: 使用 `getEngineSlice()` 统一路由引擎查询，消除硬编码分支。

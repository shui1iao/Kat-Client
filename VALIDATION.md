# Validation: Kat-Client v0.2.22 / Windows Core v0.8.15

2026-11-18 本地候选验证记录（客户端 sequence `1794903000`，内置 Windows Core v0.8.15 sequence `1794902000`，Core 源码指纹 `04a81276f5f663a48f9cfb4fac548cf4950f207d0c9df3893e0069736d3f7a8e`）：

1. **零 API 配额更新发现与防 403 限流验证**：
   - `update_check::quota_free_update_tests` 实测模拟 `api.github.com` 全线返回 `HTTP 403` 且存在 15 个历史 `windows-core-v0.8.0..0.8.14` 标签：客户端连续 3 轮检查 `Client` 与 `Core` 全部成功识别新版并读取 `RELEASE_NOTES.md`，`api.github.com` 请求数为 `0`，低于本机版本的历史标签请求数为 `0`，第 2/3 轮命中 Atom `ETag 304` 缓存，且篡改签名或错配标签被严格拒绝。
2. **Rust 全套单测、前端构建与原生包验签**：
   - `cargo test --offline --locked` 共 312 通过、0 失败、2 忽略；前端 `tsc --noEmit` 与生产构建通过。
   - 6 角色 Windows x64 二进制离线编译，内置 `kat-client-core.exe` 与正式已发布的 Windows Core v0.8.15（SHA256 `ce44c30e612c68d7c13bd379280f4e95c401f411ded85d1087eb9a5c7aed7699`）逐字节一致；原 Ed25519 公钥 `0afa646ee76f17d8` 签包并通过产品原生 `kat-package-validator`（`update_manifest::verify_package`）校验。

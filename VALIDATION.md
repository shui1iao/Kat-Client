# Validation: Kat-Client v0.2.23 / Windows Core v0.8.15

2026-11-18 本地候选构建与门禁记录（客户端 sequence `1794904000`，内置 Windows Core v0.8.15 sequence `1794902000`，Core 源码指纹 `04a81276f5f663a48f9cfb4fac548cf4950f207d0c9df3893e0069736d3f7a8e`）：

1. **前端检查与生产构建**：
   - `tsc --noEmit -p .` 与 `node build.mjs` 生产构建通过，零类型错误。
2. **Rust 全套单测与 6 角色 Windows x64 交叉编译验签**：
   - `cargo test --offline --locked` 全套通过（0 失败，2 忽略），`verify-vendor.py` 通过。
   - 6 角色 Windows x64 二进制离线编译，内置 `kat-client-core.exe` 与正式发布的 Windows Core v0.8.15 逐字节一致；原 Ed25519 公钥 `0afa646ee76f17d8` 离线签包并通过产品原生 `kat-package-validator`（`update_manifest::verify_package`）门禁校验。

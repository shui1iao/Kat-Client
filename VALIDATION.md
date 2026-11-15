# Validation: Client 0.2.14 / Windows Core 0.8.8

2026-11-15 发布前验证记录（`client_sequence = 1794731100` / `core_sequence = 1794729000`）：

- **Windows Core v0.8.8**：`core/` 源码树与 v0.2.13 完全一致（源指纹 `9c921767dd9c749d4fe349a5105dfab6d294c61382f666a9a201be40ddd895d0`），产出 `kat-client-core.exe` 字节与 SHA256（`96f0d4f636757a9b66c681f61374c84ba5e22cdb3809b9864e7338c554a4e6d6`）与已发布 `windows-core-v0.8.8` 100% 一致。
- **Rust 1.99.1**：`cargo test --offline --locked --lib` 268 passed、0 failed、1 原有 ignored；`--test control-contract` 11 passed、0 failed。
- **前端 TypeScript / Vite**：`npm run build`（`tsc --noEmit` + bundle）通过，新 `kat-icon.svg` 已同步至 `app/dist/kat-icon.svg`。
- **NSIS 3.11**：`test-setup-finish.py` 7/7、`test-setup-readlines.py` 8/8 通过。
- **六角色编译与原密钥签包**：Windows Core v0.8.8 与五个嵌入新图标资源的 Rust Windows x64 角色全量编译，`kat-install-helper.exe` 精确绑定新服务与四客户端 SHA256；原 Ed25519 公钥 `0afa646ee76f17d8` 签包并通过产品 `update_manifest::verify_package` 校验。
- **源码归档一致性**：`Kat-Source.zip` 与 `Kat-Source.tar.gz` 与 Git 发布树逐路径、字节、权限位 100% 一致。

# Validation: Client 0.2.18 / Windows Core 0.8.12

2026-11-17 发布前验证记录（统一 sequence `1794849000`）：

- **Go 1.26.9**：`./internal/clientdiag`、`./internal/route`、`./internal/kernel`、`./internal/clientcore`、`./internal/procattr`、`./internal/tunstack`、`./internal/clientegress`、`./cmd/kat-client-core` 共 8 包全部 PASS。
- **Rust 1.99.1**：`cargo test --offline --locked --lib` 268 passed、0 failed、1 原有 ignored；`--test control-contract` 11 passed、0 failed。
- **前端 TypeScript / Vite**：`npm run build`（`tsc --noEmit` + bundle）通过；`uncertain` / `subscription` / `subscription-round2b` / `rules` 33/33 通过，`c15` sniff 定向 3/3 通过。
- **NSIS 3.11**：`test-setup-finish.py` 7/7、`test-setup-readlines.py` 8/8 通过。
- **六角色重编译与原密钥签包**：Windows Core v0.8.12（源指纹 `f4982d02b2eea4d360ec6fb2dbe311025add0cffe5f8f6017cb5fd341d8b7e83`）与五个 Rust Windows x64 角色本轮全量编译，`kat-install-helper.exe` 精确绑定新服务与四客户端 SHA256；原 Ed25519 公钥 `0afa646ee76f17d8` 签包并通过产品 `update_manifest::verify_package` 校验。
- **源码归档一致性**：`Kat-Source.zip` 与 `Kat-Source.tar.gz` 与 Git 发布树逐路径、字节、权限位 100% 一致。

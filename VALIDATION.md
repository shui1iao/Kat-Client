# Validation: Client 0.2.19 / Windows Core 0.8.13

2026-11-17 发布前验证记录（统一 sequence `1794891600`）：

- **Go 1.26.9**：`./internal/clientdiag`、`./internal/route`、`./internal/kernel`、`./internal/clientcore`、`./internal/procattr`、`./internal/tunstack`、`./internal/clientegress`、`./cmd/kat-client-core` 共 8 包（含新增测速去重、规则集快速路径与冷启动快速路径单测）全部 PASS。
- **Rust 1.99.1**：`cargo test --offline --locked --lib` 268 passed、0 failed、1 原有 ignored；`--test control-contract` 11 passed、0 failed。
- **前端 TypeScript / Vite**：`npm run build`（`tsc --noEmit` + bundle）通过；`document` / `settings` 及既有前端单测全部通过。
- **NSIS 3.11**：`test-setup-finish.py` 7/7、`test-setup-readlines.py` 8/8 通过。
- **六角色重编译与原密钥签包**：Windows Core v0.8.13（源指纹 `1178de865e6175587c4259908c733f3c87f759d2669fcdeb5c231fc948b3af6d`）与五个 Rust Windows x64 角色本轮全量编译，`kat-install-helper.exe` 精确绑定新服务与四客户端 SHA256；原 Ed25519 公钥 `0afa646ee76f17d8` 签包并通过产品 `update_manifest::verify_package` 校验。
- **源码归档一致性**：`Kat-Source.zip` 与 `Kat-Source.tar.gz` 与 Git 发布树逐路径、字节、权限位 100% 一致。

# Validation: Kat-Client v0.2.20 / Windows Core v0.8.14

2026-11-17 发布前验证记录（统一 sequence `1794901000`，Windows Core 源码指纹 `c21abbdc92a68c535b0506936170d03da151cd149b3d73aac31fea8c5295a3ba`，`BuildCommit = c21abbdc92a68c535b0506936170d03da151cd14`）：

1. **Go 1.26.9 内核与客户端核心（`go test -race ./...` + Windows `desktop` 测试交叉编译）**：
   - 22 个包通过（含 `cmd/kat-client-core`、`internal/clientcore`、`internal/kernel`、`internal/route`、`internal/sniff`、`internal/outbound/direct`、`internal/outbound/group`、`internal/tunstack`、`internal/clientegress` 等），**0 数据竞态（0 data race）**，无新增失败。
   - `GOOS=windows GOARCH=amd64 -tags desktop` 测试二进制交叉编译检查通过。
   - 其余 2 个包为与 v0.2.19 基线一致的既有测试桩/环境失败（`internal/outbound/anytls`、`internal/tunplatform`），2 个包无测试文件。
2. **Rust 1.99.1 宿主、服务与安装器（`cargo test --offline --locked` + `verify-vendor.py`）**：
   - 全量 **310 通过 / 0 失败 / 2 忽略**（`lib` 274、`control_contract` 12、`supervisor` 23 含真实 Core 子进程 UAC 后置平滑交接集成回归、`elevation_launch` 1）。
   - 官方 Wintun vendor 哈希与 PE 证书表校验通过。
3. **前端 TypeScript / Vite 与桌面交互契约**：
   - `npm run typecheck` 与 `npm run build` 生产构建通过。
   - 本版相关 4 组定向单测 **27 通过 / 0 失败**；全量 `tests-ui` **207 通过 / 61 既有快照失败**（与 v0.2.19 基线失败集合一致，无新增失败）。
   - Headless Chromium `dns-cache-browser.mjs` 11 项交互检查通过（`consoleErrors = []`，`externalRequests = []`）。
4. **六角色构建、NSIS 3.11 与原密钥签包验签**：
   - NSIS 脚本回归 `test-setup-finish.py`（7/7）与 `test-setup-readlines.py`（8/8）全部通过。
   - Windows Core v0.8.14 与五个 Rust Windows x64 角色离线编译，`kat-install-helper.exe` 精确绑定新服务与四客户端 SHA256；原 Ed25519 公钥 `0afa646ee76f17d8` 签包并通过产品 `update_manifest::verify_package` 校验。
   - `Kat-Source.zip` 与 `Kat-Source.tar.gz` 与 Git 发布树逐路径、字节、权限位 100% 一致。

# Validation: Kat-Client v0.2.21 / Windows Core v0.8.15

2026-11-18 本地候选验证记录（统一 sequence `1794902000`，Windows Core 源码指纹 `04a81276f5f663a48f9cfb4fac548cf4950f207d0c9df3893e0069736d3f7a8e`，`BuildCommit = 04a81276f5f663a48f9cfb4fac548cf4950f207d`）：

1. **DNS 与全站按钮位置零跳动几何验证（Headless Chromium）**：
   - `app/tests-ui/button-stability-browser.mjs` 在 `900×720`、`965×720`、`1000×720`、`1080×720`、`1280×720` 五档视口下逐像素校验：DNS 三标签切换、筛选胶囊计数跳变、「清除缓存」状态条弹出、设置与缓存页清除按钮对齐、「跳过目标覆盖」模式切换、连接页「按进程」与「活跃/已关闭」切换、日志页三标签与筛选切换均 `0.00px` 位移。
   - `app/tests-ui/dns-cache-browser.mjs` 11/11 项全部通过；`tsc --noEmit` 与 Vite 生产构建通过。
2. **Go 客户端内核 `-race` 与冷启动流式测速验证**：
   - 客户端相关 22 个有测试包 `go test -race -tags desktop` 全数通过、0 数据竞态；新增 `TestDesktopStartupStreamingProbeUnblocksGroupsAndNestedDependenciesBeforeDeadNodeTimeout`（5s 死节点下三层策略组与真实 TCP 拨号 20ms 就绪）与 `TestHostStartingNonBlockingSnapshotAndNonNilJSONArrays`（启动期无锁快径与零 `:null` 数组）全部通过；Windows 测试二进制交叉编译通过。
3. **Rust 桌面宿主与安装器校验**：
   - `cargo test --offline --locked` 共 310 通过、0 失败、2 忽略；`verify-vendor.py`、`test-setup-finish.py`（7/7）、`test-setup-readlines.py`（8/8）全部通过。
4. **交叉构建与产品原生包验签**：
   - Windows Core v0.8.15 与五个 Rust Windows x64 角色离线编译，`kat-install-helper.exe` 绑定服务与客户端 SHA256；Ed25519 公钥 `0afa646ee76f17d8` 离线签包并通过产品原生 `kat-package-validator`（`update_manifest::verify_package`）门禁。

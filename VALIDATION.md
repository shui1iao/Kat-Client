# Validation: Client 0.2.10 / Windows Core 0.8.6

2026-11-14 发布门禁记录（`client_sequence = 1794642156`，`core_sequence = 1794587687`）。

## 本轮实际结果
- `core/` 全部 985 个源文件与 v0.8.6 逐字节一致（源指纹 `cc9a2539de5984cee366aa6b84e4996e684002925679286a524768ffbfedf19d`），重编译 `kat-client-core.exe` SHA256 与已发布 v0.8.6 完全一致（`3f86ffb5fcef189e48b8f17daa0c5da5d42eb6e1d67cc4ef7c52f52c161f57a6`），复用同日 v0.8.6 的 Go 504 PASS + ICMP 6 PASS 纯逻辑证据。
- Rust：`cargo test --offline --locked --lib` 268 passed、0 failed、1 原有 ignored；`--test control-contract` 11 passed、0 failed。
- 前端：`npm run build`（含 `tsc --noEmit`）通过；TS 行为测试（订阅/规则 17/17 + sniff 3/3）全部通过。
- NSIS：固定官方 NSIS 3.11 deb SHA256 校验通过，`test-setup-finish.py` 7/7、`test-setup-readlines.py` 8/8 通过。
- 六角色完整编译、原 Ed25519 公钥（`0afa646ee76f17d8`）签包、产品 `update_manifest::verify_package` 离线校验通过、NSIS 3.11 生成 `Kat-Setup-x64.exe`。

## 边界说明
未执行 Windows 实机安装/卸载、UAC/COM/SCM、TUN 或 Win32 ICMP API 实机测试；不承诺 Authenticode 代码签名。

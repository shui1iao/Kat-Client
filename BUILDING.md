# Build: Client 0.2.38 / Windows Core 0.8.23

Client sequence `1795859000`，Windows Core sequence `1795858000`。源归档与发布 Git index 逐成员字节/模式一致；`SOURCE-MANIFEST.json` 排除自身及 `BUILD-IDENTITY.json` 以避免循环。`CORE-BUILD.json` 按精确 `core/` 成员排序 JSON 计算指纹，前 40 位注入 `BuildCommit`（不是 Git commit）。

解压 `Kat-Source` 与 `Kat-Build-Support.tar.gz`，按 `app/src-tauri/scripts/INSTALLER-PACKAGING.md` 的 6 步顺序构建前端 `app/dist` 与 6 个 Windows x64 二进制角色、捕获 `Kat-Uninstall.exe`、由授权签发者以 Ed25519 密钥（`0afa646ee76f17d8`）独立签署 schema 1 (`kat-package-auth.json`) 与 schema 2 (`kat-setup-auth.json`)，经离线产品验证器核验后打包生成 `Kat-Setup-x64.exe`。

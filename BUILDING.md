# Build: Client 0.2.23 / Windows Core 0.8.15

统一 sequence `1794904000`。源归档与发布 Git index 逐成员字节/模式一致；`SOURCE-MANIFEST.json` 排除自身及 `BUILD-IDENTITY.json` 以避免循环。`CORE-BUILD.json` 按精确 `core/` 成员排序 JSON 计算指纹，前 40 位注入 `BuildCommit`（不是 Git commit）。

解压 `Kat-Source` 与 `Kat-Build-Support.tar.gz`，设置 `KAT_SOURCE_ROOT`（绝对源码路径）、`KAT_TOOLCHAIN_ENV`（提供 Go 1.26.9、Node 24.19.0、Rust 1.99.1/cargo-xwin、Windows SDK 10.0.26100 的环境脚本）、`KAT_OUTPUT_ROOT`（输出目录），提供离线锁定 `node_modules` 后运行 `build-support/build-release.sh` 编译六个 Windows x64 二进制角色；授权签发者使用原公钥（`0afa646ee76f17d8`）匹配的 Ed25519 密钥签发 `kat-package-auth.json`，经产品 `verify_package` 校验后由固定 NSIS 3.11 打包生成 `Kat-Setup-x64.exe`。

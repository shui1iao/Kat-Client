# Build: Client 0.2.9 / Windows Core 0.8.6

客户端 sequence `1794638859`，内置 Windows Core v0.8.6 sequence `1794587687`。源归档与发布 Git index 逐成员字节/模式一致；`SOURCE-MANIFEST.json` 排除自身及 `BUILD-IDENTITY.json` 以避免循环。`CORE-BUILD.json` 按精确 `core/` 成员排序 JSON 计算指纹，前 40 位注入 `BuildCommit`（不是 Git commit）。

环境：Go 1.26.9、Node 24.19.0/npm、锁定 Rust 1.99.1/cargo-xwin、Windows SDK 10.0.26100 及 MSVC 14.44；离线锁定 `go.mod`/`go.sum`、`Cargo.lock` 和 `package-lock.json`。

解压 `Kat-Source` 与 `Kat-Build-Support.tar.gz`，设置 `KAT_SOURCE_ROOT`、`KAT_TOOLCHAIN_ENV`、`KAT_OUTPUT_ROOT`，提供 `node_modules` 后运行 `build-support/build-release.sh` 编译前端及全部 6 个 Windows x64 二进制，再由授权签发者以原公钥匹配的 Ed25519 私钥签发 `kat-package-auth.json`，经产品 `update_manifest::verify_package` 门禁通过后由 NSIS 3.11 生成 `Kat-Setup-x64.exe`。

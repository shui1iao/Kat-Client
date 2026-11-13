# Build: Client0.2.8 / WindowsCore0.8.6

统一sequence1794587687。源归档与发布Git index逐成员字节/模式一致；SOURCE-MANIFEST.json排除自身及BUILD-IDENTITY.json以避免循环。CORE-BUILD.json（构建证据）按精确core成员path/bytes/SHA256排序JSON计算指纹；其前40位注入BuildCommit，**不是Git commit**。

环境：Go1.26.9、Node24.19.0/npm、锁定Rust1.99.1/cargo-xwin、Windows SDK10.0.26100及MSVC14.44；离线锁定go.mod/go.sum、Cargo.lock和package-lock.json，不更新依赖。Go使用GOTOOLCHAIN=local/GOPROXY=off/GOSUMDB=off，Rust --offline --locked。

解压Kat-Source与Kat-Build-Support.tar.gz，设置KAT_SOURCE_ROOT（绝对源码路径）、KAT_TOOLCHAIN_ENV（提供上述已准备工具链的env）、KAT_OUTPUT_ROOT（任务输出路径）。按环境提供node_modules（不属于公开源码）后运行build-support/build-release.sh。driver先构建前端，再以desktop标签编译core/cmd/kat-client-core Windows amd64（CGO0、trimpath、buildvcs=false），Rust xwin编译desktop/network-service/proxy-watchdog/elevate-helper，最后用新service及四客户端SHA绑定install-helper；禁止复用旧exe。

安装器：读取installer_files.rs::FILES精确payload。授权签发者以原公钥匹配的Ed25519密钥签kat-package-auth.json原始字节（schema1/windows/amd64/六新角色SHA/完整core fingerprint），sig是64字节签名的hex。私钥不在源码/附件中，driver不签发、不生成新密钥。新build-setup.py静态coreSHA门禁必须匹配最终core；先运行产品update_manifest::verify_package，再NSIS。两固定NSIS3.11 Debian deb的SHA门禁及原许可证保留。

build-setup.py依赖任务临时路径integration-evidence/comprehensive-20261029/native/setup-installer/toolchain/nsis（deb及root/解包）；运行--payload /absolute/payload --output /absolute/Kat-Setup-x64.exe --uninstaller /absolute/Kat-Uninstall.exe。工具需自行从Build-Support解包到该路径，不能使用旧stage-package.py中的历史缓存/已退役tun2socks路径作为当前产品构建入口。

GitHub在线manifest依赖实际releaseID/assetID/bytes/hash，此离线阶段不生成；禁止用旧清单替代。构建通过不证明Windows服务、UAC、TUN或真实ping通过。无Git push/tag/Release写操作。

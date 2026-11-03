# Kat-Client v0.1.0

Windows x64客户端，以已接受candidate24功能为基线，统一正式版本标识。下载Release中的`Kat-Setup-x64.exe`；安装器和应用未签名。本次没有Windows安装/升级/UAC/TUN网络实机验收，交叉构建不代表实机通过。

客户端core为0.7.1/c24基线，BuildCommit是完整接受core源码指纹的前40位，不是Git提交；不能替换成Kat-Server 0.7.2二进制。后续更新功能不在本版范围。

## 权利
Source-available，不是MIT开源。Kat自研代码保留所有权利，不授予通用使用、修改或再分发许可。第三方/上游原许可及其源码义务不变，见[RIGHTS.md](RIGHTS.md)、`core/THIRD_PARTY_NOTICES.md`及app中的许可材料。

## 源码和构建对应
本公共树来自批准c24源码归档，仅正式标识和发布材料调整。历史分析文档、工具运行材料不公开；生产Go/Rust/前端源码和对应第三方材料完整保留。内核原指纹包含原接受树的非编译文档，因此不能从精简公共树直接重算该旧指纹；编译源码对应关系由Release的SOURCE-MANIFEST.json及BUILD-IDENTITY.json记录，旧指纹只表达c24来源，不冒充本仓Git身份。

构建需Go 1.26.9、Node依赖按package-lock、Rust/cargo-xwin和Windows SDK、NSIS 3.11。前端在app运行npm ci和npm run build；Windows内核入口core/cmd/kat-client-core，宿主在app/src-tauri使用desktop feature和x86_64-pc-windows-msvc目标。安装helper必须使用本次service及三个客户端映像hash编译，然后由scripts/build-setup.py离线组包；不要使用历史生产报告或替换任意内核文件。

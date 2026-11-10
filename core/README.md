# Kat Windows 客户端内核

本目录仅构建 `cmd/kat-client-core`。本地HTTP/CONNECT、SOCKS5与内置TUN
接入共享四种协议出站、策略组、DNS与分流核心。服务端CLI、加密入站、
ACME、对外管理API、VLESS/Snell/REALITY专用实现已移除。

使用方式与IPC见 [客户端文档](docs/client/README.md)。测试peer所用的
`internal/ss`、`internal/anytls` 仅由测试引用，不在客户端生产依赖闭包。
不要将它们重新接入客户端运行配置或作为第二个服务器产品入口。

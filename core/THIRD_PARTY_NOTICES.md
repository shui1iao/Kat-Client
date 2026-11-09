# 第三方组件与二进制分发说明

Kat 自研代码保留所有权利；下述第三方组件及其修改继续适用各自原许可。此说明不替代原始法律文本，也不限制第三方许可授予的权利。

## REALITY

`third_party/reality/` 是构建实际使用的 XTLS/REALITY 提交 `9234c772ba8f181f31c3e81dc2b4177322e5a9a9` 源码及本地修改。原始 MPL-2.0 及 Go 许可均在该目录保留，修改及完整源码获取路径见 [MPL 说明](MPL-NOTICE.md)。不要只分发差异而不提供对应受许可源码。

## juju/ratelimit

二进制包含 `github.com/juju/ratelimit v1.0.2`，版权声明为 Canonical Ltd.，许可为 LGPL-3.0，附原作者提供的静态/动态链接特别例外。库源码未作本地修改。

- [库的原始许可和特别例外](third_party/licenses/github.com_juju_ratelimit@v1.0.2-LICENSE)
- [LGPL 引用的 GPL-3.0 原文](third_party/licenses/GPL-3.0.txt)
- 对应上游源码：<https://github.com/juju/ratelimit/tree/v1.0.2>

特别例外允许分发静态或动态链接的组合作品，无需提供 LGPL 第 4d 项定义的最小对应源码、最小应用代码及第 4e 项安装信息，但保留其他适用义务。本版本保留库的显著使用说明、版权、LGPL/例外及 GPL 原文，并随二进制提供许可附件。Kat 的权利声明不禁止第三方许可所允许的库修改，也不限制为调试这些库修改而依法或依适用许可进行的逆向工程。

## 其他组件

`third_party/licenses/` 保留 Go、golang.org/x/crypto、golang.org/x/net、golang.org/x/sys、golang.org/x/text、BLAKE3、cpuid、Brotli、CIRCL、WebSocket、compress、go-proxyproto、uTLS 等组件的原始许可或专利文本。目录中可能保留同一组件的不同版本许可副本，实际编译版本以 `go.mod`、`go.sum` 和二进制构建信息为准，不将旧版本许可副本误称为新增运行依赖。

产品源码及静态附件不包含独立测试客户端的源码或二进制，产品构建不依赖这些客户端。请勿将未分发的测试工具许可误当作本产品的链接依赖许可。

## 随二进制提供

`kat-0.7.1-third-party-licenses.txt` 附件汇总本说明、MPL 修改说明、第三方许可原文及其目录路径。对应受许可源码与差异可从 `https://github.com/shui1iao/Kat/tree/v0.7.1` 获取；分发者应保持此获取路径及对应版本源码可用，同时履行各原许可的其他适用义务。原始法律文本不翻译或改写。

## maxminddb-golang

二进制包含 `github.com/oschwald/maxminddb-golang v1.13.1`（`internal/route` 用于读取用户自行提供的 MaxMind DB 国家库），许可为 ISC，库源码未作本地修改。Kat 不内置、不随包分发任何 GeoIP 数据。对应上游源码：<https://github.com/oschwald/maxminddb-golang/tree/v1.13.1>。原始许可全文如下：

```
ISC License

Copyright (c) 2015, Gregory J. Oschwald <oschwald@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
```

## yaml.v3

provider 的 Clash YAML 解析链接 `gopkg.in/yaml.v3 v3.0.1`，源码未作修改。该组件部分文件为 MIT，其余为 Apache-2.0，不应将整个组件简单标成单一 MIT 许可。保留上游完整通知：[yaml.v3 LICENSE](third_party/licenses/gopkg.in_yaml.v3@v3.0.1-LICENSE)。对应源码：<https://gopkg.in/yaml.v3>。

## C50 内置 TUN netstack（增量；不覆盖既有组件）

`internal/tunstack` 直接使用 `gvisor.dev/gvisor v0.0.0-20260701204157-69c2d17aea96` 的 netstack 公共 API，不导入其容器/CLI，也不导入 tun2socks engine/tunnel/proxy。gVisor 主体 Apache-2.0，但实际编译的 `pkg/sync` 有 BSD-style 文件，部分派生自 Go 标准库，须保留 **The Go Authors 和 The gVisor Authors 各原年份版权**，不能以根 Apache 许可替代这些通知。

- 原文：[gVisor Apache LICENSE](third_party/licenses/gvisor.dev_gvisor@v0.0.0-20260701204157-69c2d17aea96-LICENSE)、[文件所指 Google BSD 原网页](third_party/licenses/gvisor-sync-Google-BSD.html)、[Go BSD 原文](third_party/licenses/gvisor-sync-Go-BSD-LICENSE)。本精确模块不带独立 NOTICE。
- 实际 Linux/amd64 定向运行路径和 Windows/amd64 生产路径的源文件并集及逐文件原版权/许可归属：[C50-TUNSTACK-FILE-NOTICES.tsv](third_party/licenses/C50-TUNSTACK-FILE-NOTICES.tsv)。这不是整个 gVisor 模块可选源码的许可保证。上游精确来源：<https://github.com/google/gvisor/tree/69c2d17aea96>；模块 zip/版本由 go.sum 锁定，未修改 gVisor 源码。
- 实际传递依赖：`github.com/google/btree v1.1.3`（Apache-2.0）、`golang.org/x/exp v0.0.0-20260611194520-c48552f49976`（BSD-3 + PATENTS，constraints）、`golang.org/x/time v0.15.0`（BSD-3 + PATENTS，rate）。完整 LICENSE/PATENTS 均在 third_party/licenses 相应版本文件，来源为各精确 Go module；不是全部 gVisor go.mod 的云/容器依赖进二进制。
- `internal/tunstack/{stack.go,link.go}` 的初始化/报文桥基于 tun2socks v2.7.0 commit `8dda19e8e4613e014f0b12f3e624fdff5e5f23b3` 的 MIT core/device/iobased；原版权 **Copyright (c) 2019 Jason Lyu**，完整 MIT 在 [LICENSE.tun2socks](internal/tunstack/LICENSE.tun2socks) 和总许可目录。文件已标明 Kat 对生命周期、packet API、UDP/admission/epoch 和错误传播的修改。不引入 tun2socks Go 模块或旧 Kat 桥补丁实现。
- 新栈的 OS Device 由 tunplatform 的官方 Wintun DLL API wrapper 提供；本 DATA 没有新增 wireguard 或 Wintun Go binding 模块。官方 DLL 的独立 Prebuilt Binaries License 与 MIT Go 源码许可不同，沿已有 network/WINTUN-LICENSE.txt 原样保留，由 OS/打包 owner pin 官方 0.14.1 amd64 字节，不编译驱动源码。

新增运行依赖和复用片段是以上 MIT/Apache/BSD 范围；既有 REALITY/MPL、ratelimit/LGPL+例外等原通知和义务保持，不据此宣称整个既有 Kat 或完整 Source 所有历史材料都只有 MIT/Apache/BSD。此增量不引入 GPL 实现，不以历史独立测试 peer 代替生产依赖证据。

Kat-Client v0.1.0 — Windows x64

以接受的candidate24功能为基线，统一正式版本标识重新构建。程序及安装器未签名；本次仅Linux交叉构建/打包及静态检查，Windows安装、升级、UAC、实际TUN网络和恢复未实机验收。

双击Kat-Setup-x64.exe，以普通用户运行向导；特权操作由固定helper请求UAC。安装/更新/卸载前正常退出Kat。更新保持原安装目录；请保留配置和恢复材料。需Microsoft Edge WebView2 Runtime。

客户端内核仍为c24的0.7.1源码基线，不是Kat-Server v0.7.2。两者入口和安装hash契约不同，不能手动互换。内核BuildCommit为源码指纹截断，不是Git commit。

自研代码保留所有权利，公开源码不授予通用使用、修改或再分发许可；第三方和上游代码继续遵守原许可。对应源和许可证见Release源码附件。

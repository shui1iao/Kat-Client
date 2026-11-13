Kat Client 0.2.8 / Windows Core 0.8.6

普通用户运行Kat-Setup-x64.exe，固定helper按需请求UAC。安装/升级/卸载前正常退出Kat，保留用户配置与已有备份；不要删除恢复日志来伪造成功。需要WebView2。
本轮没有Windows实机安装、服务/TUN/ICMP API验证。DIRECT的设计为物理真ping；代理目的地只按当前出站HTTP探测可用性生成Echo，非代理传输目标ICMP。完整说明见同版RELEASE_NOTES.md/VALIDATION.md。包Ed25519身份签名不是Authenticode代码签名。
原有用户代理、非Kat路由/服务/文件保持保护；失败按事务恢复，不全局flush网络或删除适配器。RIGHTS.md保留Kat自研权利，第三方许可与notices继续有效。

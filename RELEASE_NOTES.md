# Kat-Client v0.1.0

Windows x64，接受candidate24功能基线，仅统一正式版本/发布元数据。下载Kat-Setup-x64.exe；对应源码Kat-Source.tar.gz，校验见SHA256SUMS.txt。

**未签名，Windows安装/升级/UAC/TUN及恢复未实机验收。** 本次Linux交叉构建和NSIS离线组包通过；Linux可执行宿主测试243通过、6失败（既有托盘字符串/菜单预期及旧权限集合断言，与当前独立tray-menu权限边界不一致），没有修托盘功能或以交叉构建冒充实机通过。

core仍0.7.1/c24，非Kat-Server 0.7.2；BuildCommit是原接受core源码指纹截断，不是Git commit。安装映像hash绑定，不支持任意替换core。本版未增加自动更新、热安装、Gemini新修或新规则测试功能。

Source-available：自研代码保留所有权利，公开不授予通用使用修改再分发许可；第三方/上游继续适用原许可。公共树不含历史分析/私有运行材料，实际编译源码完整对应新构建；见SOURCE-MANIFEST.json和BUILD-IDENTITY.json。

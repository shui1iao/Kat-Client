# Netflix 完整公开响应回归样本

- 文件：`netflix-hk-20261102.html.gz`。仅gzip压缩，未修改/替换/删减原文；mtime=0。
- 获取：Hytron，2026-11-02 11:52:43 UTC+8。匿名GET `https://www.netflix.com/title/80057281`，同Host重定向到 `/hk-en/title/80057281`；HTTP200。无登录、CookieJar、授权头或用户订阅 / 节点凭据。
- 请求UA：`Mozilla/5.0 Kat-Diagnostics/1.0`，Accept-Language：`en-US,en;q=0.9`。取证上限8MiB、总预算8秒；是证实2MiB溢出后的唯一一次定向大小 / 结构取证，不是循环请求求成功。
- 解压后字节：2,354,153。SHA256：`8a49a8df740122bdaf7489dd07e8734c94cee0bbf6f22d158a55ee7fad8b0869`。
- `netflix.reactContext = ` 从0基字节偏移2,126,432开始，超过旧2,097,152上限。原解析器对完整响应读出 requestCountry.id=HK/status=ALLOW 与正确titleID；因此本样本直接复现旧体积缺陷，不是合成小HTML。
- 新定义仅判匿名地区 / 服务可用性，不把该响应当作账户、授权片库、DRM或实际播放证据。
- 单独边界测试会在本样本末尾填空格至4MiB / 4MiB+1；这些是技术边界夹具，不伪称真实响应。

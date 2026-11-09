# SS优化终验与合入状态（2026-10-18 13:17）

权威核心现为 **0.5.1-test-ssopt**；只最小合入原candidate1生产源码与test-only回归，最终binary SHA256 `670f38eb7778287a7433c057a86949014614b01225545131529278fb83e5eb4a`，与已AB binary一致。

原0.5.0源码相关文件和binary保留 `/opt/proxy-kernel-ss-opt-20261018/rollback/pre-merge-20261018`；旧基线和旧0.5.0交付包未覆写。用户13:09授权构建-only整组1core/1GiB，完成即退出；互通终验仍整组1core/512MiB/零swap、450MiB停止线。未恢复任何吞吐、profile、参考锚点或SS2022性能AB。

全产品8包test/race/vet复用同生产hash的PASS证据；缺失build、三完整app六cipher TCP/UDP、独立库server-first、SS库race count3与核心SS2022首Read/RST/重放/迁移等定向功能均通过。预编译测试首次因cwd找不到fixture，仅改执行目录，失败历史保留；无候选热路径修补。

收益仅自身SS2017六轮受限ABBA，不能宣称超过SB/XR；后profile/SS2022perf/其它协议perf未做，四项性能目标未全完成。MPL完整对应源码、replace、通知/补丁、依赖许可保留；测试版、总许可证待定、不部署/公开发布。

完整报告 `/opt/proxy-kernel-ss-opt-20261018/ss-opt-report.md` 第9节；私有测试包在该目录delivery，主控负责审阅与取回。原始证据副本在docs/ss-opt-20261018。

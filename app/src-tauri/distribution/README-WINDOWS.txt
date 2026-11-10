2026-10-29 Setup 增补（本节优先于下方历史记录）
- 安全首次非默认目录示例：C:\Program Files\Kat Client Test。父目录须已存在且仅管理员控制。
- 不支持桌面/下载/用户目录、网络盘、设备路径、磁盘根、Windows 子树、重解析路径或非 Kat 非空目录。选择不安全会明确拒绝，不静默改默认。
- 权威根位于 ProgramData\Kat Client Installation 的受保护机器记录；当前用户配置/历史/偏好/自启设置不删。
- 真实 Windows Setup/UAC/COM 与最终恢复由主控另行验收；本包构建通过不表示这些已实机通过。

2026-10-29 全面修复测试版（未发布、未签名）
本节为当前说明；下方各历史日期段落的“已验/未验”仅描述当轮，不是本包验收结论。
当前实机范围和已知限制请以随交付的 VERIFIED.md 为准，不以构建成功推定网络全通。

- 主交付为 Kat-Client-Setup-x64.exe 中文离线安装向导，请直接双击，不需要手动解压。
  首次安装可编辑/浏览选择专用目录；更新沿用真实已安装目录，不支持更新搬家。
  安装、更新或卸载前请在 Kat 中正常退出；仅独立固定 helper 请求 UAC，GUI 和向导不以管理员运行。
- 更新先暂存完整固定文件，再替换；中途失败恢复旧文件和原服务状态。
  若报告恢复未完成，保留回滚材料，勿重复盲装或删除恢复日志。
- 超时但变更结果未确认时，暂禁重复保存/切网络；取得稳定权威配置后恢复操作。
  用户未保存的草稿继续保留，不自动重发保存。
- Windows 原子保存仅对特定瞬态文件占用作最多2秒期限驱动恢复；取消优先，永久拒绝仍失败保旧。
  外部编辑仍做身份/原文核对；比较到替换之间不是文件系统 CAS，不宜与外部编辑器同时写同一配置。
- TUN 开关与后台监视使用同一操作锁，防止旧的关闭状态撤销刚成功的开启，或复活刚关闭的意图。
  不增加业务等待或自动重试；实际 TUN 流量及恢复结果仍以 VERIFIED.md 为准。
- 修复首次 TUN 查询把官方 Wintun 合法缺失1168误报为错误；其它权限/驱动错误仍明确拒绝。
  不升级驱动、不放宽调用者或文件权限；实际网络与恢复验收仍以 VERIFIED.md 为准。
- 冷自动组首次 TCP/UDP 会在调用期限内等首个完整探测轮，按原算法选择；默认 lazy 启动不自动出网。
  显式 lazy:false 保留原启动/周期行为；固定选择、权重、旧流和不重放数据原则不变。
- 订阅识别与远端节点在线率分开：22个完整接线不等于22个均可连；不删混淆/前置字段冒充可用。
- 修正设置和保存期间输入丢失、规则未知字段丢失、迟到轮询覆盖状态、弹窗键盘焦点与备份失败先删旧等缺陷。
- 白底/Zeno蓝、B猫头图标、侧栏记忆、拖动、JSON/YAML原文与失败保旧继续保留。

Kat Windows 11 x64 development candidate (not released; application/helper unsigned)

Primary delivery: double-click Kat-Client-Setup-x64.exe as a NORMAL user. The ZIP is auxiliary only.
First install selects a dedicated safe local directory; updates keep the original location.
Exit Kat normally before install/update/uninstall. Windows Apps -> Kat Client -> Uninstall preserves user data.
The Microsoft Edge WebView2 Evergreen Runtime is required (normally present on Windows 11).
Do not run the GUI as administrator. Configuration/core workspace: %LOCALAPPDATA%\app.kat.client.

The explicit Network Service Install command shows UAC. It copies only this complete fixed package to
%ProgramFiles%\Kat Client, binds the actual initiating user's SID/session, and installs KatClientNetwork.
After first installation, quit (restores owned networking) and launch the installed kat-desktop.exe as
normal user before enabling TUN. No service installation is required solely for the per-user system proxy.
Only the installed bound-user GUI can use the privileged pipe. Different-account UAC elevation is rejected.

System proxy and TUN are independent. Both require real ready core loopback entries. TUN also requires
network.egress.v1 coverage/ready confirmation. Missing dependencies produce errors, not a lit switch.
Changing only rules/mode/weights retains switches. Changed HTTP or SOCKS ports safely restore the affected
OS path and do not auto-reenable it. Invalid documents never change OS networking.

Exit uses tray Exit (restore first). The titlebar close only hides to tray. Stop Core restores own network.
GUI/core crash: same-user independent proxy watchdog and SYSTEM service monitor restore only owned state.
Whole-machine power loss or killing the service cannot invoke an immediate callback; startup/SCM recovery
compensates. No kill-switch, firewall/WFP policy or global IPv6 disable is installed.

Recovery/diagnostics (ONLY after separate Windows runtime authorization):
1. Reopen installed GUI as same user; startup recovers only-own proxy; turn both switches off and read actual state.
2. If GUI will not start, double-click Restore-User-Proxy.cmd in this package as the affected normal user.
3. If service is unhealthy, authorized administrator can use Services -> Kat Client Network Service -> Restart.
   On restart the protected network journal is compensated before the service accepts new clients.
4. Do not delete recovery journals to make the status green. Do not use global route flush, netsh WinHTTP reset,
   blanket adapter deletion, global IPv6 disable or firewall changes. Existing third-party edits remain untouched.
5. Service uninstall is explicit UAC from installed GUI, first restores routes then stops/deletes SCM service.
   Program files and original user document remain for diagnosis; no automatic recursive deletion.

Installer results are written only while impersonating the verified initiating GUI's actual non-elevated
medium-or-lower token (same SID/session and process creation time); never with helper elevation. Parent
reparse points or precreated result/.next links cannot acquire extra file access from UAC. Capturing or
writing with that token failing returns an error, never a success inferred solely from exit code. A
write/report error can follow a successful service operation: refresh service status before retrying.

Fixed diagnostics (no raw config/credentials):
%LOCALAPPDATA%\app.kat.client\network-installer-result.json
%LOCALAPPDATA%\app.kat.client\system-proxy-journal.json (sensitive local PAC/proxy; do not upload)
%ProgramData%\Kat Client\network-journal.json (SYSTEM/Admin-only)
%ProgramData%\Kat Client\network-last-error.json (SYSTEM/Admin-only)

Windows UAC/SCM installation and same-user GUI/service status were actually exercised on Bero.
Five focused native pipe/path tests also passed there. This does NOT establish Wintun loading,
real TCP/UDP dual-stack forwarding, DNS flow, proxy/PAC restore or crash/sleep/Wi-Fi recovery.
Those OS-network paths remain untested in this iteration; system proxy and TUN were not enabled.
Official original Wintun0.14.1 license and fixed MIT tun2socks2.7.0 notices accompany this package.

Daily preferences / file and diagnostics commands (v1.2 development candidate):
- Desktop preferences are separate in desktop-settings.json. All four booleans default false; close_action
  defaults tray. Saving preferences never starts/stops the core or changes live networking.
- Login startup uses only the current-user Run value KatClient, with the quoted fixed kat-desktop.exe
  plus fixed --autostart. Third-party ownership conflicts fail; Windows StartupApproved disablement is
  read, never overridden. Moving an owned installation only migrates a still-owned startup command.
- Startup hidden, auto-start core and restore-network are independent. Restore is explicitly opt-in,
  requires auto-start core and actual loopback/service readiness; never installs service or shows UAC.
  Any startup error shows the window. Cleanup/quit does not erase last successful explicit switch intent.
- Titlebar/native close follows tray or quit preference. Tray Exit always restores owned network first;
  recovery failure retains GUI/core for repair. Repeated launches best-effort wake the existing window.
- Native import is <=1MiB UTF-8 regular file, only loads a draft. Export saves the current persisted
  document and explicitly warns it CONTAINS NODE CREDENTIALS. Cancel is not success or error.
- Every valid ordinary apply first backs up the old saved document before any network/core mutation;
  backup IO failure is visible and aborts apply. backups/<opaque-sha256>.<json|yaml|yml> retains <=10*1MiB, deduped
  by content. List/read reject paths/links/unknown IDs and never restore automatically.
- Workspace opens only the fixed user configuration directory. Diagnostics exports only allowlisted
  versions/readiness/counts and fixed safe events (host ring<=500, actual Go logs), not raw config,
  destinations, names, URLs, PAC, credentials or stderr. No upload or general shell/filesystem grant.
- desktop-network-intent.json and desktop-autostart-owner.json are host-only normal-user state.
  All new file IO uses the normal-user token and rejects reparse/linked paths; elevated installation
  result writing retains the verified original GUI-token impersonation security fix.

Daily startup registration, native dialogs and NTFS/reparse behavior also remain UNTESTED ON WINDOWS.
Rust/Linux state tests and cross compilation are not Windows OS runtime acceptance. See DAILY-HOST.md
in the controller handoff for exact build/asset identities and remaining Win11 checks.

SETTINGS v1.3 development candidate (2026-10-28; still not Windows-runtime verified):
- Settings -> Latency testing now owns the single manual URL editor, static presets, point timeout,
  whole-group budget and client-wide manual concurrency. Omitted defaults remain 5s / 10s / 4.
- Automatic group probe URL/timers remain separate; display sorting never changes routing or fixed members.
- Subscription HTTP timeout/User-Agent/headers/type filters are editable; header values stay hidden by default.
- Optional window placement memory and tray left-click show/toggle are available, off/show by default.
- System proxy bypass defaults to inheriting each pre-enable Windows value. Explicit custom uses Windows
  semicolon/wildcard syntax and takes effect only on the next proxy enable, not on preference save.
  It does NOT bypass TUN or Kat routing. Recovery still restores only tuples owned by Kat.
- Win11 window/DPI/tray/WinINet/self-start/driver/network/crash-recovery runtime tests remain outstanding.

TITLEBAR DRAG FIX (2026-10-28): titlebar left-drag is routed only through the existing
fixed current-main-window action; window buttons are excluded. No generic window/shell
permissions were added. The icon is unchanged; native Windows movement still needs retest.

APPROVED ICON (2026-10-28 17:54, latest user-selected B solid cat head): transparent
background, solid blue-gradient head (#5E93E6 to #3A5FBF), same-color K with a gap, no
shadow. Large icons (>=40px) retain the small star; 16/20/24/32px use the clean no-star
variant. The titlebar/favicon use the no-star SVG; tray/main-window use new 32px RGBA.
The EXE contains nine matching ICO sizes. This supersedes the prior eeb36fd7 thin-outline
transparent icon and old white backing. Fixed-main-window drag correction stays unchanged.
Exit the old tray process before extracting/running this whole package as a normal user.
Windows shell icon caches may retain an old image; no cache-clearing/reset is performed.


JSON / YAML development test package (2026-10-28; NOT a release):
- Kat's own schema only. JSON remains supported; .yaml and .yml use the same fields/defaults.
  This does NOT accept a complete mihomo/Clash/Surge configuration.
- Exactly one kat-client.json / kat-client.yaml / kat-client.yml is active in the fixed user
  workspace. No file creates JSON as before; multiple candidates fail with an explicit conflict.
  Keep only the intended active candidate before retrying. No silent priority or migration.
- Configuration -> Format changes a draft only. Review and Save to commit the new extension.
  Cancel restores the accepted source and format. Existing target files are never overwritten.
  The previous accepted raw file is backed up; failure retains old active file/runtime.
- Ordinary visual YAML changes preserve comments/order/untouched tokens. Formatting is explicit;
  YAML->JSON warns that comments cannot be retained. Illegal drafts never replace saved source.
- Import and backup restore stage exact text+format; only Save activates. Export uses saved bytes
  and matching extension, not an unsaved draft; it CONTAINS NODE CREDENTIALS.
- YAML is UTF-8/single-document/JSON-compatible scalars and string mapping keys. No anchors,
  aliases, merge keys, custom tags, duplicate keys or multi-document streams.
- Reload does not silently accept external modifications. Same-port saves retain established
  flows and network toggles; changed ports restore only affected network paths as before.
- Desktop settings, network recovery journals and traffic history remain separate JSON files.
- This new package has NOT been installed or runtime-tested on Windows in this iteration.
  Earlier Bero Win11 checks covered only the prior build's launch/icon/native dragging, NOT
  this YAML build, file dialogs, UAC/SCM/TUN/proxy/forwarding or crash recovery.
- Approved cat-K icon and fixed-main-window drag behavior remain unchanged. All files must stay
  together. Do not overwrite files while an old tray process is running; there is no auto-update.
See YAML-README.md and kat-client.example.yaml. The example is not an automatic startup action.


MANUAL SIDEBAR (2026-10-28):
- The top sidebar button expands/collapses the navigation. In a narrow window, expand to show labels.
- Your explicit choice is remembered across restarts in this app's local UI preference storage and
  is not overridden by resizing. Before the first choice, the existing 1200px auto behavior remains.
- No config, desktop startup setting or OS networking is changed by this button. The narrow expanded
  node table can scroll horizontally so all existing columns and operations remain accessible.


FRONTEND UI POLISH (2026-10-28; display/layout only):
- Sidebar shows the accepted JSON/YAML filename; dirty source remains clearly unsaved. Flat blue
  navigation keeps useful metadata and manual expansion memory; duplicate footer is removed.
- Backup times use this computer's local time, with year for cross-year entries; original ISO
  remains in the tooltip. Sizes use B/KB. Configuration saved feedback appears only once.
- Blue accent matches the approved B logo, white-text primary buttons meet AA in both themes;
  running/success green and warning/error semantics remain. Native selects share the same style.
- Overview removes repeated mode/proxy/TUN summary and PID, with compact balanced cards/chart.
- Member cards show actual latency and a separate weight badge when not1; unknown time rows are
  omitted. This does not change weight/selection/sort computation or the saved source.
- Configuration tools keep original actions/confirmation/disabled behavior; file actions are
  secondary, save/cancel on the right. Empty link import hides useless reveal/copy controls.
- Core/native source, IPC, configuration transactions, JSON/YAML, routing, sidebar memory,
  titlebar dragging and B icon assets are unchanged. This is an unpublished unsigned test build.
- Linux browser comparisons cover both themes,1280/1440,expanded/collapsed and all seven pages;
  screenshots use explicit native test transport, NOT Win11 runtime acceptance.


2026-10-29 未发布测试包增补：
- 浅色主表面为白色，主蓝色为 Zeno #0071E3；深色/跟随系统保留。
- 去掉侧栏选中左竖线和鼠标点选/展开的多余高亮；保留必要键盘焦点。
- 用户可见错误采用安全中文说明，保留诊断码；不会回显订阅URL或节点凭据。
- 安装向导完成页可选择是否创建桌面快捷方式及是否立即运行 Kat（默认不自动打开）。
  GUI 内安装/更新操作会提示运行 Setup，不再要求寻找解压目录。
  完整卸载入口为 Windows 已安装的应用中的 Kat Client；GUI 内卸载服务仅移除服务。
- “导入订阅”先选远程HTTPS链接或本地Clash文件/配置文本，点击一次即下载、校验并接纳；失败保留旧配置。
- “使用系统代理下载”默认关闭，仅本次手动导入/更新；仅支持静态Windows系统HTTP代理，不支持PAC、认证或含糊多连接配置，不自动回落直连。Kat TUN开启时沿既有受控物理出口转发，不因TUN开启本身拒绝；不承诺任意外部代理内部链无环。
- 不再提供仅节点订阅新建/节点文本导入；既有provider兼容数据与管理、手动节点添加/编辑/复制/测速保留。Kat原生整份配置仍在配置页载入草稿，保存才生效。
  解析只预览，节点和必要策略组一笔合入配置才生效，失败保留原配置。
- 支持这次SubStore所需SS obfs-http及前置url-test依赖，保原生SS UDP传输，
  不兼容整份mihomo/Surge规则，不删混淆或前置字段伪装可用。
- 真实订阅22节点完整识别，短探测7个通过、15个未通过；不是22个均在线保证。
  普通SS、obfs-SS、经前置组SS2022各有真实本地HTTP CONNECT至HTTPS204证据。
  历史包曾存在冷自动组首请求抢跑；当前包已按顶部说明等待首完整轮，不跨配置代继承健康。
- JSON/YAML/YML、原文/注释保全、备份失败保旧、侧栏记忆、拖动、B实心猫头保持。
- 本包不含真实订阅URL、节点配置或凭据。请保留整包文件，不只替换一个EXE。

最终收尾候选（未发布、未签名）：
- TUN 启动在原有10秒总预算内等待同一网卡的 IPv4/IPv6 接口就绪；仅预写阶段1168可等待，其它错误仍拒绝，恢复逻辑不放宽。
- 诊断沿现有接口有界读取并保留最近200条内核日志，不再停留在最早200条；原隐私及时间上限保持。
- TUN 就绪门按程序实际使用的网卡 GUID 文本格式校验，修复新网卡出现后必报“无法确认网络接口身份”(INTERFACE_IDENTITY) 的问题；身份校验未放宽。
- 关闭 TUN 后桥接残留的旧 Wintun 网卡（同名、旧 GUID）不再被下次开启误认为新网卡，修复再次开启报 INTERFACE_IDENTITY / INTERFACE_QUERY 的问题；身份校验未放宽。
- TUN 开启时，发往系统原有 DNS 服务器（如路由器）的查询直接从物理网卡发出、不经节点，修复全局模式下冷 DNS 查询约 12 秒的问题；其它流量路由不变。
- 右键“以管理员身份运行”不再无反应：Kat 会自动以普通身份重新打开（GUI 本身不以管理员运行）；无法安全切换时弹出说明。
- 构建通过不代表TUN全部可用；最终实机结果、未解决项及恢复范围以随交付的 VERIFIED.md 为准。


NSIS installer runtime notices (from the hash-verified NSIS 3.11 Debian package):
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: nsis
Upstream-Contact: http://forums.winamp.com/forumdisplay.php?f=65
Source: https://sourceforge.net/projects/nsis

Files: *
Copyright: 2003-2021, NSIS Contributors
  1995-2003, Mark Adler
  1998-2005, Gilles Vollant
  1999-2000, 2002, Aladdin Enterprises.
  1999-2001, Miguel Garrido <mgarrido01@hotmail.com>
  1999-2021, Nullsoft and Contributors
  1999-2021, Nullsoft, Jeff Doozan and Contributors
  2001, Michael Bishop
  2001-2002, Yaroslav Faybishenko & Justin Frankel
  2001-2005, Koen van de Sande / Van de Sande Productions
  2002, Robert Rainwater <rrainwater@yahoo.com>
  2002-2021, Amir Szekely <kichik@netvision.net.il> and Contributors
  2002-2021, Amir Szekely <kichik@users.sourceforge.net>
  2002-2021, Joost Verburg
  2003-2021, Amir Szekely, Joost Verburg, Dave Laundon
  2003, Ramon
  2003, Sunil Kamath
  2007-2021, Jim Park
  2011-2021, Anders Kjersem
  Nik Medved
License: Zlib

Files: Source/7zip/*
Copyright: 1999-2006 Igor Pavlov
  2003-2021 Amir Szekely <kichik@netvision.net.il>
License: lzma-cpl-exception

Files: Source/bzip2/*
Copyright: 1999-2021, Nullsoft and Contributors
  1996-2000 Julian R Seward
License: bzip2-libbzip-2010

Files: Contrib/System/Source/Call.S
 Docs/src/bin/halibut/*
 SCons/Tools/crossmingw.py
 SCons/Tools/mstoolkit.py
Copyright: 1999-2001, Simon Tatham and James Aylett.
  1999-2001, Simon Tatham.
  2001-2004, The SCons Foundation
  2004, John Connors
  2008, Thomas Gaugler <thomas@dadie.net>
  2008-2021, NSIS Contributors
  Robert Rainwater
  Amir Szekely
License: Expat

Files: Source/boost/*
Copyright: 1998-1999, Greg Colvin and Beman Dawes
  1999-2002, boost.org
  2001-2003, Peter Dimov
  2002, David Abrahams
  2003, Daniel Frey
  2003, Howard Hinnant
License: NTP

Files: Contrib/NSIS?Menu/nsismenu/nslinks.cpp
 Contrib/NSIS?Menu/wx/setup.h
Copyright: 1999, Vaclav Slavik
 1997, Julian Smart
License: wxWindows
               wxWindows Library Licence, Version 3.1
               ======================================
 .
 Copyright (c) 1998-2005 Julian Smart, Robert Roebling et al
 .
 Everyone is permitted to copy and distribute verbatim copies
 of this licence document, but changing it is not allowed.
 .
                      WXWINDOWS LIBRARY LICENCE
    TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
 .
 This library is free software; you can redistribute it and/or modify it
 under the terms of the GNU Library General Public Licence as published by
 the Free Software Foundation; either version 2 of the Licence, or (at your
 option) any later version.
 .
 This library is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 Licence for more details.
 .
 You should have received a copy of the GNU Library General Public Licence
 along with this software, usually in a file named COPYING.LIB.  If not,
 write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 Floor, Boston, MA 02110-1301 USA.
 .
 EXCEPTION NOTICE
 .
 1. As a special exception, the copyright holders of this library give
 permission for additional uses of the text contained in this release of the
 library as licenced under the wxWindows Library Licence, applying either
 version 3.1 of the Licence, or (at your option) any later version of the
 Licence as published by the copyright holders of version 3.1 of the Licence
 document.
 .
 2. The exception is that you may use, copy, link, modify and distribute
 under your own terms, binary object code versions of works based on the
 Library.
 .
 3. If you copy code from files distributed under the terms of the GNU
 General Public Licence or the GNU Library General Public Licence into a
 copy of this library, as this licence permits, the exception does not apply
 to the code that you add in this way.  To avoid misleading anyone as to the
 status of such modified files, you must delete this exception notice from
 such code and/or adjust the licensing conditions notice accordingly.
 .
 4. If you write modifications of your own for this library, it is your
 choice whether to permit this exception to apply to your modifications.  If
 you do not wish that, you must delete the exception notice from such code
 and/or adjust the licensing conditions notice accordingly.

License: bzip2-libbzip-2010
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 .
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 .
 2. The origin of this software must not be misrepresented; you must
    not claim that you wrote the original software.  If you use this
    software in a product, an acknowledgment in the product
    documentation would be appreciated but is not required.
 .
 3. Altered source versions must be plainly marked as such, and must
    not be misrepresented as being the original software.
 .
 4. The name of the author may not be used to endorse or promote
    products derived from this software without specific prior written
    permission.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

License: Expat
 The MIT License
 .
 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated
 documentation files (the "Software"), to deal in the Software
 without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to
 whom the Software is furnished to do so, subject to the
 following conditions:
 .
 The above copyright notice and this permission notice shall
 be included in all copies or substantial portions of the
 Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT
 WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR
 PURPOSE AND NONINFRINGEMENT. IN NO EVENT
 SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

License: lzma-cpl-exception
 Common Public License version 1.0
 .
 THE ACCOMPANYING PROGRAM IS PROVIDED UNDER THE TERMS OF THIS COMMON PUBLIC LICENSE ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THE PROGRAM CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT.
 .
 1. DEFINITIONS
 .
 "Contribution" means:
 .
      a) in the case of the initial Contributor, the initial code and documentation distributed under this Agreement, and
      b) in the case of each subsequent Contributor:
 .
      i) changes to the Program, and
 .
      ii) additions to the Program;
 .
      where such changes and/or additions to the Program originate from and are distributed by that particular Contributor. A Contribution 'originates' from a Contributor if it was added to the Program by such Contributor itself or anyone acting on such Contributor's behalf. Contributions do not include additions to the Program which: (i) are separate modules of software distributed in conjunction with the Program under their own license agreement, and (ii) are not derivative works of the Program.
 .
 "Contributor" means any person or entity that distributes the Program.
 .
 "Licensed Patents " mean patent claims licensable by a Contributor which are necessarily infringed by the use or sale of its Contribution alone or when combined with the Program.
 .
 "Program" means the Contributions distributed in accordance with this Agreement.
 .
 "Recipient" means anyone who receives the Program under this Agreement, including all Contributors.
 .
 2. GRANT OF RIGHTS
 .
      a) Subject to the terms of this Agreement, each Contributor hereby grants Recipient a non-exclusive, worldwide, royalty-free copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, distribute and sublicense the Contribution of such Contributor, if any, and such derivative works, in source code and object code form.
 .
      b) Subject to the terms of this Agreement, each Contributor hereby grants Recipient a non-exclusive, worldwide, royalty-free patent license under Licensed Patents to make, use, sell, offer to sell, import and otherwise transfer the Contribution of such Contributor, if any, in source code and object code form. This patent license shall apply to the combination of the Contribution and the Program if, at the time the Contribution is added by the Contributor, such addition of the Contribution causes such combination to be covered by the Licensed Patents. The patent license shall not apply to any other combinations which include the Contribution. No hardware per se is licensed hereunder.
 .
      c) Recipient understands that although each Contributor grants the licenses to its Contributions set forth herein, no assurances are provided by any Contributor that the Program does not infringe the patent or other intellectual property rights of any other entity. Each Contributor disclaims any liability to Recipient for claims brought by any other entity based on infringement of intellectual property rights or otherwise. As a condition to exercising the rights and licenses granted hereunder, each Recipient hereby assumes sole responsibility to secure any other intellectual property rights needed, if any. For example, if a third party patent license is required to allow Recipient to distribute the Program, it is Recipient's responsibility to acquire that license before distributing the Program.
 .
      d) Each Contributor represents that to its knowledge it has sufficient copyright rights in its Contribution, if any, to grant the copyright license set forth in this Agreement.
 .
 3. REQUIREMENTS
 .
 A Contributor may choose to distribute the Program in object code form under its own license agreement, provided that:
 .
      a) it complies with the terms and conditions of this Agreement; and
 .
      b) its license agreement:
 .
      i) effectively disclaims on behalf of all Contributors all warranties and conditions, express and implied, including warranties or conditions of title and non-infringement, and implied warranties or conditions of merchantability and fitness for a particular purpose;
 .
      ii) effectively excludes on behalf of all Contributors all liability for damages, including direct, indirect, special, incidental and consequential damages, such as lost profits;
 .
      iii) states that any provisions which differ from this Agreement are offered by that Contributor alone and not by any other party; and
 .
      iv) states that source code for the Program is available from such Contributor, and informs licensees how to obtain it in a reasonable manner on or through a medium customarily used for software exchange.
 .
 When the Program is made available in source code form:
 .
      a) it must be made available under this Agreement; and
 .
      b) a copy of this Agreement must be included with each copy of the Program.
 .
 Contributors may not remove or alter any copyright notices contained within the Program.
 .
 Each Contributor must identify itself as the originator of its Contribution, if any, in a manner that reasonably allows subsequent Recipients to identify the originator of the Contribution.
 .
 4. COMMERCIAL DISTRIBUTION
 .
 Commercial distributors of software may accept certain responsibilities with respect to end users, business partners and the like. While this license is intended to facilitate the commercial use of the Program, the Contributor who includes the Program in a commercial product offering should do so in a manner which does not create potential liability for other Contributors. Therefore, if a Contributor includes the Program in a commercial product offering, such Contributor ("Commercial Contributor") hereby agrees to defend and indemnify every other Contributor ("Indemnified Contributor") against any losses, damages and costs (collectively "Losses") arising from claims, lawsuits and other legal actions brought by a third party against the Indemnified Contributor to the extent caused by the acts or omissions of such Commercial Contributor in connection with its distribution of the Program in a commercial product offering. The obligations in this section do not apply to any claims or Losses relating to any actual or alleged intellectual property infringement. In order to qualify, an Indemnified Contributor must: a) promptly notify the Commercial Contributor in writing of such claim, and b) allow the Commercial Contributor to control,
 and cooperate with the Commercial Contributor in, the defense and any related settlement negotiations. The Indemnified Contributor may participate in any such claim at its own expense.
 .
 For example, a Contributor might include the Program in a commercial product offering, Product X. That Contributor is then a Commercial Contributor. If that Commercial Contributor then makes performance claims, or offers warranties related to Product X, those performance claims and warranties are such Commercial Contributor's responsibility alone. Under this section, the Commercial Contributor would have to defend claims against the other Contributors related to those performance claims and warranties, and if a court requires any other Contributor to pay any damages as a result, the Commercial Contributor must pay those damages.
 .
 5. NO WARRANTY
 .
 EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is solely responsible for determining the appropriateness of using and distributing the Program and assumes all risks associated with its exercise of rights under this Agreement, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and unavailability or interruption of operations.
 .
 6. DISCLAIMER OF LIABILITY
 .
 EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 .
 7. GENERAL
 .
 If any provision of this Agreement is invalid or unenforceable under applicable law, it shall not affect the validity or enforceability of the remainder of the terms of this Agreement, and without further action by the parties hereto, such provision shall be reformed to the minimum extent necessary to make such provision valid and enforceable.
 .
 If Recipient institutes patent litigation against a Contributor with respect to a patent applicable to software (including a cross-claim or counterclaim in a lawsuit), then any patent licenses granted by that Contributor to such Recipient under this Agreement shall terminate as of the date such litigation is filed. In addition, if Recipient institutes patent litigation against any entity (including a cross-claim or counterclaim in a lawsuit) alleging that the Program itself (excluding combinations of the Program with other software or hardware) infringes such Recipient's patent(s), then such Recipient's rights granted under Section 2(b) shall terminate as of the date such litigation is filed.
 .
 All Recipient's rights under this Agreement shall terminate if it fails to comply with any of the material terms or conditions of this Agreement and does not cure such failure in a reasonable period of time after becoming aware of such noncompliance. If all Recipient's rights under this Agreement terminate, Recipient agrees to cease use and distribution of the Program as soon as reasonably practicable. However, Recipient's obligations under this Agreement and any licenses granted by Recipient relating to the Program shall continue and survive.
 .
 Everyone is permitted to copy and distribute copies of this Agreement, but in order to avoid inconsistency the Agreement is copyrighted and may only be modified in the following manner. The Agreement Steward reserves the right to publish new versions (including revisions) of this Agreement from time to time. No one other than the Agreement Steward has the right to modify this Agreement. IBM is the initial Agreement Steward. IBM may assign the responsibility to serve as the Agreement Steward to a suitable separate entity. Each new version of the Agreement will be given a distinguishing version number. The Program (including Contributions) may always be distributed subject to the version of the Agreement under which it was received. In addition, after a new version of the Agreement is published, Contributor may elect to distribute the Program (including its Contributions) under the new version. Except as expressly stated in Sections 2(a) and 2(b) above, Recipient receives no rights or licenses to the intellectual property of any Contributor under this Agreement, whether expressly, by implication, estoppel or otherwise. All rights in the Program not expressly granted under this Agreement are reserved.
 .
 This Agreement is governed by the laws of the State of New York and the intellectual property laws of the United States of America. No party to this Agreement will bring a legal action under this Agreement more than one year after the cause of action arose. Each party waives its rights to a jury trial in any resulting litigation.
 Special exception for LZMA compression module
 .
 Igor Pavlov and Amir Szekely, the authors of the LZMA compression module for NSIS, expressly permit you to statically or dynamically link your code (or bind by name) to the files from the LZMA compression module for NSIS without subjecting your linked code to the terms of the Common Public license version 1.0. Any modifications or additions to files from the LZMA compression module for NSIS, however, are subject to the terms of the Common Public License version 1.0.

License: NTP
 Permission to copy, use, modify, sell and distribute this software
 is granted provided this copyright notice appears in all copies.
 This software is provided "as is" without express or implied
 warranty, and with no claim as to its suitability for any purpose.

License: Zlib
 The zlib License
 .
 This software is provided 'as-is', without any express or implied
 warranty. In no event will the authors be held liable for any damages
 arising from the use of this software.
 .
 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:
 .
   1. The origin of this software must not be misrepresented; you must
      not claim that you wrote the original software. If you use this
      software in a product, an acknowledgment in the product
      documentation would be appreciated but is not required.
 .
   2. Altered source versions must be plainly marked as such, and must
      not be misrepresented as being the original software.
 .
   3. This notice may not be removed or altered from any source
      distribution.
